/** @jest-environment node */

import {
  auditLogResponse,
  auditPageResponse,
  capabilitiesResponse,
  userResponse,
  usersResponse,
  verificationResponse,
  type AdminAuditQuery,
  type AdminVerification,
  type AdminVerifyQuery,
} from '../app/_lib/admin/contracts';
import {
  compareDecimal,
  decimalString,
  normalizeModerationReason,
  timestampNanoseconds,
  validateAuditQuery,
  validateVerifyQuery,
} from '../app/_lib/admin/validation';
import {
  advanceVerificationRun,
  beginVerificationRun,
  verificationPageResponse,
} from '../app/_lib/admin/verification';
import { safeReturnPath } from '../app/_lib/portal/validation';

const id = '00000000-0000-4000-8000-000000000001';
const other = '00000000-0000-4000-8000-000000000002';
const high = '9007199254740993';
const maximum = '9223372036854775807';
const seed = '5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb';
const ledgerSeed = '6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54';
const hash = 'b'.repeat(64);
const finalHash = 'c'.repeat(64);
const auditScope =
  'stored_segment_relative_to_seed; not complete ingestion, tail-truncation detection, or independent historical authenticity';
const ledgerScope =
  'database_relative_chain_and_retained_payloads; erased payloads are authorized by erasure records, not recomputed; not complete ingestion or independent historical authenticity';
const user = {
  id,
  status: 'active',
  is_mfa_enabled: false,
  lifecycle_revision: high,
  created_at: '2026-10-27T00:00:00Z',
  updated_at: null,
  deleted_at: null,
};
const log = {
  id,
  user_id: null,
  actor_id: other,
  actor_spiffe_id: 'spiffe://identity.test/service',
  event_type: 'admin.users.viewed',
  action_status: 'success',
  client_ip: '203.0.113.5',
  user_agent: 'untrusted browser',
  payload: '{"untrusted":"<img src=x onerror=alert(1)>"}',
  timestamp: '2026-10-27T12:00:00.123456Z',
  sha256_leaf_hash: seed,
  sha256_chain_hash: hash,
  seq: high,
};
const limits = {
  page_size_default: 50,
  page_size_max: 200,
  audit_max_window_seconds: 31 * 86400,
  chain_verify_max_limit: 5000,
};
const capabilities = {
  capabilities: {
    users_read: true,
    users_pii: false,
    users_lookup: false,
    users_status_write: false,
    audit_logs_read: false,
    audit_chain_verify: false,
    ledger_verify: false,
    legal_holds_read: false,
    legal_holds_apply: false,
    legal_holds_release: false,
    preservation_requests_create: false,
    legal_inquiry_lookup: false,
  },
  limits,
};
const query = { start_time: '2026-10-27T00:00:00Z', end_time: '2026-10-28T00:00:00Z', limit: 2 };

function proof(overrides: Record<string, unknown> = {}) {
  return {
    chain: 'audit',
    after_seq: '0',
    through_seq: maximum,
    seed_hash: seed,
    seed_source: 'genesis',
    scope: auditScope,
    last_hash: hash,
    complete: false,
    verified: true,
    checked: 2,
    first_seq: '2',
    last_seq: high,
    broken_at_seq: null,
    expected_hash: null,
    stored_hash: null,
    next_after_seq: high,
    ...overrides,
  };
}

describe('exact bounded admin DTOs', () => {
  it.each(['0', '1', '9007199254740992', high, maximum])(
    'preserves canonical int64 %s without numeric conversion',
    (value) => {
      expect(decimalString(value)).toBe(value);
      expect(userResponse({ ...user, lifecycle_revision: value }).lifecycle_revision).toBe(value);
    }
  );

  it.each([
    undefined,
    null,
    0,
    1,
    9007199254740992,
    9223372036854775807n,
    '',
    '00',
    '01',
    '-0',
    '-1',
    '+1',
    '1.0',
    '1e3',
    ' 1',
    '1 ',
    '1\n',
    '1\r',
    '1\u2028',
    '1\u2029',
    '9223372036854775808\n',
    '9223372036854775808',
    '9'.repeat(100),
  ])('rejects noncanonical or non-string revision %p', (value) => {
    expect(() => decimalString(value)).toThrow('invalid_response');
    expect(() => userResponse({ ...user, lifecycle_revision: value })).toThrow('invalid_response');
  });

  it('compares decimal strings by value above 2^53 and across digit lengths', () => {
    expect(compareDecimal('9', '10')).toBe(-1);
    expect(compareDecimal(high, '9007199254740992')).toBe(1);
    expect(compareDecimal(high, maximum)).toBe(-1);
    expect(compareDecimal(maximum, maximum)).toBe(0);
    expect(() => compareDecimal('01', '1')).toThrow('invalid_response');
  });

  it('preserves omitted email and explicit null timestamps, dropping non-DTO private fields', () => {
    expect(
      userResponse({
        ...user,
        email: 'operator@example.test',
        auth_version: 123,
        roles: ['secret'],
        legal_hold: true,
      })
    ).toEqual({ ...user, email: 'operator@example.test' });
    expect(userResponse(user)).not.toHaveProperty('email');
    for (const patch of [
      { email: null },
      { created_at: undefined },
      { deleted_at: undefined },
      { is_mfa_enabled: 'false' },
      { status: 'deleted' },
      { id: '../secret' },
      { updated_at: '2026-02-30T00:00:00Z' },
      { updated_at: '2026-10-27T24:00:00Z' },
      { updated_at: '2026-10-27T00:00:00Z\n' },
    ])
      expect(() => userResponse({ ...user, ...patch })).toThrow('invalid_response');
  });

  it('requires every boolean and bounded numeric effective capability limit', () => {
    expect(
      capabilitiesResponse({
        ...capabilities,
        roles: ['support'],
        capabilities: { ...capabilities.capabilities, legal_write: true },
      })
    ).toEqual(capabilities);
    for (const flags of [{ users_read: undefined }, { users_pii: 'true' }, { users_lookup: true }])
      expect(() =>
        capabilitiesResponse({
          ...capabilities,
          capabilities: { ...capabilities.capabilities, ...flags },
        })
      ).toThrow('invalid_response');
    for (const patch of [
      { page_size_default: 0 },
      { page_size_max: 201 },
      { page_size_max: 49 },
      { chain_verify_max_limit: 5001 },
      { chain_verify_max_limit: '5000' },
      { audit_max_window_seconds: 31 * 86400 + 1 },
      { audit_max_window_seconds: 0 },
      { audit_max_window_seconds: NaN },
      { audit_max_window_seconds: Infinity },
      { audit_max_window_seconds: '60' },
    ])
      expect(() =>
        capabilitiesResponse({ ...capabilities, limits: { ...limits, ...patch } })
      ).toThrow('invalid_response');
    expect(
      capabilitiesResponse({
        ...capabilities,
        limits: { ...limits, audit_max_window_seconds: 0.5 },
      }).limits.audit_max_window_seconds
    ).toBe(0.5);
  });

  it('validates user count/offset relationships without accepting unsafe numeric totals', () => {
    expect(usersResponse({ items: [user], total: 1, limit: 50, offset: 0 }).items).toHaveLength(1);
    expect(usersResponse({ items: [], total: 1, limit: 50, offset: 2 }).items).toEqual([]);
    for (const page of [
      { items: [user], total: 0, limit: 50, offset: 0 },
      { items: [], total: 1, limit: 50, offset: 0 },
      { items: [user, user], total: 2, limit: 2, offset: 0 },
      { items: [], total: '0', limit: 50, offset: 0 },
      { items: [], total: 9007199254740992, limit: 50, offset: 0 },
      { items: [], total: 0, limit: 0, offset: 0 },
      { items: [], total: 0, limit: 50, offset: 2147483648 },
    ])
      expect(() => usersResponse(page)).toThrow('invalid_response');
  });

  it('keeps audit payloads as text and validates descending keyset cursors including terminal nonzero cursors', () => {
    const page = {
      items: [{ ...log, id: other, seq: maximum }, log],
      limit: 2,
      has_more: true,
      next_before_seq: high,
    };
    expect(auditPageResponse({ ...page, total: 999 }).items.map((row) => row.seq)).toEqual([
      maximum,
      high,
    ]);
    expect(auditPageResponse(page)).not.toHaveProperty('total');
    expect(auditPageResponse({ ...page, has_more: false }).next_before_seq).toBe(high);
    expect(
      auditPageResponse({ items: [], limit: 2, has_more: false, next_before_seq: '0' }).items
    ).toEqual([]);
    expect(auditLogResponse(log).payload).toBe(log.payload);
    for (const patch of [
      { seq: 1 },
      { seq: '0' },
      { seq: '01' },
      { sha256_leaf_hash: 'a'.repeat(63) },
      { sha256_chain_hash: 'A'.repeat(64) },
      { sha256_leaf_hash: 'g'.repeat(64) },
      { user_id: undefined },
      { payload: { html: '<script>' } },
      { timestamp: undefined },
    ])
      expect(() => auditLogResponse({ ...log, ...patch })).toThrow('invalid_response');
    for (const patch of [
      { next_before_seq: '9007199254740992' },
      { next_before_seq: 9007199254740992 },
      { items: [log] },
      { items: [log, { ...log, id: other, seq: maximum }] },
      { items: [log, { ...log, id: other }] },
      { items: [], next_before_seq: '0' },
      { limit: 1 },
      { has_more: 'false' },
    ])
      expect(() => auditPageResponse({ ...page, ...patch })).toThrow('invalid_response');
  });

  it('validates audit UTC/window/event/page/cursor inputs and honors smaller configured bounds', () => {
    expect(
      validateAuditQuery(
        {
          ...query,
          start_time: '2026-10-27T00:00',
          end_time: '2026-10-28T00:00',
          event_type: ' admin.users.viewed ',
          before_seq: maximum,
        },
        limits
      )
    ).toEqual({
      ...query,
      start_time: '2026-10-27T00:00:00.000Z',
      end_time: '2026-10-28T00:00:00.000Z',
      event_type: 'admin.users.viewed',
      before_seq: maximum,
    });
    expect(
      validateAuditQuery({ ...query, start_time: '2026-10-27T02:00:00+02:00' }).start_time
    ).toBe('2026-10-27T00:00:00.000Z');
    expect(() =>
      validateAuditQuery(query, { ...limits, audit_max_window_seconds: 3600 })
    ).toThrow();
    for (const patch of [
      { start_time: '2026-10-29T00:00:00Z' },
      { start_time: '2026-02-30T00:00' },
      { start_time: 'not a date' },
      { start_time: '2026-01-01T00:00:00Z' },
      { event_type: 'USER.LOGIN' },
      { event_type: 'x&email=secret' },
      { event_type: '' },
      { event_type: null },
      { event_type: 'x'.repeat(101) },
      { limit: '2' },
      { limit: 0 },
      { limit: 201 },
      { before_seq: 2 },
      { before_seq: '01' },
      { offset: 0 },
      { email: 'private@example.test' },
    ])
      expect(() => validateAuditQuery({ ...query, ...patch } as AdminAuditQuery)).toThrow();
  });

  it('enforces UTF-8 moderation reason length after Go-compatible whitespace trimming', () => {
    expect(normalizeModerationReason('\u0085  moderation\nreason \u3000')).toBe(
      'moderation\nreason'
    );
    expect(normalizeModerationReason('\ufeffReason')).toBe('\ufeffReason');
    expect(normalizeModerationReason('\u{1f642}'.repeat(500))).toHaveLength(1000);
    expect(normalizeModerationReason('x'.repeat(2000))).toHaveLength(2000);
    for (const reason of ['', '\u0085 \t\n', 'x'.repeat(2001), '\u{1f642}'.repeat(501), '\ud800'])
      expect(() => normalizeModerationReason(reason)).toThrow('invalid_request');
  });

  it('preserves and compares RFC3339 nanosecond query boundaries rather than rounding them', () => {
    const start_time = '2026-10-27T00:00:00.000000001Z';
    const end_time = '2026-10-27T00:00:00.000000002Z';
    expect(validateAuditQuery({ start_time, end_time })).toEqual({ start_time, end_time });
    expect(
      validateAuditQuery({ start_time: '2026-10-27T02:00:00.000000001+02:00', end_time }).start_time
    ).toBe(start_time);
    expect(() => validateAuditQuery({ start_time: end_time, end_time: start_time })).toThrow(
      'invalid_request'
    );
    expect(timestampNanoseconds(end_time) - timestampNanoseconds(start_time)).toBe(1n);
    expect(timestampNanoseconds('1969-12-31T23:59:59.999999999Z')).toBe(-1n);
    expect(() =>
      validateAuditQuery(
        { start_time: '2026-10-27T00:00:00Z', end_time: '2026-10-27T00:00:00.500000001Z' },
        { ...limits, audit_max_window_seconds: 0.5 }
      )
    ).toThrow('invalid_request');
  });

  it('returns only fixed admin destinations and strips every expired detail identifier', () => {
    for (const path of ['/admin', '/admin/users', '/admin/audit-logs', '/admin/integrity', '/admin/legal'])
      expect(safeReturnPath(path)).toBe(path);
    for (const path of [
      `/admin/users/${id}`,
      `/admin/users/${id}?email=private`,
      `/admin/users/${id}#reason`,
      '/admin/users/%2e%2e/login',
    ])
      expect(safeReturnPath(path)).toBe('/admin/users');
    for (const path of [
      '/admin?email=private',
      '/admin/integrity#secret',
      '/admin/../dashboard',
      'https://evil.test/admin',
      '//evil.test/admin',
      '/admin/audit-logs?event_type=secret',
    ])
      expect(safeReturnPath(path)).toBe('/dashboard');
  });
});

describe('canonical-v2 proof contract and fixed-bound runs', () => {
  describe.each(['audit', 'ledger'] as const)('%s genesis seed', (chain) => {
    it.each(['partial', 'complete', 'empty'] as const)(
      'requires the canonical seed on an otherwise clean %s first page',
      (state) => {
        const genesis = chain === 'audit' ? seed : ledgerSeed;
        const empty = state === 'empty';
        const value = proof({
          chain,
          scope: chain === 'audit' ? auditScope : ledgerScope,
          ...(chain === 'ledger' ? { erased_checked: 0 } : {}),
          seed_hash: genesis,
          through_seq: empty ? '0' : state === 'complete' ? high : maximum,
          checked: empty ? 0 : 2,
          first_seq: empty ? null : '2',
          last_seq: empty ? null : high,
          last_hash: empty ? genesis : hash,
          next_after_seq: empty ? null : high,
          complete: state !== 'partial',
        });
        const run = beginVerificationRun(chain, 2);
        expect(verificationResponse(value).seed_hash).toBe(genesis);
        expect(verificationPageResponse(value, chain, {}).seed_hash).toBe(genesis);
        expect(() =>
          verificationPageResponse(value, chain === 'audit' ? 'ledger' : 'audit', {})
        ).toThrow('invalid_response');
        expect(advanceVerificationRun(run, value as AdminVerification)).toMatchObject({
          pages: 1,
          checked: value.checked,
          through_seq: value.through_seq,
          result: { seed_hash: genesis, complete: value.complete },
        });
        for (const wrongSeed of [
          'a'.repeat(64),
          '0'.repeat(64),
          chain === 'audit' ? ledgerSeed : seed,
        ]) {
          const wrong = {
            ...value,
            seed_hash: wrongSeed,
            last_hash: empty ? wrongSeed : value.last_hash,
          };
          expect(() => verificationResponse(wrong)).toThrow('invalid_response');
          expect(() => verificationPageResponse(wrong, chain, {})).toThrow('invalid_response');
          expect(() => advanceVerificationRun(run, wrong as AdminVerification)).toThrow(
            'invalid_response'
          );
        }
        expect(run).toMatchObject({ through_seq: null, pages: 0, checked: 0, result: null });
      }
    );
  });

  it('starts only at genesis without a high-water bound, and walks sequence gaps above 2^53', () => {
    const fresh = beginVerificationRun('audit', 5000);
    expect(fresh.next).toEqual({ after_seq: '0', limit: 1000 });
    expect(beginVerificationRun('ledger', 25).next).toEqual({ after_seq: '0', limit: 25 });
    const first = advanceVerificationRun(fresh, verificationResponse(proof()));
    expect(first).toMatchObject({ checked: 2, erased_checked: 0, pages: 1, through_seq: maximum });
    expect(first.next).toEqual({
      after_seq: high,
      through_seq: maximum,
      predecessor_hash: hash,
      limit: 1000,
    });
    const page = proof({
      after_seq: high,
      seed_source: 'supplied_predecessor',
      seed_hash: hash,
      last_hash: finalHash,
      checked: 1,
      first_seq: maximum,
      last_seq: maximum,
      next_after_seq: maximum,
      complete: true,
    });
    const final = advanceVerificationRun(first, verificationResponse(page));
    expect(final).toMatchObject({
      checked: 3,
      pages: 2,
      through_seq: maximum,
      next: null,
      result: { complete: true, verified: true },
    });
    expect(() => advanceVerificationRun(final, verificationResponse(page))).toThrow(
      'invalid_response'
    );
  });

  it('accepts neutral empty chains and fully erased ledger pages without counting erased nodes twice', () => {
    const empty = verificationResponse(
      proof({
        through_seq: '0',
        checked: 0,
        first_seq: null,
        last_seq: null,
        last_hash: seed,
        next_after_seq: null,
        complete: true,
      })
    );
    expect(advanceVerificationRun(beginVerificationRun('audit', 1000), empty)).toMatchObject({
      checked: 0,
      next: null,
    });
    const erased = verificationResponse(
      proof({
        chain: 'ledger',
        seed_hash: ledgerSeed,
        scope: ledgerScope,
        erased_checked: 2,
        through_seq: high,
        complete: true,
      })
    );
    expect(advanceVerificationRun(beginVerificationRun('ledger', 1000), erased)).toMatchObject({
      checked: 2,
      erased_checked: 2,
      next: null,
    });
    expect(
      verificationResponse(proof({ through_seq: high, complete: true, next_after_seq: maximum }))
        .complete
    ).toBe(true);
    expect(
      verificationResponse(proof({ through_seq: high, complete: true, next_after_seq: null }))
        .complete
    ).toBe(true);
  });

  it.each(['after_seq', 'through_seq', 'first_seq', 'last_seq', 'broken_at_seq', 'next_after_seq'])(
    'rejects numeric coordinates in %s, including nullable positions',
    (field) => {
      expect(() => verificationResponse(proof({ [field]: 9007199254740992 }))).toThrow(
        'invalid_response'
      );
      expect(() => verificationResponse(proof({ [field]: '9223372036854775808' }))).toThrow(
        'invalid_response'
      );
      expect(() => verificationResponse(proof({ [field]: '01' }))).toThrow('invalid_response');
    }
  );

  it('rejects malformed proofs rather than converting them to empty or partially trusted results', () => {
    for (const patch of [
      { verified: 'true' },
      { complete: null },
      { checked: '2' },
      { checked: -1 },
      { checked: 5001 },
      { chain: 'other' },
      { seed_source: 'checkpoint' },
      { scope: '' },
      { scope: ledgerScope },
      { scope: 'independently_authenticated_complete_history' },
      { scope: 'x'.repeat(1025) },
      { first_seq: null },
      { last_seq: null },
      { first_seq: '0' },
      { last_seq: '1' },
      { checked: 1 },
      { checked: 0 },
      { first_seq: high, checked: 2 },
      { first_seq: '2', last_seq: '3', next_after_seq: '3', checked: 3 },
      { next_after_seq: null },
      { next_after_seq: '2' },
      { through_seq: '1' },
      { complete: true },
      { verified: false },
      { failure_reason: 'no_retained_records' },
      { broken_at_seq: '2' },
      { seed_hash: seed.slice(1) },
      { last_hash: hash.toUpperCase() },
      { expected_hash: hash },
      { seed_source: 'database_predecessor' },
      { first_seq: undefined },
      { next_after_seq: undefined },
      { chain: 'ledger', seed_hash: ledgerSeed, scope: ledgerScope },
      { chain: 'ledger', seed_hash: ledgerSeed, scope: ledgerScope, erased_checked: 3 },
      { chain: 'ledger', seed_hash: ledgerSeed, scope: ledgerScope, erased_checked: '2' },
    ])
      expect(() => verificationResponse(proof(patch))).toThrow('invalid_response');
  });

  it('rejects mismatched chain, fixed bound, request seed, scope, limit, and repeated or stale cursors', () => {
    const run = advanceVerificationRun(
      beginVerificationRun('audit', 2),
      verificationResponse(proof())
    );
    const next = proof({
      after_seq: high,
      seed_source: 'supplied_predecessor',
      seed_hash: hash,
      checked: 1,
      first_seq: maximum,
      last_seq: maximum,
      last_hash: finalHash,
      next_after_seq: maximum,
      complete: true,
    });
    for (const patch of [
      { chain: 'ledger', scope: ledgerScope, erased_checked: 0 },
      { through_seq: '9223372036854775806' },
      { after_seq: '2' },
      { seed_hash: seed },
      { seed_source: 'database_predecessor' },
      { scope: 'a different verification scope' },
    ])
      expect(() => advanceVerificationRun(run, { ...next, ...patch } as AdminVerification)).toThrow(
        'invalid_response'
      );
    expect(() => advanceVerificationRun(run, verificationResponse(proof()))).toThrow(
      'invalid_response'
    );
    expect(() => verificationPageResponse(proof(), 'audit', { limit: 1 })).toThrow(
      'invalid_response'
    );
    expect(() => verificationPageResponse(proof(), 'ledger', {})).toThrow('invalid_response');
    expect(() => verificationPageResponse(proof(), 'audit', { through_seq: high })).toThrow(
      'invalid_response'
    );
  });

  it('requires bounded continuation inputs, string coordinates, and exact digest lengths', () => {
    expect(
      validateVerifyQuery({
        after_seq: high,
        through_seq: maximum,
        predecessor_hash: hash,
        limit: 2,
      })
    ).toEqual({ after_seq: high, through_seq: maximum, predecessor_hash: hash, limit: 2 });
    for (const input of [
      { after_seq: high },
      { after_seq: maximum, through_seq: high },
      { after_seq: null },
      { after_seq: 1 },
      { through_seq: 1 },
      { after_seq: '01' },
      { predecessor_hash: 'a'.repeat(63) },
      { predecessor_hash: 'A'.repeat(64) },
      { limit: '1' },
      { limit: 0 },
      { limit: 5001 },
      { checkpoint: seed },
    ])
      expect(() => validateVerifyQuery(input as AdminVerifyQuery)).toThrow();
  });

  it.each([
    'chain_mismatch',
    'leaf_mismatch',
    'record_not_serializable',
    'payload_absent_without_erasure_record',
    'head_mismatch',
  ])('preserves HTTP-200 %s failure evidence and stops continuation', (reason) => {
    const mismatch = ['chain_mismatch', 'leaf_mismatch', 'head_mismatch'].includes(reason);
    const failed = verificationResponse(
      proof({
        verified: false,
        failure_reason: reason,
        broken_at_seq: high,
        through_seq: reason === 'head_mismatch' ? high : maximum,
        expected_hash: mismatch ? hash : null,
        stored_hash: mismatch ? seed : null,
        next_after_seq: reason === 'head_mismatch' ? high : null,
      })
    );
    expect(advanceVerificationRun(beginVerificationRun('audit', 1000), failed)).toMatchObject({
      checked: 2,
      next: null,
      result: { verified: false, failure_reason: reason },
    });
  });

  it.each(['invalid_leaf_hash', 'invalid_chain_hash'])(
    'supports %s before a node can contribute to checked',
    (reason) => {
      const first = proof({
        verified: false,
        failure_reason: reason,
        checked: 0,
        first_seq: null,
        last_seq: null,
        last_hash: seed,
        broken_at_seq: '2',
        next_after_seq: null,
      });
      expect(verificationResponse(first).checked).toBe(0);
      const later = proof({
        verified: false,
        failure_reason: reason,
        last_hash: seed,
        broken_at_seq: maximum,
        next_after_seq: null,
      });
      expect(verificationResponse(later).checked).toBe(2);
      expect(() => verificationResponse({ ...later, broken_at_seq: high })).toThrow(
        'invalid_response'
      );
    }
  );

  it('preserves predecessor mismatches and no-stored-records as different non-success states', () => {
    const run = advanceVerificationRun(
      beginVerificationRun('audit', 1000),
      verificationResponse(proof())
    );
    const mismatch = verificationResponse(
      proof({
        after_seq: high,
        seed_source: 'supplied_predecessor',
        seed_hash: hash,
        last_hash: hash,
        checked: 0,
        first_seq: null,
        last_seq: null,
        next_after_seq: null,
        verified: false,
        failure_reason: 'predecessor_mismatch',
        broken_at_seq: high,
        expected_hash: hash,
        stored_hash: finalHash,
      })
    );
    expect(advanceVerificationRun(run, mismatch).next).toBeNull();
    expect(() => verificationResponse({ ...mismatch, expected_hash: seed })).toThrow(
      'invalid_response'
    );
    const missing = verificationResponse(
      proof({
        verified: false,
        failure_reason: 'no_stored_records',
        checked: 0,
        first_seq: null,
        last_seq: null,
        last_hash: seed,
        next_after_seq: null,
      })
    );
    expect(advanceVerificationRun(beginVerificationRun('audit', 1000), missing)).toMatchObject({
      checked: 0,
      next: null,
      result: { verified: false, failure_reason: 'no_stored_records' },
    });
    for (const patch of [
      { complete: true },
      { broken_at_seq: '2' },
      { expected_hash: hash },
      { through_seq: '0' },
    ])
      expect(() => verificationResponse({ ...missing, ...patch })).toThrow('invalid_response');
  });

  it('permits equal head hashes for a head-sequence mismatch, but requires the reported expected head to match the page', () => {
    const failed = proof({
      through_seq: high,
      verified: false,
      failure_reason: 'head_mismatch',
      broken_at_seq: high,
      expected_hash: hash,
      stored_hash: hash,
    });
    expect(verificationResponse(failed).failure_reason).toBe('head_mismatch');
    expect(() => verificationResponse({ ...failed, expected_hash: seed })).toThrow(
      'invalid_response'
    );
  });
});
