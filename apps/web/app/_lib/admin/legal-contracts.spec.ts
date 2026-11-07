/** @jest-environment node */

import { capabilitiesResponse } from './contracts';
import {
  legalCreateResponse,
  legalDisclosureFields,
  legalHoldResponse,
  legalHoldsResponse,
  legalLookupResponse,
  type LegalLookupPage,
  type LegalLookupQuery,
} from './legal-contracts';
import {
  legalLookupContinuation,
  legalPageLimits,
  validateLegalHoldRequest,
  validateLegalHoldsQuery,
  validateLegalJSON,
  validateLegalLookupContinuation,
  validateLegalLookupQuery,
  validateLegalPreservationRequest,
} from './legal-validation';

const id = '00000000-0000-4000-8000-000000000001';
const other = '00000000-0000-4000-8000-000000000002';
const operation = '01234567-89ab-cdef-0123-456789abcdef';
const zero = '00000000-0000-0000-0000-000000000000';
const high = '9007199254740993';
const maximum = '9223372036854775807';
const limits = {
  page_size_default: 100,
  page_size_max: 200,
  audit_max_window_seconds: 31 * 86400,
  chain_verify_max_limit: 5000,
};
const request = {
  accountRef: id,
  requestId: operation,
  reason: 'Preserve the specified records',
  requestingAuthority: 'Authority reference',
  legalBasis: 'Recorded legal basis',
};
const hold = {
  id: other,
  account_ref: id,
  request_kind: 'legal_hold',
  reason: request.reason,
  requesting_authority: request.requestingAuthority,
  legal_basis: request.legalBasis,
  applied_by: other,
  is_active: true,
  applied_at: '2026-11-01T12:00:00.123456Z',
  review_at: null,
  released_at: null,
  released_by: null,
  details_purged: false,
  replayed: false,
};
const query: LegalLookupQuery = {
  identifier: 'Subject+intake@EXAMPLE.test',
  requestingAuthority: 'Authority reference',
  caseReference: 'Case reference',
  purpose: 'Recorded inquiry purpose',
  startTime: '2026-10-31T00:00:00Z',
  endTime: '2026-11-01T00:00:00Z',
  limit: 1,
  fields: [],
};
const event = {
  id: other,
  account_ref: id,
  event_type: 'auth.login',
  timestamp: '2026-10-31T12:00:00.123456Z',
  retain_until: null,
  seq: high,
};
const page = {
  items: [event],
  next_cursor: 'opaque-lookup-cursor',
  coverage: {
    through_seq: maximum,
    observed_at: '2026-11-01T12:00:00.123456789Z',
    eligibility_checked_at: '2026-11-01T12:00:00.123456789Z',
    note: 'Matching indexed retained records only; this is not complete historical coverage.',
  },
};

describe('legal capabilities and input boundaries', () => {
  it('requires all five independent legal flags without inferring privileges or route availability', () => {
    const flags = {
      users_read: false,
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
    };
    for (const name of [
      'legal_holds_read',
      'legal_holds_apply',
      'legal_holds_release',
      'preservation_requests_create',
      'legal_inquiry_lookup',
    ]) {
      expect(
        capabilitiesResponse({ capabilities: { ...flags, [name]: true }, limits }).capabilities
      ).toEqual({ ...flags, [name]: true });
      for (const value of [undefined, null, 0, 'true'])
        expect(() =>
          capabilitiesResponse({ capabilities: { ...flags, [name]: value }, limits })
        ).toThrow('invalid_response');
    }
    expect(capabilitiesResponse({ capabilities: flags, limits }).capabilities).toEqual(flags);
  });

  it('caps disclosure page sizes at the effective maximum and 50, without dropping data', () => {
    expect(legalPageLimits(limits)).toEqual({ default: 50, max: 50 });
    expect(legalPageLimits({ ...limits, page_size_default: 10, page_size_max: 25 })).toEqual({
      default: 10,
      max: 25,
    });
    expect(() => legalPageLimits({ ...limits, page_size_default: 26, page_size_max: 25 })).toThrow(
      'invalid_request'
    );
    expect(() => validateLegalLookupQuery({ ...query, limit: 51 })).toThrow('invalid_request');
    expect(() =>
      validateLegalLookupQuery(
        { ...query, limit: 2 },
        {
          ...limits,
          page_size_default: 1,
          page_size_max: 1,
        }
      )
    ).toThrow('invalid_request');
  });

  it('requires explicit holds status/pagination and rejects invalid filters rather than widening scope', () => {
    const all = { status: 'all', limit: 50, offset: 0 } as const;
    expect(validateLegalHoldsQuery(all)).toEqual(all);
    expect(validateLegalHoldsQuery({ ...all, accountRef: id }).accountRef).toBe(id);
    for (const patch of [
      { accountRef: '' },
      { accountRef: null },
      { accountRef: zero },
      { accountRef: operation.toUpperCase() },
      { account_ref: id },
      { status: '' },
      { status: 'preservation' },
      { status: undefined },
      { limit: 0 },
      { limit: 51 },
      { limit: '1' },
      { offset: -1 },
      { offset: 2147483648 },
      { offset: 0.5 },
      { reason: 'private' },
      { requestKind: 'preservation' },
    ])
      expect(() => validateLegalHoldsQuery({ ...all, ...patch } as never)).toThrow(
        'invalid_request'
      );
  });

  it('requires exact nonzero canonical target and operation UUIDs without synthesis', () => {
    for (const value of [
      undefined,
      null,
      '',
      zero,
      operation.toUpperCase(),
      operation.replaceAll('-', ''),
      `urn:uuid:${operation}`,
      `{${operation}}`,
      ` ${operation}`,
      `${operation}\n`,
    ]) {
      expect(() => validateLegalHoldRequest({ ...request, requestId: value } as never)).toThrow(
        'invalid_request'
      );
      expect(() => validateLegalHoldRequest({ ...request, accountRef: value } as never)).toThrow(
        'invalid_request'
      );
    }
    expect(validateLegalHoldRequest(request)).toEqual(request);
    expect(() => validateLegalHoldRequest({ ...request, user_id: id } as never)).toThrow(
      'invalid_request'
    );
    expect(() => validateLegalHoldRequest({ ...request, legalBasis: '' })).toThrow(
      'invalid_request'
    );
    expect(() => validateLegalPreservationRequest(request)).toThrow('invalid_request');
  });

  it('trims once with Go whitespace rules and enforces UTF-8 limits, not moderation limits', () => {
    const normalized = validateLegalHoldRequest({
      ...request,
      reason: '\u0085  narrative\ntext \u3000',
      requestingAuthority: '\ufeffAuthority',
      legalBasis: `  ${'\u00e9'.repeat(127)}a  `,
    });
    expect(normalized.reason).toBe('narrative\ntext');
    expect(normalized.requestingAuthority).toBe('\ufeffAuthority');
    expect(normalized.legalBasis).toHaveLength(128);
    expect(Object.isFrozen(normalized)).toBe(true);
    expect(
      validateLegalHoldRequest({ ...request, reason: '\u{1f642}'.repeat(1024) }).reason
    ).toHaveLength(2048);
    expect(validateLegalHoldRequest({ ...request, reason: 'x'.repeat(4096) }).reason).toHaveLength(
      4096
    );
    for (const patch of [
      { reason: 'x'.repeat(4097) },
      { reason: '\u{1f642}'.repeat(1025) },
      { reason: '\u0085\t\n' },
      { reason: '\ud800' },
      { requestingAuthority: '\u00e9'.repeat(128) },
      { legalBasis: 'x'.repeat(256) },
    ])
      expect(() => validateLegalHoldRequest({ ...request, ...patch })).toThrow('invalid_request');
  });

  it('accepts past UTC dates at stable microsecond precision, rejects implicit zones and precision loss', () => {
    const reviewAt = '1969-12-31T23:59:59.999999Z';
    expect(validateLegalHoldRequest({ ...request, reviewAt }).reviewAt).toBe(reviewAt);
    expect(validateLegalHoldRequest({ ...request, reviewAt: '' })).not.toHaveProperty('reviewAt');
    const preservation = {
      accountRef: id,
      requestId: operation,
      reason: request.reason,
      requestingAuthority: request.requestingAuthority,
    };
    expect(
      validateLegalPreservationRequest({ ...preservation, expiresAt: reviewAt }).expiresAt
    ).toBe(reviewAt);
    expect(validateLegalPreservationRequest({ ...preservation, expiresAt: '' })).not.toHaveProperty(
      'expiresAt'
    );
    for (const date of [
      '2026-11-01T00:00',
      '2026-11-01T00:00:00',
      '2026-11-01T00:00:00+01:00',
      '2026-11-01T00:00:00.1234567Z',
      '2026-11-01T00:00:00.123456000Z',
      '2026-02-30T00:00:00Z',
      '2026-11-01T24:00:00Z',
      '2026-11-01T00:00:00Z\n',
      '0000-01-01T00:00:00Z',
      '0001-01-01T00:00:00Z',
      null,
    ]) {
      expect(() => validateLegalHoldRequest({ ...request, reviewAt: date } as never)).toThrow(
        'invalid_request'
      );
      expect(() =>
        validateLegalPreservationRequest({ ...preservation, expiresAt: date } as never)
      ).toThrow('invalid_request');
    }
  });

  it('preserves email case and Unicode without provider-specific normalization and limits bytes', () => {
    const identifier = '\uff35ser.Name+case@EXAMPLE.test';
    expect(
      validateLegalLookupQuery({ ...query, identifier: `  ${identifier}\u0085` }).identifier
    ).toBe(identifier);
    const size = new TextEncoder().encode(identifier).length;
    const exact = `${' '.repeat(1024 - size)}${identifier}`;
    expect(new TextEncoder().encode(exact).length).toBe(1024);
    expect(validateLegalLookupQuery({ ...query, identifier: exact }).identifier).toBe(identifier);
    for (const identifier of ['User@\u4f8b\u3048.test', 'User@EXAMPLE\u3002test'])
      expect(validateLegalLookupQuery({ ...query, identifier }).identifier).toBe(identifier);
    for (const identifier of [
      '',
      ' ',
      'not-an-address',
      'display <subject@example.test>',
      'mailto:subject@example.test',
      'subject@example.test,other@example.test',
      'subject@@example.test',
      '.subject@example.test',
      'subject..name@example.test',
      'subject@example..test',
      'subject@',
      '@example.test',
      'subject\u0000@example.test',
      'sub ject@example.test',
      'subject@\ud800',
      ` ${exact}`,
      'Subject@[192.0.2.1]',
      'Subject@[2001:db8::1]',
      'subject@[256.0.0.1]',
      'subject@[192.00.2.1]',
      'subject@[2001:::1]',
      'subject\u200c@example.test',
      '\ufeffsubject@example.test',
      'subject\ufffd@example.test',
    ])
      expect(() => validateLegalLookupQuery({ ...query, identifier })).toThrow('invalid_request');
  });

  it('freezes the complete inquiry, sorts only selected fields, and retains nanosecond bounds', () => {
    const source = {
      ...query,
      fields: ['user_agent', 'client_ip'] as const,
      startTime: '2026-11-01T00:00:00.000000001Z',
      endTime: '2026-11-01T00:00:00.500000001Z',
    };
    const normalized = validateLegalLookupQuery(source, {
      ...limits,
      audit_max_window_seconds: 0.5,
    });
    expect(normalized.startTime).toBe(source.startTime);
    expect(normalized.endTime).toBe(source.endTime);
    expect(normalized.fields).toEqual(['client_ip', 'user_agent']);
    expect(Object.isFrozen(normalized)).toBe(true);
    expect(Object.isFrozen(normalized.fields)).toBe(true);
    expect(validateLegalLookupQuery(query).fields).toEqual([]);
    expect(() =>
      validateLegalLookupQuery(
        { ...source, endTime: '2026-11-01T00:00:00.500000002Z' },
        { ...limits, audit_max_window_seconds: 0.5 }
      )
    ).toThrow('invalid_request');
    for (const patch of [
      { endTime: '2026-10-30T00:00:00Z' },
      { startTime: '2026-09-01T00:00:00Z' },
      { purpose: '' },
      { purpose: 'x'.repeat(4097) },
      { requestingAuthority: '\u00e9'.repeat(128) },
      { caseReference: 'x'.repeat(256) },
      { fields: ['user_agent', 'user_agent'] },
      { fields: ['identity_blind_index'] },
      { fields: ['seq'] },
      { fields: undefined },
      { fields: null },
      { fields: 'user_agent' },
      { identifierType: 'phone' },
      { cursor: 'opaque' },
    ])
      expect(() => validateLegalLookupQuery({ ...query, ...patch } as never)).toThrow(
        'invalid_request'
      );
  });

  it('counts serialized UTF-8 and JSON escaping for the exact 32 KiB request limit', () => {
    expect(() => validateLegalJSON('x'.repeat(32 * 1024 - 2))).not.toThrow();
    expect(() => validateLegalJSON('x'.repeat(32 * 1024 - 1))).toThrow('invalid_request');
    expect(() => validateLegalJSON('\u{1f642}'.repeat(8192))).toThrow('invalid_request');
    expect(() => validateLegalJSON('\u0000'.repeat(5462))).toThrow('invalid_request');
    const cycle: { value?: unknown } = {};
    cycle.value = cycle;
    expect(() => validateLegalJSON(cycle)).toThrow('invalid_request');
    expect(() => validateLegalJSON(undefined)).toThrow('invalid_request');
  });
});

describe('legal hold and preservation projections', () => {
  it('preserves nullable dates and separates purged narratives from originally empty strings', () => {
    expect(legalHoldResponse({ ...hold, applied_at: null })).toEqual({ ...hold, applied_at: null });
    const {
      reason: _reason,
      requesting_authority: _authority,
      legal_basis: _basis,
      ...core
    } = hold;
    const purged = {
      ...core,
      is_active: false,
      details_purged: true,
      released_by: id,
      released_at: '2026-11-02T00:00:00Z',
    };
    expect(legalHoldResponse(purged)).toEqual(purged);
    for (const patch of [
      { id: zero },
      { account_ref: zero },
      { applied_by: zero },
      { request_kind: 'unknown' },
      { reason: undefined },
      { reason: '' },
      { requesting_authority: null },
      { legal_basis: undefined },
      { is_active: 'true' },
      { applied_at: undefined },
      { review_at: undefined },
      { review_at: '2026-02-30T00:00:00Z' },
      { released_by: undefined },
      { released_by: zero },
      { released_by: id },
      { details_purged: true },
      { replayed: undefined },
      { email: 'never returned' },
      { identity_blind_index: 'never returned' },
    ])
      expect(() => legalHoldResponse({ ...hold, ...patch })).toThrow('invalid_response');
    expect(() => legalHoldResponse({ ...purged, reason: '' })).toThrow('invalid_response');
    expect(() => legalHoldResponse({ ...purged, is_active: true })).toThrow('invalid_response');
  });

  it('matches snapshot counts, duplicates, status and original reference filters', () => {
    const parameters = { status: 'active', accountRef: id, limit: 1, offset: 0 } as const;
    const value = { items: [hold], total: 1, limit: 1, offset: 0 };
    expect(legalHoldsResponse(value, parameters).items).toHaveLength(1);
    for (const patch of [
      { total: 0 },
      { total: '1' },
      { total: 9007199254740992 },
      { limit: 0 },
      { limit: 2 },
      { offset: 1 },
      { items: [] },
      { items: [hold, hold] },
      { extra: 'private' },
      { items: [{ ...hold, account_ref: other }] },
      { items: [{ ...hold, is_active: false }] },
      { items: [{ ...hold, replayed: true }] },
    ])
      expect(() => legalHoldsResponse({ ...value, ...patch }, parameters)).toThrow(
        'invalid_response'
      );
    expect(
      legalHoldsResponse({ items: [], total: 1, offset: 2, limit: 1 }, { ...parameters, offset: 2 })
        .items
    ).toEqual([]);
    expect(() => legalHoldsResponse(value, { ...parameters, limit: 2 })).toThrow(
      'invalid_response'
    );
  });

  it('requires 201 for a new matching hold and 200 for a replay including released current state', () => {
    expect(legalCreateResponse(hold, 201, request, 'legal_hold')).toEqual(hold);
    const released = {
      ...hold,
      is_active: false,
      released_at: '2026-11-02T00:00:00Z',
      released_by: id,
      replayed: true,
    };
    expect(legalCreateResponse(released, 200, request, 'legal_hold')).toEqual(released);
    for (const [value, status] of [
      [hold, 200],
      [hold, 202],
      [released, 201],
      [{ ...released, replayed: false }, 201],
      [{ ...hold, account_ref: other }, 201],
      [{ ...hold, reason: 'different scope' }, 201],
      [{ ...hold, legal_basis: 'different basis' }, 201],
      [{ ...hold, review_at: '2026-01-01T00:00:00Z' }, 201],
    ] as const)
      expect(() => legalCreateResponse(value, status, request, 'legal_hold')).toThrow(
        'invalid_response'
      );
    const reviewAt = '2026-01-01T00:00:00.123400Z';
    expect(() =>
      legalCreateResponse(
        { ...hold, review_at: '2026-01-01T00:00:00.1234Z' },
        201,
        { ...request, reviewAt },
        'legal_hold'
      )
    ).not.toThrow();
    expect(() =>
      legalCreateResponse(
        { ...hold, review_at: '2026-01-01T00:00:00.123401Z' },
        201,
        { ...request, reviewAt },
        'legal_hold'
      )
    ).toThrow('invalid_response');
  });

  it('uses top-level preservation replay and never treats missing evidence as an invalid hold', () => {
    const preservation = {
      accountRef: id,
      requestId: operation,
      reason: request.reason,
      requestingAuthority: request.requestingAuthority,
      expiresAt: '2026-11-01T00:00:00Z',
    };
    const value = {
      hold: {
        ...hold,
        request_kind: 'preservation',
        legal_basis: 'preservation_request',
        review_at: preservation.expiresAt,
        replayed: false,
      },
      replayed: true,
      account_present: false,
      ledger_evidence_present: false,
      observed_at: '2026-11-01T12:00:00Z',
      note: 'Presence is an observation, not a completeness guarantee.',
    };
    expect(legalCreateResponse(value, 200, preservation, 'preservation')).toEqual(value);
    expect(() => legalCreateResponse(value, 201, preservation, 'preservation')).toThrow(
      'invalid_response'
    );
    for (const patch of [
      { account_present: 'false' },
      { ledger_evidence_present: null },
      { observed_at: null },
      { note: '' },
      { note: undefined },
      { extra: 'private' },
      { hold: { ...value.hold, request_kind: 'legal_hold' } },
      { hold: { ...value.hold, legal_basis: 'not preservation' } },
      { hold: { ...value.hold, review_at: null } },
    ])
      expect(() =>
        legalCreateResponse({ ...value, ...patch }, 200, preservation, 'preservation')
      ).toThrow('invalid_response');
  });
});

describe('attribution projection and fixed-scope continuation', () => {
  it('requires exact decimal coordinates without numeric fallback up to signed int64 maximum', () => {
    for (const seq of ['1', '9007199254740992', high, maximum]) {
      const value = { ...page, next_cursor: undefined, items: [{ ...event, seq }] };
      expect(legalLookupResponse(value, query).items[0].seq).toBe(seq);
    }
    for (const seq of [
      0,
      1,
      9007199254740992,
      1n,
      null,
      undefined,
      '',
      '00',
      '01',
      '-1',
      '+1',
      '1e3',
      '1.0',
      ' 1',
      '1\n',
      '1\u2028',
      '9223372036854775808',
    ]) {
      expect(() => legalLookupResponse({ ...page, items: [{ ...event, seq }] }, query)).toThrow(
        'invalid_response'
      );
      expect(() =>
        legalLookupResponse({ ...page, coverage: { ...page.coverage, through_seq: seq } }, query)
      ).toThrow('invalid_response');
    }
    expect(() => legalLookupResponse({ ...page, items: [{ ...event, seq: '0' }] }, query)).toThrow(
      'invalid_response'
    );
    expect(
      legalLookupResponse({ items: [], coverage: { ...page.coverage, through_seq: '0' } }, query)
        .items
    ).toEqual([]);
  });

  it('accepts only selected optional strings, never raw identity, blind indexes, payload or chain hashes', () => {
    for (const field of legalDisclosureFields) {
      expect(() =>
        legalLookupResponse({ ...page, items: [{ ...event, [field]: 'private' }] }, query)
      ).toThrow('invalid_response');
      const selected = { ...query, fields: [field] };
      expect(
        legalLookupResponse(
          { ...page, items: [{ ...event, [field]: '<b>inert text</b>' }] },
          selected
        ).items[0][field]
      ).toBe('<b>inert text</b>');
      expect(legalLookupResponse(page, selected).items[0]).not.toHaveProperty(field);
      for (const value of [null, 1, {}, [], '\ud800'])
        expect(() =>
          legalLookupResponse({ ...page, items: [{ ...event, [field]: value }] }, selected)
        ).toThrow('invalid_response');
    }
    for (const field of [
      'email',
      'identifier',
      'phone',
      'identity_blind_index',
      'pepper_version',
      'payload',
      'sha256_leaf_hash',
      'sha256_chain_hash',
      'credentials',
    ])
      expect(() =>
        legalLookupResponse({ ...page, items: [{ ...event, [field]: 'private' }] }, query)
      ).toThrow('invalid_response');
    expect(() => legalLookupResponse({ ...page, total: 1 }, query)).toThrow('invalid_response');
    expect(() =>
      legalLookupResponse({ ...page, coverage: { ...page.coverage, complete: true } }, query)
    ).toThrow('invalid_response');
  });

  it('checks request times at nanosecond precision and requires ascending bounded rows and honest pagination', () => {
    const narrowed = {
      ...query,
      startTime: '2026-10-31T12:00:00.123456001Z',
      endTime: '2026-10-31T12:00:00.123456002Z',
    };
    expect(
      legalLookupResponse(
        { ...page, items: [{ ...event, timestamp: narrowed.startTime }] },
        narrowed
      ).items
    ).toHaveLength(1);
    for (const timestamp of [null, undefined, event.timestamp, '2026-10-31T12:00:00.123456003Z'])
      expect(() =>
        legalLookupResponse({ ...page, items: [{ ...event, timestamp }] }, narrowed)
      ).toThrow('invalid_response');
    for (const patch of [
      { items: [] },
      { items: [event, event] },
      { next_cursor: '' },
      { next_cursor: null },
      { next_cursor: 'bad=cursor' },
      { next_cursor: 'x'.repeat(4097) },
      { coverage: { ...page.coverage, through_seq: high } },
      { coverage: { ...page.coverage, observed_at: '2026-11-01T12:00:00.123456790Z' } },
      { coverage: { ...page.coverage, eligibility_checked_at: undefined } },
    ])
      expect(() => legalLookupResponse({ ...page, ...patch }, query)).toThrow('invalid_response');
    const second = { ...event, id, seq: maximum };
    expect(() =>
      legalLookupResponse(
        { ...page, next_cursor: undefined, items: [second, event] },
        { ...query, limit: 2 }
      )
    ).toThrow('invalid_response');
    expect(
      legalLookupResponse(
        { ...page, next_cursor: undefined, items: [event, second] },
        { ...query, limit: 2 }
      ).items
    ).toHaveLength(2);
  });

  it('pins original coverage and every normalized input including limit across cursor pages', () => {
    const continuation = legalLookupContinuation(query, page);
    if (!continuation) throw new Error('Expected a continuation');
    expect(Object.isFrozen(continuation)).toBe(true);
    expect(Object.isFrozen(continuation.query.fields)).toBe(true);
    expect(continuation).toMatchObject({
      cursor: page.next_cursor,
      throughSeq: maximum,
      observedAt: page.coverage.observed_at,
      afterSeq: high,
    });
    expect(validateLegalLookupContinuation(query, continuation)).toEqual(continuation);
    const next: LegalLookupPage = {
      items: [{ ...event, id, seq: maximum }],
      coverage: { ...page.coverage, eligibility_checked_at: '2026-11-01T12:01:00Z' },
    };
    expect(legalLookupResponse(next, query, continuation)).toEqual(next);
    expect(legalLookupContinuation(query, next)).toBeUndefined();
    expect(legalLookupResponse({ ...next, items: [] }, query, continuation).items).toEqual([]);
    for (const patch of [
      { identifier: 'other@example.test' },
      { identifier: query.identifier.toLowerCase() },
      { requestingAuthority: 'Different authority' },
      { caseReference: 'Different case' },
      { purpose: 'Different purpose' },
      { startTime: '2026-10-30T23:59:59Z' },
      { endTime: '2026-11-01T00:00:01Z' },
      { limit: 2 },
      { fields: ['client_ip'] },
    ])
      expect(() =>
        validateLegalLookupContinuation({ ...query, ...patch } as LegalLookupQuery, continuation)
      ).toThrow('invalid_request');
    for (const patch of [
      { items: [event] },
      { items: [{ ...event, seq: '9007199254740992' }] },
      { coverage: { ...next.coverage, through_seq: '9223372036854775806' } },
      { coverage: { ...next.coverage, observed_at: '2026-11-01T12:00:00.123456788Z' } },
    ])
      expect(() => legalLookupResponse({ ...next, ...patch }, query, continuation)).toThrow(
        'invalid_response'
      );
    expect(() =>
      legalLookupResponse(
        { ...page, items: [{ ...event, seq: '9007199254740994' }] },
        query,
        continuation
      )
    ).toThrow('invalid_response');
    for (const patch of [
      { afterSeq: '0' },
      { afterSeq: maximum },
      { throughSeq: 1 },
      { cursor: '' },
      { observedAt: undefined },
      { extra: 'private' },
    ])
      expect(() =>
        validateLegalLookupContinuation(query, { ...continuation, ...patch } as never)
      ).toThrow('invalid_request');
  });
});
