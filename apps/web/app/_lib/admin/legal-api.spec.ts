/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { PortalClient } from '../portal/client';
import { StepUpGrant } from '../portal/contracts';
import type { BrowserKey } from '../portal/dpop';
import { PortalError } from '../portal/errors';
import { LegalClient } from './legal-api';
import type { LegalLookupQuery } from './legal-contracts';
import { legalLookupContinuation } from './legal-validation';

const origin = 'https://identity.example.test';
const id = '00000000-0000-4000-8000-000000000001';
const holdId = '00000000-0000-4000-8000-000000000002';
const requestId = '01234567-89ab-cdef-0123-456789abcdef';
const high = '9007199254740993';
const maximum = '9223372036854775807';
const request = {
  accountRef: id,
  requestId,
  reason: 'Reason',
  requestingAuthority: 'Authority',
  legalBasis: 'Basis',
};
const preservation = {
  accountRef: id,
  requestId,
  reason: 'Reason',
  requestingAuthority: 'Authority',
};
const hold = {
  id: holdId,
  account_ref: id,
  request_kind: 'legal_hold',
  reason: 'Reason',
  requesting_authority: 'Authority',
  legal_basis: 'Basis',
  applied_by: id,
  is_active: true,
  applied_at: '2026-11-01T12:00:00Z',
  review_at: null,
  released_at: null,
  released_by: null,
  details_purged: false,
  replayed: false,
};
const preserved = {
  hold: { ...hold, request_kind: 'preservation', legal_basis: 'preservation_request' },
  replayed: false,
  account_present: false,
  ledger_evidence_present: false,
  observed_at: '2026-11-01T12:00:00Z',
  note: 'Presence observations do not guarantee complete evidence.',
};
const query: LegalLookupQuery = {
  identifier: '\uff35ser+case@EXAMPLE.test',
  requestingAuthority: 'Authority',
  caseReference: 'Case',
  purpose: 'Purpose',
  startTime: '2026-10-31T00:00:00Z',
  endTime: '2026-11-01T00:00:00Z',
  limit: 1,
  fields: [],
};
const event = {
  id: holdId,
  account_ref: id,
  event_type: 'auth.login',
  timestamp: '2026-10-31T12:00:00Z',
  retain_until: '2027-01-01T00:00:00Z',
  seq: high,
};
const lookup = {
  items: [event],
  next_cursor: 'opaque-cursor',
  coverage: {
    through_seq: maximum,
    observed_at: '2026-11-01T12:00:00.123456789Z',
    eligibility_checked_at: '2026-11-01T12:00:00.123456790Z',
    note: 'Indexed retained records only.',
  },
};
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const rawJSON = (size: number) =>
  new Response(`"${'x'.repeat(size - 2)}"`, {
    headers: { 'Content-Type': 'application/json' },
  });
const grant = () =>
  new StepUpGrant(
    { token: 'one-use-legal-grant', token_type: 'StepUp', expires_in: 60 },
    'session-id',
    Date.now(),
    Date.now() + 60000
  );
let key: BrowserKey;
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

beforeAll(async () => {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (!jwk.x || !jwk.y) throw new Error('Missing public key');
  key = { privateKey: pair.privateKey, publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
});
afterAll(() => {
  if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto);
});

async function session() {
  const fetcher = jest.fn().mockResolvedValueOnce(
    json({
      id,
      email: 'actor@example.test',
      display_name: '',
      status: 'active',
      lifecycle_revision: high,
      session: { id: 'session-id', expires_at: new Date(Date.now() + 3600000).toISOString() },
    })
  );
  const portal = new PortalClient({ origin, fetcher, getKey: async () => key });
  await portal.bootstrap();
  fetcher.mockClear();
  return { portal, fetcher, api: new LegalClient(portal) };
}

describe('legal API uses only the shared session and exact browser request routes', () => {
  it('maps explicit holds filters into a structured query with a queryless DPoP target', async () => {
    const { api, fetcher } = await session();
    fetcher.mockResolvedValueOnce(json({ items: [hold], total: 1, limit: 1, offset: 0 }));
    expect(
      (await api.holds({ accountRef: id, status: 'active', limit: 1, offset: 0 })).items
    ).toEqual([hold]);
    const [target, options] = fetcher.mock.calls[0];
    const url = new URL(target);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      account_ref: id,
      status: 'active',
      limit: '1',
      offset: '0',
    });
    const headers = new Headers(options.headers);
    const proof = JSON.parse(
      Buffer.from((headers.get('DPoP') ?? '').split('.')[1], 'base64url').toString()
    );
    expect(proof.htu).toBe(`${origin}/api/v1/admin/legal-holds`);
    expect(proof.htm).toBe('GET');
    expect(headers.get('X-Portal-Session')).toBe('session-id');
    expect(headers.has('X-Step-Up-Auth')).toBe(false);
    expect(headers.has('Idempotency-Key')).toBe(false);
    expect(options.body).toBeUndefined();
    expect(options).toMatchObject({
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    fetcher.mockResolvedValueOnce(json({ items: [], total: 0, limit: 1, offset: 0 }));
    await api.holds({ status: 'all', limit: 1, offset: 0 });
    expect(new URL(fetcher.mock.calls[1][0]).searchParams.has('account_ref')).toBe(false);
  });

  it('maps frozen camel-case creates to explicit DTO bodies and the recorded operation header', async () => {
    const { api, fetcher } = await session();
    fetcher
      .mockResolvedValueOnce(json(hold, 201))
      .mockResolvedValueOnce(json({ ...preserved, replayed: true }, 200));
    const first = grant();
    const second = grant();
    const sent = jest.fn();
    expect(
      await api.applyHold({ ...request, reason: '  Reason\u0085' }, first, undefined, sent)
    ).toEqual(hold);
    expect(await api.preserve(preservation, second, undefined, sent)).toMatchObject({
      replayed: true,
      account_present: false,
      ledger_evidence_present: false,
      hold: { replayed: false },
    });
    const [holdURL, holdOptions] = fetcher.mock.calls[0];
    const [preservationURL, preservationOptions] = fetcher.mock.calls[1];
    expect(holdURL).toBe(`${origin}/api/v1/admin/legal-holds`);
    expect(preservationURL).toBe(`${origin}/api/v1/admin/preservation-requests`);
    expect(JSON.parse(holdOptions.body)).toEqual({
      account_ref: id,
      reason: 'Reason',
      requesting_authority: 'Authority',
      legal_basis: 'Basis',
    });
    expect(JSON.parse(preservationOptions.body)).toEqual({
      account_ref: id,
      reason: 'Reason',
      requesting_authority: 'Authority',
    });
    for (const options of [holdOptions, preservationOptions]) {
      expect(options.method).toBe('POST');
      const headers = new Headers(options.headers);
      expect(headers.get('Idempotency-Key')).toBe(requestId);
      expect(headers.get('X-Step-Up-Auth')).toBe('one-use-legal-grant');
      expect(headers.get('Content-Type')).toBe('application/json');
      expect(headers.has('Authorization')).toBe(false);
      expect(options.body).not.toContain(requestId);
    }
    expect(sent).toHaveBeenCalledTimes(2);
    expect(() => first.take('session-id')).toThrow('grant_expired');
    expect(() => second.take('session-id')).toThrow('grant_expired');
  });

  it('sends only a pinned hold DELETE with no body, narrative, revision or idempotency key', async () => {
    const { api, fetcher } = await session();
    fetcher.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const authority = grant();
    const sent = jest.fn();
    await expect(api.releaseHold(holdId, authority, undefined, sent)).resolves.toBeUndefined();
    const [target, options] = fetcher.mock.calls[0];
    expect(target).toBe(`${origin}/api/v1/admin/legal-holds/${holdId}`);
    expect(options.method).toBe('DELETE');
    expect(options.body).toBeUndefined();
    expect(new Headers(options.headers).has('Content-Type')).toBe(false);
    expect(new Headers(options.headers).has('Idempotency-Key')).toBe(false);
    expect(sent).toHaveBeenCalledTimes(1);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
    fetcher.mockResolvedValueOnce(json({}));
    await expect(api.releaseHold(holdId, grant())).rejects.toMatchObject({
      code: 'invalid_response',
      uncertain: true,
    });
  });

  it('rejects unrecognized, missing and invalid input before grant consumption or transmission', async () => {
    const { api, fetcher } = await session();
    const authority = grant();
    const sent = jest.fn();
    for (const patch of [
      { requestId: undefined },
      { requestId: '' },
      { requestId: requestId.toUpperCase() },
      { accountRef: '' },
      { user_id: id },
      { reason: '\ud800' },
      { legalBasis: '' },
      { reviewAt: '2026-11-01T00:00:00.123456789Z' },
    ])
      await expect(
        api.applyHold({ ...request, ...patch } as never, authority, undefined, sent)
      ).rejects.toMatchObject({ code: 'invalid_request', uncertain: false });
    await expect(
      api.preserve({ ...preservation, legalBasis: 'invented' } as never, authority)
    ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(api.releaseHold(`${holdId}?reason=private`, authority)).rejects.toMatchObject({
      code: 'invalid_request',
    });
    await expect(
      api.holds({ status: 'all', limit: 1, offset: 0, accountRef: '' })
    ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(
      api.lookup({ ...query, fields: ['email'] } as never, authority)
    ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
    expect(sent).not.toHaveBeenCalled();
    expect(authority.take('session-id')).toBe('one-use-legal-grant');
  });

  it('allows the canonical operation key only on the two exact create POST paths', async () => {
    const { portal, fetcher } = await session();
    const authority = grant();
    for (const [path, method] of [
      ['/api/v1/admin/legal-holds', 'GET'],
      ['/api/v1/admin/legal-holds', 'PATCH'],
      [`/api/v1/admin/legal-holds/${holdId}`, 'DELETE'],
      ['/api/v1/admin/legal-inquiry/lookup', 'POST'],
      ['/api/v1/admin/preservation-requests', 'DELETE'],
      ['/api/v1/admin/legal-holds/other', 'POST'],
      ['/api/v1/admin/users/lookup', 'POST'],
      ['/api/v1/auth/stepup/verify', 'POST'],
    ] as const)
      await expect(
        portal.request(path, (value) => value, {
          method,
          idempotencyKey: requestId,
          grant: authority,
        })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    for (const idempotencyKey of [
      '',
      '00000000-0000-0000-0000-000000000000',
      requestId.toUpperCase(),
      ` ${requestId}`,
      `${requestId}\n`,
      requestId.replaceAll('-', ''),
      `urn:uuid:${requestId}`,
      1,
      null,
    ])
      await expect(
        portal.request('/api/v1/admin/legal-holds', (value) => value, {
          method: 'POST',
          idempotencyKey: idempotencyKey as never,
          grant: authority,
        })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
    expect(authority.take('session-id')).toBe('one-use-legal-grant');
  });

  it('restricts structured legal queries and rejects raw URLs, duplicates, empty references and body-route queries', async () => {
    const { portal, fetcher } = await session();
    for (const path of [
      '/api/v1/admin/legal-holds?',
      `/api/v1/admin/legal-holds?account_ref=${id}`,
      '/api/v1/admin/preservation-requests?',
      '/api/v1/admin/legal-inquiry/lookup?',
      `/api/v1/admin/legal-holds/${holdId}?`,
    ])
      await expect(portal.request(path, (value) => value)).rejects.toMatchObject({
        code: 'invalid_request',
      });
    for (const parameters of [
      { account_ref: '' },
      { account_ref: null },
      { account_ref: '00000000-0000-0000-0000-000000000000' },
      { account_ref: [id, holdId] },
      { status: '' },
      { status: 'active&account_ref=private' },
      { identifier: 'private@example.test' },
      { reason: 'private' },
      { request_kind: 'preservation' },
      { limit: '01' },
      { limit: -1 },
      { offset: 2147483648 },
      new URLSearchParams(`account_ref=${id}&account_ref=${holdId}`),
    ])
      await expect(
        portal.request('/api/v1/admin/legal-holds', (value) => value, {
          query: parameters as never,
        })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    for (const path of [
      '/api/v1/admin/legal-inquiry/lookup',
      '/api/v1/admin/preservation-requests',
      `/api/v1/admin/legal-holds/${holdId}`,
    ])
      await expect(
        portal.request(path, (value) => value, { query: { account_ref: id } })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(
      portal.request('/api/v1/admin/legal-holds', (value) => value, { method: 'POST', query: {} })
    ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('freezes scope/fields/page size and sends each explicit cursor page only with fresh authority', async () => {
    const { api, fetcher } = await session();
    fetcher.mockResolvedValueOnce(json(lookup));
    const firstGrant = grant();
    const first = await api.lookup(query, firstGrant);
    const firstBody = JSON.parse(fetcher.mock.calls[0][1].body);
    expect(firstBody).toEqual({
      identifier_type: 'email',
      identifier: query.identifier,
      requesting_authority: query.requestingAuthority,
      case_reference: query.caseReference,
      purpose: query.purpose,
      start_time: query.startTime,
      end_time: query.endTime,
      limit: 1,
      fields: [],
    });
    expect(fetcher.mock.calls[0][0]).toBe(`${origin}/api/v1/admin/legal-inquiry/lookup`);
    expect(new Headers(fetcher.mock.calls[0][1].headers).has('Idempotency-Key')).toBe(false);
    const continuation = legalLookupContinuation(query, first);
    if (!continuation) throw new Error('Expected a continuation');
    await expect(
      api.lookup(query, firstGrant, undefined, undefined, continuation)
    ).rejects.toMatchObject({ code: 'grant_expired' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    const freshGrant = grant();
    for (const patch of [
      { identifier: 'different@example.test' },
      { requestingAuthority: 'Different' },
      { caseReference: 'Different' },
      { purpose: 'Different' },
      { startTime: '2026-10-30T00:00:00Z' },
      { endTime: '2026-11-02T00:00:00Z' },
      { fields: ['client_ip'] },
      { limit: 2 },
    ])
      await expect(
        api.lookup(
          { ...query, ...patch } as LegalLookupQuery,
          freshGrant,
          undefined,
          undefined,
          continuation
        )
      ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(
      json({
        items: [{ ...event, id, seq: maximum }],
        coverage: { ...lookup.coverage, eligibility_checked_at: '2026-11-01T12:01:00Z' },
      })
    );
    const second = await api.lookup(query, freshGrant, undefined, undefined, continuation);
    expect(second.items[0].seq).toBe(maximum);
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({
      ...firstBody,
      cursor: lookup.next_cursor,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

describe('legal nonce, failures and late responses', () => {
  it('never drops a rejected lookup cursor to restart or broaden the inquiry', async () => {
    const { api, fetcher } = await session();
    const continuation = legalLookupContinuation(query, lookup);
    if (!continuation) throw new Error('Expected a continuation');
    fetcher.mockResolvedValueOnce(json({ error: 'invalid_request' }, 400));
    const authority = grant();
    await expect(
      api.lookup(query, authority, undefined, undefined, continuation)
    ).rejects.toMatchObject({ code: 'invalid_request', status: 400, uncertain: false });
    expect(JSON.parse(fetcher.mock.calls[0][1].body).cursor).toBe(lookup.next_cursor);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
  });

  it.each(['hold', 'preservation'] as const)(
    'resends the exact %s body/key/grant only for one pre-handler nonce',
    async (kind) => {
      const { api, fetcher } = await session();
      const source = kind === 'hold' ? { ...request } : { ...preservation };
      fetcher
        .mockImplementationOnce(async () => {
          source.reason = 'Changed after serialization';
          source.requestId = holdId;
          return json({ error: 'use_dpop_nonce' }, 401, {
            'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
            'DPoP-Nonce': 'server-nonce',
          });
        })
        .mockResolvedValueOnce(json(kind === 'hold' ? hold : preserved, 201));
      const authority = grant();
      const sent = jest.fn();
      if (kind === 'hold')
        await api.applyHold(source as typeof request, authority, undefined, sent);
      else await api.preserve(source, authority, undefined, sent);
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(sent).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.calls[0][0]).toBe(fetcher.mock.calls[1][0]);
      expect(fetcher.mock.calls[0][1].body).toBe(fetcher.mock.calls[1][1].body);
      const proofs = fetcher.mock.calls.map(([, options]) => {
        const headers = new Headers(options.headers);
        expect(headers.get('Idempotency-Key')).toBe(requestId);
        expect(headers.get('X-Step-Up-Auth')).toBe('one-use-legal-grant');
        return JSON.parse(
          Buffer.from((headers.get('DPoP') ?? '').split('.')[1], 'base64url').toString()
        );
      });
      expect(proofs[0].jti).not.toBe(proofs[1].jti);
      expect(proofs[0].nonce).toBeUndefined();
      expect(proofs[1].nonce).toBe('server-nonce');
      expect(() => authority.take('session-id')).toThrow('grant_expired');
    }
  );

  it('never retries a repeated nonce or an incomplete/non-DPoP challenge', async () => {
    const { api, fetcher } = await session();
    fetcher.mockImplementation(async () =>
      json({ error: 'use_dpop_nonce' }, 401, {
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
        'DPoP-Nonce': 'nonce',
      })
    );
    await expect(api.applyHold(request, grant())).rejects.toMatchObject({ code: 'use_dpop_nonce' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const authenticate of [
      '',
      'Basic error="use_dpop_nonce"',
      'DPoP error="use_dpop_nonce", Basic realm="x"',
    ]) {
      fetcher.mockReset().mockResolvedValueOnce(
        json({ error: 'use_dpop_nonce' }, 401, {
          'WWW-Authenticate': authenticate,
          'DPoP-Nonce': 'nonce',
        })
      );
      await expect(api.applyHold(request, grant())).rejects.toMatchObject({
        code: 'use_dpop_nonce',
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });

  it.each([
    [400, 'invalid_request'],
    [401, 'session_required'],
    [403, 'forbidden'],
    [403, 'insufficient_user_authentication'],
    [404, 'hold_not_found'],
    [409, 'idempotency_conflict'],
    [429, 'rate_limited'],
    [500, 'response_too_large'],
    [503, 'legal_unavailable'],
    [503, 'audit_unavailable'],
  ] as const)(
    'does not automatically replay a legal create on HTTP %i %s',
    async (status, code) => {
      const { api, fetcher, portal } = await session();
      const lost = jest.fn();
      portal.onSessionLoss = lost;
      fetcher.mockResolvedValueOnce(
        json({ error: code, private_diagnostic: 'must not be retained' }, status, {
          'Retry-After': '99999999',
        })
      );
      const authority = grant();
      await expect(api.applyHold(request, authority)).rejects.toMatchObject({
        code,
        status,
        message: code,
        uncertain: status >= 500,
        retryAfterSeconds: 3600,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(() => authority.take('session-id')).toThrow('grant_expired');
      expect(lost).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
      if (status === 403) expect(portal.assertSession().id).toBe(id);
    }
  );

  it('reports lost or malformed writes as unconfirmed, but a lost lookup is not a business mutation', async () => {
    const { api, fetcher } = await session();
    fetcher.mockRejectedValue(new Error('private@example.test?purpose=secret'));
    for (const send of [
      () => api.applyHold(request, grant()),
      () => api.preserve(preservation, grant()),
      () => api.releaseHold(holdId, grant()),
    ])
      await expect(send()).rejects.toMatchObject({
        code: 'network_error',
        message: 'network_error',
        uncertain: true,
      });
    await expect(api.lookup(query, grant())).rejects.toMatchObject({
      code: 'network_error',
      uncertain: false,
    });
    expect(fetcher).toHaveBeenCalledTimes(4);
    for (const response of [
      json({ ...hold, account_ref: holdId }, 201),
      new Response('{invalid', { status: 201, headers: { 'Content-Type': 'application/json' } }),
      new Response(Uint8Array.of(0x22, 0xff, 0x22), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
      rawJSON(256 * 1024 + 1),
    ]) {
      fetcher.mockResolvedValueOnce(response);
      await expect(api.applyHold(request, grant())).rejects.toMatchObject({
        code: 'invalid_response',
        uncertain: true,
      });
    }
    fetcher.mockResolvedValueOnce(json({ ...lookup, items: [{ ...event, seq: Number(high) }] }));
    await expect(api.lookup(query, grant())).rejects.toMatchObject({
      code: 'invalid_response',
      uncertain: false,
    });
    expect(fetcher).toHaveBeenCalledTimes(9);
  });

  it('retains pre-send cancellation authority, and withholds late responses after an ignored abort', async () => {
    const { api, fetcher } = await session();
    const before = new AbortController();
    before.abort();
    const unsent = jest.fn();
    const unused = grant();
    await expect(api.applyHold(request, unused, before.signal, unsent)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(fetcher).not.toHaveBeenCalled();
    expect(unsent).not.toHaveBeenCalled();
    expect(unused.take('session-id')).toBe('one-use-legal-grant');
    const controller = new AbortController();
    fetcher.mockImplementationOnce(async () => {
      controller.abort();
      return json(hold, 201);
    });
    const sent = jest.fn();
    const authority = grant();
    await expect(api.applyHold(request, authority, controller.signal, sent)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
  });
});

describe('exact legal request and response budgets', () => {
  it.each([
    '/api/v1/admin/legal-holds',
    '/api/v1/admin/preservation-requests',
    '/api/v1/admin/legal-inquiry/lookup',
  ])('validates the serialized 32 KiB POST budget before consuming a grant on %s', async (path) => {
    const { portal, fetcher } = await session();
    const authority = grant();
    for (const body of ['x'.repeat(32 * 1024 - 1), '\u{1f642}'.repeat(8192), '\u0000'.repeat(5462)])
      await expect(
        portal.request(path, (value) => value, { method: 'POST', body, grant: authority })
      ).rejects.toMatchObject({ code: 'invalid_request', uncertain: false });
    expect(fetcher).not.toHaveBeenCalled();
    fetcher.mockResolvedValueOnce(json({}));
    await portal.request(path, (value) => value, {
      method: 'POST',
      body: 'x'.repeat(32 * 1024 - 2),
      grant: authority,
    });
    expect(new TextEncoder().encode(fetcher.mock.calls[0][1].body).length).toBe(32 * 1024);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
  });

  it('keeps the existing 64 KiB request limit for other routes', async () => {
    const { portal, fetcher } = await session();
    fetcher.mockResolvedValueOnce(json({}));
    await portal.request('/api/v1/admin/users/lookup', (value) => value, {
      method: 'POST',
      body: 'x'.repeat(64 * 1024 - 2),
    });
    expect(new TextEncoder().encode(fetcher.mock.calls[0][1].body).length).toBe(64 * 1024);
  });

  it('accepts complete typed legal pages above 256 KiB without dropping narratives or selected telemetry', async () => {
    const { api, fetcher } = await session();
    const reason = `r${'\u0000'.repeat(4095)}`;
    const items = Array.from({ length: 12 }, (_, index) => ({
      ...hold,
      id: `00000000-0000-4000-8000-${String(index + 10).padStart(12, '0')}`,
      reason,
    }));
    const value = { items, limit: 12, total: 12, offset: 0 };
    expect(new TextEncoder().encode(JSON.stringify(value)).length).toBeGreaterThan(256 * 1024);
    fetcher.mockResolvedValueOnce(json(value));
    expect(await api.holds({ status: 'active', limit: 12, offset: 0 })).toEqual(value);
    const user_agent = 'x'.repeat(300 * 1024);
    fetcher.mockResolvedValueOnce(json({ ...lookup, items: [{ ...event, user_agent }] }));
    expect(
      (await api.lookup({ ...query, fields: ['user_agent'] }, grant())).items[0].user_agent
    ).toBe(user_agent);
  });

  it.each([
    ['/api/v1/admin/audit-logs', 'GET'],
    ['/api/v1/admin/legal-holds', 'GET'],
    ['/api/v1/admin/legal-inquiry/lookup', 'POST'],
  ] as const)(
    'allows exactly 4 MiB and checks declared and streamed bytes for %s %s',
    async (path, method) => {
      const { portal, fetcher } = await session();
      const limit = 4 * 1024 * 1024;
      fetcher.mockResolvedValueOnce(rawJSON(limit));
      expect((await portal.request(path, (value) => value as string, { method })).length).toBe(
        limit - 2
      );
      for (const declared of [String(limit + 1), '999999999999999999', '-1', '1, 2']) {
        const cancel = jest.fn();
        fetcher.mockResolvedValueOnce(
          new Response(new ReadableStream({ cancel }), {
            headers: { 'Content-Type': 'application/json', 'Content-Length': declared },
          })
        );
        await expect(portal.request(path, (value) => value, { method })).rejects.toMatchObject({
          code: 'invalid_response',
          uncertain: false,
        });
        expect(cancel).toHaveBeenCalledTimes(1);
      }
      for (const declared of [undefined, '2']) {
        const cancel = jest.fn();
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(limit / 2));
            controller.enqueue(new Uint8Array(limit / 2));
            controller.enqueue(Uint8Array.of(1));
          },
          cancel,
        });
        fetcher.mockResolvedValueOnce(
          new Response(stream, {
            headers: {
              'Content-Type': 'application/json',
              ...(declared === undefined ? {} : { 'Content-Length': declared }),
            },
          })
        );
        const decode = jest.fn();
        await expect(portal.request(path, decode, { method })).rejects.toMatchObject({
          code: 'invalid_response',
          uncertain: false,
        });
        expect(decode).not.toHaveBeenCalled();
        expect(cancel).toHaveBeenCalledTimes(1);
      }
    }
  );

  it('does not widen any near-match path or other legal method beyond 256 KiB', async () => {
    const { portal, fetcher } = await session();
    for (const [path, method] of [
      ['/api/v1/admin/legal-holds', 'POST'],
      ['/api/v1/admin/legal-holds', 'PATCH'],
      ['/api/v1/admin/preservation-requests', 'POST'],
      ['/api/v1/admin/preservation-requests', 'GET'],
      [`/api/v1/admin/legal-holds/${holdId}`, 'DELETE'],
      ['/api/v1/admin/legal-inquiry/lookup', 'GET'],
      ['/api/v1/admin/legal-inquiry/lookup/other', 'POST'],
      ['/api/v1/admin/legal-holds/other', 'GET'],
      ['/api/v1/admin/audit-logs', 'POST'],
      ['/api/v1/admin/audit-logs/verify', 'GET'],
    ] as const) {
      fetcher.mockResolvedValueOnce(rawJSON(256 * 1024));
      expect((await portal.request(path, (value) => value as string, { method })).length).toBe(
        256 * 1024 - 2
      );
      fetcher.mockResolvedValueOnce(rawJSON(256 * 1024 + 1));
      await expect(portal.request(path, (value) => value, { method })).rejects.toMatchObject({
        code: 'invalid_response',
      });
    }
  });

  it('withholds forbidden disclosures and wrong HTTP success variants instead of showing partial results', async () => {
    const { api, fetcher } = await session();
    for (const value of [
      { ...lookup, items: [{ ...event, user_agent: 'not selected' }] },
      { ...lookup, items: [{ ...event, identifier: query.identifier }] },
      { ...lookup, coverage: { ...lookup.coverage, through_seq: Number(maximum) } },
    ]) {
      fetcher.mockResolvedValueOnce(json(value));
      await expect(api.lookup(query, grant())).rejects.toBeInstanceOf(PortalError);
    }
    fetcher.mockResolvedValueOnce(json(lookup, 201));
    await expect(api.lookup(query, grant())).rejects.toMatchObject({
      code: 'invalid_response',
      uncertain: false,
    });
    fetcher.mockResolvedValueOnce(json({ items: [hold], total: 1, limit: 1, offset: 0 }, 201));
    await expect(api.holds({ status: 'active', limit: 1, offset: 0 })).rejects.toMatchObject({
      code: 'invalid_response',
    });
    expect(fetcher).toHaveBeenCalledTimes(5);
  });
});
