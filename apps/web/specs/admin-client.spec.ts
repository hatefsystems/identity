/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { AdminClient } from '../app/_lib/admin/client';
import { PortalClient } from '../app/_lib/portal/client';
import { StepUpGrant } from '../app/_lib/portal/contracts';
import type { BrowserKey } from '../app/_lib/portal/dpop';
import {
  errorMessage,
  isSessionLoss,
  parseRetryAfter,
  PortalError,
} from '../app/_lib/portal/errors';
import { readResponse } from '../app/_lib/portal/json-response';

const origin = 'https://identity.example.test';
const id = '00000000-0000-4000-8000-000000000001';
const high = '9007199254740993';
const maximum = '9223372036854775807';
const hash = 'a'.repeat(64);
const user = {
  id,
  status: 'active',
  is_mfa_enabled: false,
  lifecycle_revision: high,
  created_at: null,
  updated_at: null,
  deleted_at: null,
};
const auditQuery = {
  start_time: '2026-10-27T00:00:00Z',
  end_time: '2026-10-28T00:00:00Z',
  limit: 1,
};
const row = {
  id,
  user_id: null,
  actor_id: id,
  actor_spiffe_id: 'spiffe://identity.test/service',
  event_type: 'admin.users.viewed',
  action_status: 'success',
  client_ip: '',
  user_agent: '',
  payload: '{}',
  timestamp: '2026-10-27T12:00:00Z',
  sha256_leaf_hash: hash,
  sha256_chain_hash: hash,
  seq: high,
};
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const nonce = (
  authenticate = 'DPoP error="use_dpop_nonce"',
  status = 401,
  challenge = 'server-nonce'
) =>
  json({ error: 'use_dpop_nonce' }, status, {
    'WWW-Authenticate': authenticate,
    'DPoP-Nonce': challenge,
  });
const rawJSON = (size: number) =>
  new Response(`"${'x'.repeat(size - 2)}"`, { headers: { 'Content-Type': 'application/json' } });
const grant = () =>
  new StepUpGrant(
    { token: 'one-use-grant', token_type: 'StepUp', expires_in: 60 },
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
  return { portal, api: new AdminClient(portal), fetcher };
}

describe('admin structured-query and one-session transport', () => {
  it('fetches all and only structured allowlisted queries while signing origin plus pathname', async () => {
    const { portal, fetcher } = await session();
    fetcher.mockImplementation(async () => json({}));
    const requests = [
      ['/api/v1/admin/users', { status: 'active', limit: 2, offset: 0 }],
      [
        '/api/v1/admin/audit-logs',
        { ...auditQuery, event_type: 'admin.users.viewed', before_seq: maximum },
      ],
      [
        '/api/v1/admin/audit-logs/verify',
        { after_seq: high, through_seq: maximum, predecessor_hash: hash, limit: 2 },
      ],
      ['/api/v1/admin/ledger/verify', { after_seq: '0', limit: 2 }],
    ] as const;
    for (const [path, query] of requests) await portal.request(path, (value) => value, { query });
    for (const [index, [target, options]] of fetcher.mock.calls.entries()) {
      const url = new URL(target);
      const headers = new Headers(options.headers);
      const claims = JSON.parse(
        Buffer.from((headers.get('DPoP') ?? '').split('.')[1], 'base64url').toString()
      );
      expect(url.origin).toBe(origin);
      expect(url.pathname).toBe(requests[index][0]);
      for (const [name, value] of Object.entries(requests[index][1]))
        expect(url.searchParams.get(name)).toBe(String(value));
      expect(claims.htu).toBe(`${origin}${url.pathname}`);
      expect(claims.htm).toBe('GET');
      expect(claims.ath).toBeUndefined();
      expect(headers.get('X-Portal-Session')).toBe('session-id');
      expect(headers.has('Authorization')).toBe(false);
      expect(headers.has('Origin')).toBe(false);
      expect(headers.has('Referer')).toBe(false);
      expect(options).toMatchObject({
        credentials: 'same-origin',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      });
      expect(options.signal).toBeInstanceOf(AbortSignal);
    }
  });

  it('constructs escaped values with URLSearchParams rather than treating them as additional keys', async () => {
    const { portal, fetcher } = await session();
    fetcher.mockResolvedValue(json({}));
    await portal.request('/api/v1/admin/users', (value) => value, {
      query: { status: 'active&offset=100#fragment' },
    });
    const url = new URL(fetcher.mock.calls[0][0]);
    expect([...url.searchParams.keys()]).toEqual(['status']);
    expect(url.searchParams.get('status')).toBe('active&offset=100#fragment');
    expect(url.hash).toBe('');
  });

  it('rejects raw query paths, normalization tricks, unsupported routes/keys, duplicate containers and non-string coordinates before send', async () => {
    const { portal, fetcher } = await session();
    for (const path of [
      '/api/v1/admin/users?limit=1',
      '/api/v1/admin/users?',
      '/api/v1/admin/users#fragment',
      '/api/v1/admin/users/',
      '/api/v1/admin//users',
      '/api/v1/admin/../users',
      '/api/v1/admin/%75sers',
      '/api/v1/admin/%2e%2e/users',
      '/api/v1/admin/%252e%252e/users',
      '/api/v1/admin/users%3flimit=1',
      '/api/v1/admin/users\\lookup',
      '/api/v1/admin/users\n',
      `${origin}/api/v1/admin/users`,
      '//evil.test/api/v1/admin/users',
    ])
      await expect(portal.request(path, (value) => value)).rejects.toMatchObject({
        code: 'invalid_request',
      });
    for (const path of [
      '/api/v1/users/me',
      '/api/v1/admin/capabilities',
      `/api/v1/admin/users/${id}`,
      '/api/v1/admin/users/lookup',
      '/api/v1/admin/audit-logs/other',
    ])
      await expect(portal.request(path, (value) => value, { query: {} })).rejects.toMatchObject({
        code: 'invalid_request',
      });
    for (const query of [
      { email: 'private@example.test' },
      { reason: 'private' },
      { Limit: 1 },
      { 'limit&email': 1 },
      { limit: [1, 2] },
      { limit: NaN },
      { limit: Infinity },
      { limit: 1.5 },
      { status: 'x\n' },
      { status: 'x'.repeat(129) },
      new URLSearchParams('limit=1&limit=2'),
      [
        ['limit', '1'],
        ['limit', '2'],
      ],
      Object.create({ limit: 1 }),
      null,
    ])
      await expect(
        portal.request('/api/v1/admin/users', (value) => value, { query: query as never })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    for (const before_seq of [
      1,
      null,
      '01',
      '-1',
      '9223372036854775808',
      '1\u2028',
      '9223372036854775808\u2029',
    ])
      await expect(
        portal.request('/api/v1/admin/audit-logs', (value) => value, {
          query: { before_seq } as never,
        })
      ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(
      portal.request('/api/v1/admin/audit-logs', (value) => value, { query: { offset: 0 } })
    ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(
      portal.request('/api/v1/admin/users', (value) => value, {
        method: 'POST',
        query: { limit: 1 },
      })
    ).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('uses the same PortalClient for body-only lookup and mandatory revision moderation', async () => {
    const { api, fetcher, portal } = await session();
    fetcher
      .mockResolvedValueOnce(
        json({ items: [{ ...user, email: 'target@example.test' }], total: 1, limit: 1, offset: 0 })
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await api.lookup('  TARGET@example.test ');
    const authority = grant();
    const sent = jest.fn();
    await api.updateStatus(
      id,
      { status: 'banned', reason: '  final reason  ', expected_revision: maximum },
      authority,
      undefined,
      sent
    );
    const [lookupURL, lookupOptions] = fetcher.mock.calls[0];
    expect(lookupURL).toBe(`${origin}/api/v1/admin/users/lookup`);
    expect(lookupOptions.method).toBe('POST');
    expect(JSON.parse(lookupOptions.body)).toEqual({ email: 'target@example.test' });
    const [statusURL, statusOptions] = fetcher.mock.calls[1];
    expect(statusURL).toBe(`${origin}/api/v1/admin/users/${id}/status`);
    expect(statusOptions.method).toBe('PATCH');
    expect(JSON.parse(statusOptions.body)).toEqual({
      status: 'banned',
      reason: 'final reason',
      expected_revision: maximum,
    });
    expect(new Headers(statusOptions.headers).get('X-Step-Up-Auth')).toBe('one-use-grant');
    expect(new Headers(statusOptions.headers).get('X-Portal-Session')).toBe(
      portal.profile?.session.id
    );
    expect(new Headers(statusOptions.headers).get('Content-Type')).toBe('application/json');
    expect(sent).toHaveBeenCalledTimes(1);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('rejects numeric/missing revisions and invalid bodies before consuming authority or sending', async () => {
    const { api, fetcher } = await session();
    const authority = grant();
    for (const update of [
      { status: 'suspended', reason: 'reason' },
      { status: 'suspended', reason: 'reason', expected_revision: null },
      { status: 'suspended', reason: 'reason', expected_revision: 1 },
      { status: 'suspended', reason: 'reason', expected_revision: '01' },
      { status: 'suspended', reason: 'reason', expected_revision: '9223372036854775808' },
      { status: 'pending_deletion', reason: 'reason', expected_revision: high },
      { status: 'banned', reason: '\u{1f642}'.repeat(501), expected_revision: high },
      { status: 'banned', reason: ' ', expected_revision: high },
      { status: 'banned', reason: 'reason', expected_revision: high, user_id: id },
    ])
      await expect(api.updateStatus(id, update as never, authority)).rejects.toBeInstanceOf(
        PortalError
      );
    await expect(api.user(`${id}?email=secret`)).rejects.toBeInstanceOf(PortalError);
    expect(fetcher).not.toHaveBeenCalled();
    expect(authority.take('session-id')).toBe('one-use-grant');
  });

  it('rejects mismatched identity, filters, page cursors, timestamps and count contracts', async () => {
    const { api, fetcher } = await session();
    fetcher.mockResolvedValueOnce(json({ ...user, id: '00000000-0000-4000-8000-000000000002' }));
    await expect(api.user(id)).rejects.toMatchObject({ code: 'invalid_response' });
    fetcher.mockResolvedValueOnce(json({ items: [user], total: 1, limit: 1, offset: 0 }));
    await expect(api.users({ status: 'banned', limit: 1 })).rejects.toMatchObject({
      code: 'invalid_response',
    });
    fetcher.mockResolvedValueOnce(json({ items: [], total: 0, limit: 2, offset: 1 }));
    await expect(api.users({ limit: 1 })).rejects.toMatchObject({ code: 'invalid_response' });
    for (const patch of [
      { seq: maximum },
      { timestamp: '2026-10-26T12:00:00Z' },
      { timestamp: null },
      { event_type: 'other.event' },
    ]) {
      const item = { ...row, ...patch };
      fetcher.mockResolvedValueOnce(
        json({ items: [item], limit: 1, has_more: false, next_before_seq: item.seq })
      );
      await expect(
        api.auditLogs({ ...auditQuery, before_seq: maximum, event_type: row.event_type })
      ).rejects.toMatchObject({ code: 'invalid_response' });
    }
  });

  it('preserves nanosecond audit filters on the wire and rejects a row just outside them', async () => {
    const { api, fetcher } = await session();
    const query = {
      start_time: '2026-10-27T00:00:00.000000001Z',
      end_time: '2026-10-27T00:00:00.000000002Z',
    };
    fetcher.mockResolvedValueOnce(
      json({
        items: [{ ...row, timestamp: query.end_time }],
        limit: 1,
        has_more: false,
        next_before_seq: high,
      })
    );
    expect((await api.auditLogs(query)).items).toHaveLength(1);
    expect(new URL(fetcher.mock.calls[0][0]).searchParams.get('start_time')).toBe(query.start_time);
    fetcher.mockResolvedValueOnce(
      json({
        items: [{ ...row, timestamp: '2026-10-27T00:00:00.000000003Z' }],
        limit: 1,
        has_more: false,
        next_before_seq: high,
      })
    );
    await expect(api.auditLogs(query)).rejects.toMatchObject({ code: 'invalid_response' });
  });
});

describe('nonce-only retry and bounded error feedback', () => {
  it('retries one exact nonce challenge with the full query unchanged and a new queryless htu proof', async () => {
    const { api, fetcher } = await session();
    fetcher
      .mockResolvedValueOnce(nonce())
      .mockResolvedValueOnce(json({ items: [user], total: 1, limit: 1, offset: 0 }));
    await api.users({ limit: 1 });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][0]).toBe(fetcher.mock.calls[1][0]);
    expect(fetcher.mock.calls[0][0]).toBe(`${origin}/api/v1/admin/users?limit=1`);
    const claims = fetcher.mock.calls.map(([, options]) =>
      JSON.parse(
        Buffer.from(
          (new Headers(options.headers).get('DPoP') ?? '').split('.')[1],
          'base64url'
        ).toString()
      )
    );
    expect(claims[0].jti).not.toBe(claims[1].jti);
    expect(claims[0].nonce).toBeUndefined();
    expect(claims[1].nonce).toBe('server-nonce');
    for (const claim of claims) expect(claim.htu).toBe(`${origin}/api/v1/admin/users`);
  });

  it('reuses only the same logical moderation body/grant after a pre-handler nonce and marks send once', async () => {
    const { api, fetcher } = await session();
    fetcher
      .mockResolvedValueOnce(nonce())
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const authority = grant();
    const sent = jest.fn();
    await api.updateStatus(
      id,
      { status: 'suspended', reason: 'reason', expected_revision: high },
      authority,
      undefined,
      sent
    );
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1].body).toBe(fetcher.mock.calls[1][1].body);
    for (const [, options] of fetcher.mock.calls)
      expect(new Headers(options.headers).get('X-Step-Up-Auth')).toBe('one-use-grant');
    expect(() => authority.take('session-id')).toThrow('grant_expired');
  });

  it('refuses repeated, spoofed, generic, incomplete and wrong-status nonce challenges', async () => {
    const { api, fetcher } = await session();
    fetcher.mockImplementation(async () => nonce());
    await expect(api.users()).rejects.toMatchObject({ code: 'use_dpop_nonce' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const response of [
      nonce('', 401),
      nonce('Basic realm="DPoP error=use_dpop_nonce"'),
      nonce('x-DPoP error="use_dpop_nonce"'),
      nonce('DPoP error="use_dpop_nonce", Basic realm="other"'),
      nonce('DPoP error="use_dpop_nonce"', 403),
      nonce('DPoP error="use_dpop_nonce"', 401, 'nonce,duplicate'),
      json({ error: 'invalid_credentials' }, 401, {
        'DPoP-Nonce': 'nonce',
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
      }),
    ]) {
      fetcher.mockReset().mockResolvedValueOnce(response);
      await expect(api.users()).rejects.toBeInstanceOf(PortalError);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });

  it.each([403, 409, 429, 503])('never replays moderation on HTTP %i', async (status) => {
    const { api, fetcher, portal } = await session();
    const lost = jest.fn();
    portal.onSessionLoss = lost;
    fetcher.mockResolvedValueOnce(
      json(
        {
          error:
            status === 403
              ? 'forbidden'
              : status === 409
                ? 'account_conflict'
                : status === 429
                  ? 'rate_limited'
                  : 'audit_unavailable',
        },
        status,
        { 'Retry-After': '9999' }
      )
    );
    const authority = grant();
    await expect(
      api.updateStatus(
        id,
        { status: 'suspended', reason: 'reason', expected_revision: high },
        authority
      )
    ).rejects.toMatchObject({ status, uncertain: status >= 500, retryAfterSeconds: 3600 });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(lost).not.toHaveBeenCalled();
    expect(portal.assertSession().id).toBe(id);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
    expect(isSessionLoss(new PortalError('forbidden', 403))).toBe(false);
  });

  it('bounds Retry-After delta/date feedback without retaining response prose or scheduling work', () => {
    const now = Date.parse('2026-10-28T09:00:00Z');
    expect(parseRetryAfter('60', now)).toBe(60);
    expect(parseRetryAfter('9999999999', now)).toBe(3600);
    expect(parseRetryAfter('0', now)).toBe(0);
    expect(parseRetryAfter('Wed, 28 Oct 2026 09:01:00 GMT', now)).toBe(60);
    expect(parseRetryAfter('Wed, 28 Oct 2026 08:00:00 GMT', now)).toBe(0);
    expect(parseRetryAfter('Thu, 29 Oct 2026 09:00:00 GMT', now)).toBe(3600);
    for (const value of [
      null,
      '',
      '-1',
      '+1',
      '1.5',
      '1e3',
      '60\n',
      '60, 60',
      '1\r\nX-Secret: data',
      'x'.repeat(81),
      '2026-10-28T09:01:00Z',
      'Wed, 31 Feb 2026 09:01:00 GMT',
    ])
      expect(parseRetryAfter(value, now)).toBeUndefined();
    expect(errorMessage(new PortalError('rate_limited', 429, false, 60))).toContain('60 seconds');
  });

  it('never replays lost moderation or authenticator responses and does not retain private network errors', async () => {
    const { api, fetcher, portal } = await session();
    fetcher.mockRejectedValue(new Error('private@example.test/request?reason=secret'));
    const pending = api.updateStatus(
      id,
      { status: 'banned', reason: 'private reason', expected_revision: high },
      grant()
    );
    await expect(pending).rejects.toMatchObject({
      code: 'network_error',
      uncertain: true,
      message: 'network_error',
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await expect(
      portal.stepUpVerify({ method: 'totp', code: '012345' }, new AbortController().signal)
    ).rejects.toMatchObject({ code: 'network_error', uncertain: true });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('preserves sanitized status and bounded Retry-After even for unreadable denial or gateway bodies', async () => {
    const { api, fetcher, portal } = await session();
    const lost = jest.fn();
    portal.onSessionLoss = lost;
    for (const status of [403, 429, 503]) {
      fetcher.mockResolvedValueOnce(
        new Response('private upstream diagnostic', { status, headers: { 'Retry-After': '60' } })
      );
      await expect(api.users()).rejects.toMatchObject({
        code: 'invalid_response',
        status,
        retryAfterSeconds: 60,
        message: 'invalid_response',
      });
    }
    fetcher.mockResolvedValueOnce(json({ error: 'forbidden\n' }, 403));
    await expect(api.users()).rejects.toMatchObject({ code: 'request_failed', status: 403 });
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(lost).not.toHaveBeenCalled();
  });

  it('distinguishes unsent cancellation from sent interruption using the existing on-send marker', async () => {
    const { api, fetcher } = await session();
    const before = new AbortController();
    before.abort();
    const unsent = jest.fn();
    await expect(
      api.updateStatus(
        id,
        { status: 'banned', reason: 'reason', expected_revision: high },
        grant(),
        before.signal,
        unsent
      )
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(unsent).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
    const after = new AbortController();
    fetcher.mockImplementation(async () => {
      after.abort();
      return new Response(null, { status: 204 });
    });
    const sent = jest.fn();
    const authority = grant();
    await expect(
      api.updateStatus(
        id,
        { status: 'banned', reason: 'reason', expected_revision: high },
        authority,
        after.signal,
        sent
      )
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(() => authority.take('session-id')).toThrow('grant_expired');
  });
});

describe('streamed and declared response budgets', () => {
  it('allows an actual typed audit page above 256 KiB, without widening any other route', async () => {
    const { api, portal, fetcher } = await session();
    const payload = 'x'.repeat(300 * 1024);
    fetcher.mockResolvedValueOnce(
      json({ items: [{ ...row, payload }], limit: 1, has_more: false, next_before_seq: high })
    );
    expect((await api.auditLogs(auditQuery)).items[0].payload).toBe(payload);
    for (const path of [
      '/api/v1/admin/users',
      '/api/v1/admin/capabilities',
      `/api/v1/admin/users/${id}`,
      '/api/v1/admin/audit-logs/verify',
      '/api/v1/admin/ledger/verify',
      '/api/v1/users/me',
    ]) {
      fetcher.mockResolvedValueOnce(rawJSON(256 * 1024 + 1));
      await expect(portal.request(path, (value) => value)).rejects.toMatchObject({
        code: 'invalid_response',
      });
    }
    fetcher.mockResolvedValueOnce(rawJSON(256 * 1024 + 1));
    await expect(
      portal.request('/api/v1/admin/audit-logs', (value) => value, { method: 'POST', body: {} })
    ).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
  });

  it('accepts exactly 256 KiB or 4 MiB only on the appropriate GET path', async () => {
    const { portal, fetcher } = await session();
    for (const [path, size] of [
      ['/api/v1/admin/capabilities', 256 * 1024],
      ['/api/v1/admin/audit-logs', 4 * 1024 * 1024],
    ] as const) {
      fetcher.mockResolvedValueOnce(rawJSON(size));
      const result = await portal.request(path, (value) => value as string);
      expect(result.length).toBe(size - 2);
    }
  });

  it.each(['/api/v1/admin/capabilities', '/api/v1/admin/audit-logs'])(
    'enforces declared and cumulative streamed budget for %s, even with lying Content-Length',
    async (path) => {
      const { portal, fetcher } = await session();
      const limit = path.endsWith('audit-logs') ? 4 * 1024 * 1024 : 256 * 1024;
      for (const declared of [
        String(limit + 1),
        '99999999999999999999999999',
        '-1',
        '1, 2',
        'NaN',
        '1.5',
      ]) {
        const cancel = jest.fn();
        const stream = new ReadableStream({ cancel });
        fetcher.mockResolvedValueOnce(
          new Response(stream, {
            headers: { 'Content-Type': 'application/json', 'Content-Length': declared },
          })
        );
        await expect(portal.request(path, (value) => value)).rejects.toMatchObject({
          code: 'invalid_response',
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
        await expect(portal.request(path, decode)).rejects.toMatchObject({
          code: 'invalid_response',
        });
        expect(cancel).toHaveBeenCalledTimes(1);
        expect(decode).not.toHaveBeenCalled();
      }
    }
  );

  it('normalizes malformed UTF-8/JSON, wrong media types and impossible 204 metadata as invalid responses', async () => {
    const { api, portal, fetcher } = await session();
    for (const response of [
      new Response(Uint8Array.of(0x22, 0xc3, 0x28, 0x22), {
        headers: { 'Content-Type': 'application/json' },
      }),
      new Response('{"incomplete":', { headers: { 'Content-Type': 'application/json' } }),
      new Response('{}{}', { headers: { 'Content-Type': 'application/json' } }),
      new Response('<html>untrusted</html>', { headers: { 'Content-Type': 'text/html' } }),
      new Response(null, { status: 204, headers: { 'Content-Length': '1' } }),
    ]) {
      fetcher.mockResolvedValueOnce(response);
      await expect(
        api.updateStatus(
          id,
          { status: 'banned', reason: 'reason', expected_revision: high },
          grant()
        )
      ).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
    }
    fetcher.mockResolvedValueOnce(
      new Response(Uint8Array.of(0xff), { headers: { 'Content-Type': 'application/json' } })
    );
    await expect(
      portal.request('/api/v1/admin/capabilities', (value) => value)
    ).rejects.toMatchObject({ code: 'invalid_response', uncertain: false });
  });

  it('accepts Chromium-style empty 204 streams but rejects any body bytes', async () => {
    for (const content of ['', 'unexpected']) {
      const response = new Response(new ReadableStream({
        start(controller) {
          if (content) controller.enqueue(new TextEncoder().encode(content));
          controller.close();
        },
      }), { headers: { 'Content-Length': '0' } });
      Object.defineProperty(response, 'status', { value: 204 });
      const result = readResponse(response, new AbortController().signal);
      if (content) await expect(result).rejects.toMatchObject({ code: 'invalid_response' });
      else await expect(result).resolves.toBeUndefined();
    }
  });

  it('cancels a stalled response reader when the request is interrupted', async () => {
    const cancel = jest.fn();
    const stream = new ReadableStream({ cancel });
    const controller = new AbortController();
    const pending = readResponse(
      new Response(stream, { headers: { 'Content-Type': 'application/json' } }),
      controller.signal
    );
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('decodes fragmented UTF-8 across tiny chunks without trusting partial data', async () => {
    const encoded = new TextEncoder().encode(JSON.stringify({ payload: '\u{1f642}' }));
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array());
        for (const byte of encoded) controller.enqueue(Uint8Array.of(byte));
        controller.close();
      },
    });
    await expect(
      readResponse(
        new Response(stream, { headers: { 'Content-Type': 'application/json' } }),
        new AbortController().signal
      )
    ).resolves.toEqual({ payload: '\u{1f642}' });
  });

  it('keeps invalid-response classification when rejecting a body whose cancellation fails', async () => {
    const cancel = jest.fn().mockRejectedValue(new Error('untrusted cancellation detail'));
    const stream = new ReadableStream({ cancel });
    await expect(
      readResponse(
        new Response(stream, { headers: { 'Content-Type': 'text/html' } }),
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: 'invalid_response', message: 'invalid_response' });
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('cancels already-aborted and redirected response bodies without disclosing their content', async () => {
    const cancelled = new AbortController();
    cancelled.abort();
    const abortCancel = jest.fn();
    await expect(
      readResponse(new Response(new ReadableStream({ cancel: abortCancel })), cancelled.signal)
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(abortCancel).toHaveBeenCalledTimes(1);
    const { api, fetcher } = await session();
    const redirectCancel = jest.fn();
    const redirected = new Response(new ReadableStream({ cancel: redirectCancel }));
    Object.defineProperty(redirected, 'redirected', { value: true });
    fetcher.mockResolvedValueOnce(redirected);
    await expect(api.users()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(redirectCancel).toHaveBeenCalledTimes(1);
  });
});
