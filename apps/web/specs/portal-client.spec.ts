/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { PortalClient } from '../app/_lib/portal/client';
import { type BrowserKey } from '../app/_lib/portal/dpop';
import { PortalError } from '../app/_lib/portal/errors';
import { StepUpGrant } from '../app/_lib/portal/contracts';

const origin = 'https://identity.example.test';
const profile = () => ({
  id: 'user-id',
  email: 'user@example.test',
  display_name: 'Saved name',
  status: 'active',
  lifecycle_revision: '9007199254740993',
  session: { id: 'session-id', expires_at: new Date(Date.now() + 3600000).toISOString() },
});
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const nonceResponse = () =>
  json({ error: 'use_dpop_nonce' }, 401, {
    'DPoP-Nonce': 'server-nonce',
    'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
  });
let key: BrowserKey;
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
beforeAll(async () => {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (!jwk.x || !jwk.y) throw new Error('Missing test public key');
  key = { privateKey: pair.privateKey, publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
});
afterAll(() => {
  if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto);
});

function client(fetcher: jest.Mock) {
  return new PortalClient({ origin, fetcher, getKey: async () => key });
}

describe('bounded same-origin portal transport', () => {
  it('uses cookies/no-store/no-referrer/error redirects and retries one explicit pre-handler nonce challenge with a fresh proof', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(nonceResponse())
      .mockResolvedValueOnce(json(profile()));
    const api = client(fetcher);
    const result = await api.bootstrap();
    expect(result.lifecycle_revision).toBe('9007199254740993');
    expect(fetcher).toHaveBeenCalledTimes(2);
    const first = fetcher.mock.calls[0][1] as RequestInit;
    const second = fetcher.mock.calls[1][1] as RequestInit;
    expect(first).toMatchObject({
      method: 'GET',
      credentials: 'same-origin',
      mode: 'cors',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    const firstClaims = JSON.parse(
      Buffer.from(
        (new Headers(first.headers).get('DPoP') ?? '').split('.')[1],
        'base64url'
      ).toString()
    );
    const secondClaims = JSON.parse(
      Buffer.from(
        (new Headers(second.headers).get('DPoP') ?? '').split('.')[1],
        'base64url'
      ).toString()
    );
    expect(firstClaims.nonce).toBeUndefined();
    expect(secondClaims.nonce).toBe('server-nonce');
    expect(firstClaims.jti).not.toBe(secondClaims.jti);
    expect(secondClaims.htu).toBe(`${origin}/api/v1/users/me`);
    expect(new Headers(first.headers).has('Authorization')).toBe(false);
  });

  it('stops at a second nonce challenge and never retries a generic 401 or a headerless challenge', async () => {
    const repeated = jest.fn().mockImplementation(async () => nonceResponse());
    await expect(client(repeated).bootstrap()).rejects.toMatchObject({ code: 'use_dpop_nonce' });
    expect(repeated).toHaveBeenCalledTimes(2);
    for (const response of [
      json({ error: 'invalid_credentials' }, 401),
      json({ error: 'use_dpop_nonce' }, 401, { 'DPoP-Nonce': 'nonce' }),
      json({ error: 'use_dpop_nonce' }, 400, {
        'DPoP-Nonce': 'nonce',
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
      }),
    ]) {
      const fetcher = jest.fn().mockResolvedValue(response);
      await expect(client(fetcher).bootstrap()).rejects.toBeInstanceOf(PortalError);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });

  it('rejects arbitrary origins, query strings, fragments and path normalization before fetching', async () => {
    const fetcher = jest.fn();
    const api = client(fetcher);
    for (const path of [
      'https://evil.test/api/v1/me',
      '//evil.test/api/v1/me',
      '/api/v1/../users',
      '/api/v1/users?token=secret',
      '/api/v1/users#secret',
      '/api/v1/%2e/users',
    ])
      await expect(api.request(path, (v) => v, { anonymous: true })).rejects.toBeInstanceOf(
        PortalError
      );
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('bounds streaming responses and cancels oversized bodies even without Content-Length', async () => {
    const cancel = jest.fn();
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(256 * 1024 + 1));
      },
      cancel,
    });
    const fetcher = jest
      .fn()
      .mockResolvedValue(new Response(body, { headers: { 'Content-Type': 'application/json' } }));
    await expect(client(fetcher).bootstrap()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(cancel).toHaveBeenCalledTimes(1);
    const huge = jest.fn().mockResolvedValue(json({}, 200, { 'Content-Length': '9999999' }));
    await expect(client(huge).bootstrap()).rejects.toMatchObject({ code: 'invalid_response' });
    const html = jest
      .fn()
      .mockResolvedValue(
        new Response('<script>untrusted</script>', { headers: { 'Content-Type': 'text/html' } })
      );
    await expect(client(html).bootstrap()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('rejects over-limit request bodies and absent browser keys without contacting the service', async () => {
    const fetcher = jest.fn();
    await expect(
      client(fetcher).request('/api/v1/auth/webauthn/login/verify', (v) => v, {
        anonymous: true,
        method: 'POST',
        body: { data: 'x'.repeat(65536) },
      })
    ).rejects.toMatchObject({ code: 'invalid_request' });
    const missing = new PortalClient({
      origin,
      fetcher,
      getKey: async () => {
        throw new PortalError('key_unavailable');
      },
    });
    await expect(missing.bootstrap()).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('aborts late replies without a nonce retry or session bootstrap', async () => {
    let finish!: (response: Response) => void;
    const fetcher = jest.fn(
      () =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        })
    );
    const api = client(fetcher);
    const controller = new AbortController();
    const pending = api.bootstrap(controller.signal);
    // Let the real asynchronous signature complete before aborting the fetch.
    while (!finish) await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    finish(nonceResponse());
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.profile).toBeUndefined();
  });
});

describe('bound session intent and one-use mutations', () => {
  it('reports initial transmission once per logical request, not while preparing a proof or on its nonce retry', async () => {
    const sent = jest.fn();
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(nonceResponse())
      .mockResolvedValueOnce(json({ done: true }));
    await client(fetcher).request('/api/v1/auth/webauthn/login/verify', (value) => value, {
      anonymous: true,
      method: 'POST',
      body: {},
      onSend: sent,
    });
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const missing = new PortalClient({
      origin,
      fetcher,
      getKey: async () => {
        throw new PortalError('key_unavailable');
      },
    });
    sent.mockClear();
    await expect(
      missing.request('/api/v1/auth/webauthn/login/verify', (value) => value, {
        anonymous: true,
        method: 'POST',
        body: {},
        onSend: sent,
      })
    ).rejects.toMatchObject({ code: 'key_unavailable' });
    expect(sent).not.toHaveBeenCalled();
  });
  it('pins session intent on reads/mutations, consumes a grant once and sends the same logical body only for a nonce retry', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(nonceResponse())
      .mockResolvedValueOnce(json({ remaining: 3, low: true }));
    const api = client(fetcher);
    await api.bootstrap();
    const grant = new StepUpGrant(
      { token: 'opaque-grant', token_type: 'StepUp', expires_in: 60 },
      'session-id',
      Date.now(),
      Date.now() + 60000
    );
    await api.request('/api/v1/auth/recovery-codes/generate', (v) => v, {
      method: 'POST',
      body: {},
      grant,
    });
    for (const call of fetcher.mock.calls.slice(1)) {
      const headers = new Headers(call[1].headers);
      expect(headers.get('X-Portal-Session')).toBe('session-id');
      expect(headers.get('X-Step-Up-Auth')).toBe('opaque-grant');
      expect(call[1].body).toBe('{}');
    }
    await expect(
      api.request('/api/v1/auth/recovery-codes/generate', (v) => v, {
        method: 'POST',
        body: {},
        grant,
      })
    ).rejects.toMatchObject({ code: 'grant_expired' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it('never replays uncertain mutations, authenticator responses or consumed grants after transport failure', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(profile()))
      .mockRejectedValueOnce(new TypeError('private transport detail'));
    const api = client(fetcher);
    await api.bootstrap();
    await expect(api.saveProfile('Draft', '9007199254740993')).rejects.toMatchObject({
      uncertain: true,
      code: 'network_error',
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    const login = jest.fn().mockRejectedValue(new TypeError('transport'));
    await expect(
      client(login).loginVerify({ response: 'authenticator-secret' }, new AbortController().signal)
    ).rejects.toMatchObject({ uncertain: true });
    expect(login).toHaveBeenCalledTimes(1);
  });

  it('treats malformed upstream success and gateway failure bodies as uncertain mutation results', async () => {
    for (const status of [200, 502]) {
      const fetcher = jest
        .fn()
        .mockResolvedValueOnce(json(profile()))
        .mockResolvedValueOnce(new Response('upstream response lost', { status }));
      const api = client(fetcher);
      await api.bootstrap();
      await expect(api.saveProfile('Draft', '9007199254740993')).rejects.toMatchObject({
        uncertain: true,
      });
      expect(fetcher).toHaveBeenCalledTimes(2);
    }
  });

  it('bounds stalled fetches by a deadline without replaying an uncertain mutation', async () => {
    jest.useFakeTimers();
    const sign = jest.spyOn(crypto.subtle, 'sign').mockResolvedValue(new Uint8Array(64).buffer);
    const fetcher = jest.fn(
      (_url, options: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          options.signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Timed out', 'AbortError')),
            { once: true }
          );
        })
    );
    try {
      const api = client(fetcher);
      const pending = api.loginVerify(
        { response: 'one-use-assertion' },
        new AbortController().signal
      );
      const rejected = expect(pending).rejects.toMatchObject({
        code: 'network_error',
        uncertain: true,
      });
      for (let index = 0; index < 6; index++) await Promise.resolve();
      expect(fetcher).toHaveBeenCalledTimes(1);
      jest.advanceTimersByTime(20001);
      await rejected;
      expect(fetcher).toHaveBeenCalledTimes(1);
    } finally {
      sign.mockRestore();
      jest.useRealTimers();
    }
  });

  it('reports cookie/session loss separately from incorrect TOTP and clears disposed clients', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(json({ error: 'invalid_credentials' }, 401))
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    const lost = jest.fn();
    api.onSessionLoss = lost;
    await api.bootstrap();
    await expect(
      api.stepUpVerify({ method: 'totp', code: '012345' }, new AbortController().signal)
    ).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(lost).not.toHaveBeenCalled();
    await expect(api.bootstrap()).rejects.toMatchObject({ code: 'session_required' });
    expect(lost).toHaveBeenCalledTimes(1);
    api.dispose();
    expect(api.profile).toBeUndefined();
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it('detects a changed bootstrap identity and never adopts it into a stale client', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(
        json({
          ...profile(),
          id: 'different-user',
          session: { ...profile().session, id: 'other-session' },
        })
      );
    const api = client(fetcher);
    await api.bootstrap();
    const lost = jest.fn();
    api.onSessionLoss = lost;
    await expect(api.bootstrap()).rejects.toMatchObject({ code: 'session_changed' });
    expect(api.profile?.id).toBe('user-id');
    expect(lost).toHaveBeenCalledTimes(1);
  });
});
