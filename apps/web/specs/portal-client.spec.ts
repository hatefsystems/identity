/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { PortalClient } from '../app/_lib/portal/client';
import { type BrowserKey } from '../app/_lib/portal/dpop';
import { PortalError } from '../app/_lib/portal/errors';
import { passkeyResponse, StepUpGrant } from '../app/_lib/portal/contracts';
import { emptyResponse } from '../app/_lib/portal/json-response';

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
const credential = {
  id: 'key-id', name: 'Device', created_at: '2026-01-01T00:00:00Z',
  user_verified: true, backup_eligible: false, backup_state: false,
};
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

function controlledResponse(status = 201, headers: Record<string, string> = {}) {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let started!: () => void;
  const reading = new Promise<void>((resolve) => { started = resolve; });
  const cancel = jest.fn();
  const body = new ReadableStream<Uint8Array>({
    start(value) { controller = value; },
    cancel,
  });
  const getReader = body.getReader.bind(body);
  jest.spyOn(body, 'getReader').mockImplementation(() => {
    started();
    return getReader();
  });
  const response = new Response(body, {
    status: status === 204 ? 200 : status,
    headers: { 'Content-Type': 'application/json', 'X-Identity-Auth-Invalidated': 'true', ...headers },
  });
  // Chromium can expose a zero-byte stream for 204; native Node disallows it.
  if (status === 204) Object.defineProperty(response, 'status', { value: 204 });
  return {
    response, reading, cancel,
    finish(value?: unknown) {
      if (value !== undefined) controller.enqueue(new TextEncoder().encode(JSON.stringify(value)));
      controller.close();
    },
    fail() { controller.error(new TypeError('Interrupted response')); },
  };
}

it('strictly decodes passkey MFA without establishing a session or exposing profile authority', async () => {
  const result = { status: 'mfa_required', preauthentication: 'private-preauth', expires_at: new Date(Date.now() + 300000).toISOString() };
  const fetcher = jest.fn().mockResolvedValue(json(result));
  const api = client(fetcher);
  expect(await api.loginVerify({ response: 'assertion' }, new AbortController().signal)).toEqual(result);
  expect(api.profile).toBeUndefined();
  expect(fetcher).toHaveBeenCalledTimes(1);
  api.dispose();
});

it.each([
  { status: 'mfa_required', preauthentication: 'private-preauth' },
  { status: 'session' },
  { status: 'mfa_required', preauthentication: 'private-preauth', expires_at: 'invalid' },
  { status: 'mfa_required', preauthentication: 'private-preauth', expires_at: new Date(Date.now() + 300000).toISOString(), session: 'forbidden' },
])('rejects malformed passkey MFA success as an uncertain mutation without replay', async (result) => {
  const fetcher = jest.fn().mockResolvedValue(json(result));
  const api = client(fetcher);
  await expect(api.loginVerify({ response: 'assertion' }, new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(api.profile).toBeUndefined();
  api.dispose();
});

it.each([null, 'user@example.test', '\u0647\u0627\u062a\u0641@example.test'])(
  'preserves typed email %p through bootstrap and display-name saves without fetching private data',
  async (email) => {
    const initial = { ...profile(), email };
    const saved = { ...initial, display_name: 'Updated', lifecycle_revision: '9007199254740994' };
    const fetcher = jest.fn().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(json(saved));
    const api = client(fetcher);
    expect((await api.bootstrap()).email).toBe(email);
    expect(api.assertSession().email).toBe(email);
    expect((await api.saveProfile('Updated', initial.lifecycle_revision)).email).toBe(email);
    expect(api.profile?.email).toBe(email);
    expect(fetcher.mock.calls.map(([url, init]) => [url, init.method])).toEqual([
      [`${origin}/api/v1/users/me`, 'GET'],
      [`${origin}/api/v1/users/me`, 'PATCH'],
    ]);
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({
      display_name: 'Updated', expected_revision: initial.lifecycle_revision,
    });
    api.dispose();
  }
);

it.each([undefined, '', 7, {}, []])(
  'rejects missing, empty or malformed email %p instead of inventing absence',
  async (email) => {
    const fetcher = jest.fn().mockResolvedValue(json({ ...profile(), email }));
    const api = client(fetcher);
    await expect(api.bootstrap()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(api.profile).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(1);
    api.dispose();
  }
);

it.each([null, { display: '\u0639\u0644\u064a.\u0645\u0624\u0645\u0646\u064a' }])('reads truthful username state through the existing authenticated GET transport', async (username) => {
  const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json({ username }));
  const api = client(fetcher), signal = new AbortController().signal;
  await api.bootstrap(signal);
  expect(await api.username(signal)).toEqual(username);
  const [url, init] = fetcher.mock.calls[1];
  expect(url).toBe(`${origin}/api/v1/users/me/username`);
  expect(init).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer' });
  expect(init.body).toBeUndefined();
  expect(new Headers(init.headers).get('X-Portal-Session')).toBe('session-id');
  expect(new Headers(init.headers).has('DPoP')).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(2);
  api.dispose();
});

it.each([
  {}, { username: undefined }, { username: { display: '' } }, { username: { display: 4 } },
  { username: { display: 'a'.repeat(1025) } }, { username: { display: 'name', key: 'private' } },
  { username: null, owner: 'private' },
])('rejects malformed username read envelopes without inventing absence', async (response) => {
  const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json(response));
  const api = client(fetcher);
  await api.bootstrap();
  await expect(api.username(new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
  expect(fetcher).toHaveBeenCalledTimes(2);
});

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
  it.each([
    ['/api/v1/auth/webauthn/register/verify', 'POST', 'passkeyAdded', credential, 201],
    ['/api/v1/auth/webauthn/keys/key-id', 'DELETE', 'passkeyRemoved', undefined, 204],
    ['/api/v1/auth/mfa/verify', 'POST', 'totpEnabled', { status: 'enabled' }, 200],
    ['/api/v1/auth/mfa', 'DELETE', 'totpDisabled', undefined, 204],
    ['/api/v1/users/me/phone/verify', 'POST', 'phoneVerified', { status: 'verified' }, 200],
    ['/api/v1/users/me/phone', 'DELETE', 'phoneRemoved', undefined, 204],
  ] as const)('lets a strictly decoded %s success win after concurrent GET401 without retaining other authority', async (path, method, outcome, value, status) => {
    const mutation = controlledResponse(status);
    const unrelated = controlledResponse(200);
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(mutation.response).mockResolvedValueOnce(unrelated.response)
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    const ui = new AbortController();
    api.onSessionLoss = jest.fn((_error, settling) => { if (settling) ui.abort(); });
    api.onSecurityChange = jest.fn();
    const decode = path.endsWith('register/verify') ? passkeyResponse
      : status === 204 ? emptyResponse : (body: unknown) => body;
    const pending = api.request(path, decode, { method, signal: ui.signal, body: method === 'POST' ? {} : undefined });
    await mutation.reading;
    const read = api.sessions(new AbortController().signal);
    const rejectedRead = expect(read).rejects.toMatchObject({ name: 'AbortError' });
    await unrelated.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    await rejectedRead;
    expect(api.onSessionLoss).toHaveBeenCalledWith(expect.objectContaining({ code: 'session_required' }), true);
    expect(api.profile).toBeUndefined();
    expect(() => api.assertSession()).toThrow('The operation was cancelled');
    expect(ui.signal.aborted).toBe(true);
    expect(fetcher.mock.calls[1][1].signal.aborted).toBe(false);
    expect(fetcher.mock.calls[2][1].signal.aborted).toBe(true);
    expect(unrelated.cancel).toHaveBeenCalledTimes(1);
    expect(mutation.cancel).not.toHaveBeenCalled();
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    await expect(api.saveProfile('Draft', '1')).rejects.toMatchObject({ name: 'AbortError' });
    await expect(api.registerVerify({}, new AbortController().signal)).rejects.toMatchObject({ name: 'AbortError' });
    expect(api.profile).toBeUndefined();
    mutation.finish(value);
    expect(await pending).toEqual(value);
    expect(api.onSecurityChange).toHaveBeenCalledTimes(1);
    expect(api.onSecurityChange).toHaveBeenCalledWith(outcome);
    expect(api.onSessionLoss).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(api.profile).toBeUndefined();
  });

  it.each([
    ['malformed success', 201, {}, 'invalid_response'],
    ['policy refusal', 409, { error: 'last_credential' }, 'last_credential'],
    ['dependency error', 503, { error: 'temporarily_unavailable' }, 'temporarily_unavailable'],
    ['interrupted stream', 201, undefined, 'network_error'],
  ] as const)('settles concurrent session loss without claiming success for %s', async (_case, status, value, code) => {
    const mutation = controlledResponse(status);
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSessionLoss = jest.fn();
    api.onSecurityChange = jest.fn();
    const pending = api.registerVerify({}, new AbortController().signal);
    const rejected = expect(pending).rejects.toMatchObject({ code });
    await mutation.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    if (value === undefined) mutation.fail();
    else mutation.finish(value);
    await rejected;
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.onSessionLoss).toHaveBeenCalledTimes(2);
    expect(api.onSessionLoss).toHaveBeenLastCalledWith(expect.objectContaining({ code: 'session_required' }));
    expect(api.profile).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it('never retries a nonce challenge after concurrent loss withdrew authority', async () => {
    const mutation = controlledResponse(401, {
      'DPoP-Nonce': 'server-nonce', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
    });
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    const pending = api.registerVerify({}, new AbortController().signal);
    const rejected = expect(pending).rejects.toMatchObject({ uncertain: true });
    await mutation.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    mutation.finish({ error: 'use_dpop_nonce' });
    await rejected;
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(api.profile).toBeUndefined();
  });

  it('does not restore authority or claim invalidation from an unmarked successful no-op after concurrent loss', async () => {
    const mutation = controlledResponse(204, { 'X-Identity-Auth-Invalidated': 'false' });
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSecurityChange = jest.fn();
    api.onSessionLoss = jest.fn();
    const pending = api.request('/api/v1/users/me/phone', emptyResponse, { method: 'DELETE' });
    await mutation.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    mutation.finish();
    await pending;
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.onSessionLoss).toHaveBeenCalledTimes(2);
    expect(api.profile).toBeUndefined();
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it('does not preserve an unrelated already-sent mutation alongside the security response', async () => {
    const mutation = controlledResponse();
    const unrelated = controlledResponse(200);
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
      .mockResolvedValueOnce(unrelated.response).mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    const pending = api.registerVerify({}, new AbortController().signal);
    await mutation.reading;
    const save = api.saveProfile('Draft', '1');
    const rejected = expect(save).rejects.toMatchObject({ name: 'AbortError' });
    await unrelated.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    await rejected;
    expect(unrelated.cancel).toHaveBeenCalledTimes(1);
    expect(mutation.cancel).not.toHaveBeenCalled();
    mutation.finish(credential);
    await pending;
    expect(api.profile).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(4);
  });

  it('does not preserve a security operation that has not yet transmitted', async () => {
    let release!: (value: BrowserKey) => void;
    const waiting = new Promise<BrowserKey>((resolve) => { release = resolve; });
    const getKey = jest.fn().mockResolvedValueOnce(key).mockReturnValueOnce(waiting).mockResolvedValue(key);
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = new PortalClient({ origin, fetcher, getKey });
    await api.bootstrap();
    api.onSessionLoss = jest.fn(() => api.dispose());
    api.onSecurityChange = jest.fn();
    const pending = api.registerVerify({}, new AbortController().signal);
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    release(key);
    await rejected;
    expect(api.onSessionLoss).toHaveBeenCalledWith(expect.objectContaining({ code: 'session_required' }), false);
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.profile).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('keeps the original twenty-second response deadline after concurrent loss', async () => {
    jest.useFakeTimers();
    const sign = jest.spyOn(crypto.subtle, 'sign').mockResolvedValue(new Uint8Array(64).buffer);
    try {
      const mutation = controlledResponse();
      const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
        .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
      const api = client(fetcher);
      await api.bootstrap();
      api.onSessionLoss = jest.fn();
      api.onSecurityChange = jest.fn();
      const pending = api.registerVerify({}, new AbortController().signal);
      const rejected = expect(pending).rejects.toMatchObject({ code: 'network_error', uncertain: true });
      await mutation.reading;
      jest.advanceTimersByTime(12000);
      await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
      jest.advanceTimersByTime(7999);
      expect(api.onSessionLoss).toHaveBeenCalledTimes(1);
      expect(mutation.cancel).not.toHaveBeenCalled();
      jest.advanceTimersByTime(1);
      await rejected;
      expect(api.onSessionLoss).toHaveBeenCalledTimes(2);
      expect(api.onSecurityChange).not.toHaveBeenCalled();
      expect(mutation.cancel).toHaveBeenCalledTimes(1);
      expect(fetcher).toHaveBeenCalledTimes(3);
    } finally {
      sign.mockRestore();
      jest.useRealTimers();
    }
  });

  it('still aborts a preserved security reader on explicit disposal', async () => {
    const mutation = controlledResponse();
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(mutation.response)
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSecurityChange = jest.fn();
    const pending = api.registerVerify({}, new AbortController().signal);
    const rejected = expect(pending).rejects.toMatchObject({ uncertain: true });
    await mutation.reading;
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'session_required' });
    api.dispose();
    await rejected;
    expect(mutation.cancel).toHaveBeenCalledTimes(1);
    expect(api.onSecurityChange).not.toHaveBeenCalled();
  });

  it.each([
    ['/api/v1/auth/webauthn/register/verify', 'POST', 'passkeyAdded', credential, 201],
    ['/api/v1/auth/webauthn/keys/key-id', 'DELETE', 'passkeyRemoved', undefined, 204],
    ['/api/v1/auth/mfa/verify', 'POST', 'totpEnabled', { status: 'enabled' }, 200],
    ['/api/v1/auth/mfa', 'DELETE', 'totpDisabled', undefined, 204],
    ['/api/v1/users/me/phone/verify', 'POST', 'phoneVerified', { status: 'verified' }, 200],
    ['/api/v1/users/me/phone', 'DELETE', 'phoneRemoved', undefined, 204],
  ] as const)('preserves the decoded committed %s result before clearing initiating authority', async (path, method, outcome, body, status) => {
    const response = status === 204
      ? new Response(null, { status, headers: { 'X-Identity-Auth-Invalidated': 'true' } })
      : json(body, status, { 'X-Identity-Auth-Invalidated': 'true' });
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(response);
    const api = client(fetcher);
    await api.bootstrap();
    const changed = jest.fn();
    const lost = jest.fn();
    api.onSecurityChange = changed;
    api.onSessionLoss = lost;
    const decode = path.endsWith('register/verify') ? passkeyResponse
      : status === 204 ? emptyResponse : (value: unknown) => value;
    const result = await api.request(path, decode, { method, body: method === 'POST' ? {} : undefined });
    expect(result).toEqual(body);
    expect(changed).toHaveBeenCalledTimes(1);
    expect(changed).toHaveBeenCalledWith(outcome);
    expect(api.profile).toBeUndefined();
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(lost).not.toHaveBeenCalled();
  });

  it.each(['/api/v1/users/me/phone', '/api/v1/auth/mfa'])('retains authority after an unmarked successful no-op at %s', async (path) => {
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSecurityChange = jest.fn();
    await api.request(path, emptyResponse, { method: 'DELETE' });
    expect(api.assertSession().session.id).toBe('session-id');
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    api.dispose();
  });

  it('keeps rename responses unchanged and does not invalidate normal authority', async () => {
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json(credential));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSecurityChange = jest.fn();
    expect(await api.request('/api/v1/auth/webauthn/keys/key-id', passkeyResponse, { method: 'PATCH' })).toEqual(credential);
    expect(api.assertSession().session.id).toBe('session-id');
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    api.dispose();
  });

  it('does not call a malformed mutation response committed even with an invalidation header', async () => {
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(json({}, 201, { 'X-Identity-Auth-Invalidated': 'true' }));
    const api = client(fetcher);
    await api.bootstrap();
    api.onSecurityChange = jest.fn();
    await expect(api.registerVerify({}, new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(2);
    api.dispose();
  });

  it('preserves restricted recovery enrollment as one next-login outcome without normal-session callbacks', async () => {
    const fetcher = jest.fn().mockResolvedValue(json({ next: 'login' }, 200, { 'X-Identity-Auth-Invalidated': 'true' }));
    const api = client(fetcher);
    api.onSecurityChange = jest.fn();
    api.onSessionLoss = jest.fn();
    expect(await api.request('/api/v1/auth/enrollment/webauthn/register/verify', (value) => value, {
      method: 'POST', body: {}, anonymous: true,
    })).toEqual({ next: 'login' });
    expect(api.profile).toBeUndefined();
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.onSessionLoss).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(new Headers(fetcher.mock.calls[0][1].headers).has('X-Portal-Session')).toBe(false);
    api.dispose();
  });

  it.each([true, false])('strictly decodes a required %p removal hint from each listed passkey', async (can_remove) => {
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json([{ ...credential, can_remove }]));
    const api = client(fetcher);
    await api.bootstrap();
    expect(await api.keys(new AbortController().signal)).toEqual([{ ...credential, can_remove }]);
    api.dispose();
  });

  it.each([undefined, null, 'true', 1, {}])('rejects malformed or missing list removal hint %p without fabricating availability', async (can_remove) => {
    const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json([{ ...credential, can_remove }]));
    const api = client(fetcher);
    await api.bootstrap();
    await expect(api.keys(new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    api.dispose();
  });

  it('sends deletion with the current session and single-use grant, retrying only the pre-handler nonce once', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json({ ...profile(), deletion_enabled: true }))
      .mockResolvedValueOnce(nonceResponse())
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const api = client(fetcher);
    await api.bootstrap();
    const grant = new StepUpGrant(
      { token: 'deletion-grant', token_type: 'StepUp', expires_in: 60 },
      'session-id',
      Date.now(),
      Date.now() + 60000
    );
    const sent = jest.fn();
    await api.deleteAccount(grant, new AbortController().signal, sent);
    expect(sent).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(3);
    for (const [url, options] of fetcher.mock.calls.slice(1)) {
      expect(url).toBe(`${origin}/api/v1/users/me`);
      expect(options).toMatchObject({
        method: 'DELETE',
        credentials: 'same-origin',
        redirect: 'error',
      });
      expect(options.body).toBeUndefined();
      const headers = new Headers(options.headers);
      expect(headers.get('X-Portal-Session')).toBe('session-id');
      expect(headers.get('X-Step-Up-Auth')).toBe('deletion-grant');
      expect(headers.has('DPoP')).toBe(true);
    }
    expect(() => grant.take('session-id')).toThrow('grant_expired');
  });

  it.each([403, 503])('never replays a deletion after a %i response', async (status) => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(json(profile()))
      .mockResolvedValueOnce(json({ error: 'insufficient_user_authentication' }, status));
    const api = client(fetcher);
    await api.bootstrap();
    const grant = new StepUpGrant(
      { token: 'deletion-grant', token_type: 'StepUp', expires_in: 60 },
      'session-id',
      Date.now(),
      Date.now() + 60000
    );
    await expect(api.deleteAccount(grant, new AbortController().signal)).rejects.toMatchObject({
      status,
      uncertain: status >= 500,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(() => grant.take('session-id')).toThrow('grant_expired');
  });

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

describe('notification presentation header boundary', () => {
  it.each(['en', 'fa-IR'] as const)(
    'freezes %s on deletion and its one permitted nonce retry',
    async (locale) => {
      const fetcher = jest
        .fn()
        .mockResolvedValueOnce(json({ ...profile(), deletion_enabled: true }))
        .mockResolvedValueOnce(nonceResponse())
        .mockResolvedValueOnce(new Response(null, { status: 204 }));
      const api = client(fetcher);
      await api.bootstrap();
      const grant = new StepUpGrant(
        { token: 'presentation-grant', token_type: 'StepUp', expires_in: 60 },
        'session-id',
        Date.now(),
        Date.now() + 60000
      );
      await api.deleteAccount(grant, new AbortController().signal, undefined, locale);
      expect(new Headers(fetcher.mock.calls[0][1].headers).has('X-Hatef-Notification-Locale')).toBe(
        false
      );
      for (const [, options] of fetcher.mock.calls.slice(1)) {
        expect(new Headers(options.headers).get('X-Hatef-Notification-Locale')).toBe(locale);
        expect(options.body).toBeUndefined();
        expect(new Headers(options.headers).get('X-Step-Up-Auth')).toBe('presentation-grant');
      }
      expect(fetcher).toHaveBeenCalledTimes(3);
    }
  );

  it.each([
    ['/api/v1/users/me', 'GET', 'fa-IR'],
    ['/api/v1/auth/logout', 'POST', 'fa-IR'],
    ['/api/v1/users/me', 'DELETE', 'fa'],
    ['/api/v1/users/me', 'DELETE', 'fa-IR\r\nInjected: value'],
  ])(
    'rejects a locale outside its exact route/method/allowlist before network access',
    async (path, method, locale) => {
      const fetcher = jest.fn();
      const api = client(fetcher);
      // Exercise the runtime boundary against untyped JavaScript callers too.
      await expect(
        api.request(path, () => undefined, {
          method: method as 'GET' | 'POST' | 'DELETE',
          notificationLocale: locale as 'fa-IR',
        })
      ).rejects.toMatchObject({ code: 'invalid_request' });
      expect(fetcher).not.toHaveBeenCalled();
    }
  );
});

it('snapshots the validated presentation locale before asynchronous proof generation', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(json(profile()))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const api = client(fetcher);
  await api.bootstrap();
  const options = { method: 'DELETE' as const, notificationLocale: 'fa-IR' as 'en' | 'fa-IR' };
  const work = api.request('/api/v1/users/me', () => undefined, options);
  options.notificationLocale = 'en';
  await work;
  expect(new Headers(fetcher.mock.calls[1][1].headers).get('X-Hatef-Notification-Locale')).toBe(
    'fa-IR'
  );
});
