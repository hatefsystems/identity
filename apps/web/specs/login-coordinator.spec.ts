/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { PortalClient } from '../app/_lib/portal/client';
import type { BrowserKey } from '../app/_lib/portal/dpop';
import { LoginCoordinator } from '../app/_lib/portal/login-coordinator';

const origin = 'https://identity.example.test';
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const codeResponse = () => ({ status: 'code_requested', challenge: 'private-challenge', expires_at: new Date(Date.now() + 180000).toISOString() });
const mfaResponse = () => ({ status: 'mfa_required', preauthentication: 'private-preauthentication', expires_at: new Date(Date.now() + 300000).toISOString() });
let key: BrowserKey;
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
beforeAll(async () => {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (!jwk.x || !jwk.y) throw new Error('Missing test public key');
  key = { privateKey: pair.privateKey, publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
});
afterAll(() => { if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto); });
afterEach(() => jest.restoreAllMocks());
function coordinator(fetcher: jest.Mock) {
  return new LoginCoordinator(new PortalClient({ origin, fetcher, getKey: async () => key }));
}

it.each(['email', 'sms'] as const)('sends username/channel only, keeps opaque %s handles out of state, and completes contact+MFA with exact ASCII codes', async (channel) => {
  const fetched = jest.fn().mockResolvedValueOnce(json(codeResponse(), 202)).mockResolvedValueOnce(json(mfaResponse())).mockResolvedValueOnce(new Response(null, { status: 204 }));
  const flow = coordinator(fetched);
  await flow.requestCode('هاتف۱۲', channel);
  expect(flow.state).toMatchObject({ stage: 'delivered', channel });
  expect(JSON.stringify(flow.state)).not.toContain('private-challenge');
  await flow.verifyCode('012345');
  expect(flow.state.stage).toBe('mfa');
  expect(JSON.stringify(flow.state)).not.toContain('private-preauthentication');
  await flow.verifyTotp('023456');
  expect(flow.state).toEqual({ stage: 'session' });
  expect(fetched.mock.calls.map(([url, init]) => [url, JSON.parse(init.body)])).toEqual([
    [`${origin}/api/v1/auth/login/code/request`, { username: 'هاتف۱۲', channel }],
    [`${origin}/api/v1/auth/login/code/verify`, { challenge: 'private-challenge', code: '012345' }],
    [`${origin}/api/v1/auth/login/mfa`, { preauthentication: 'private-preauthentication', code: '023456' }],
  ]);
  for (const [url, init] of fetched.mock.calls) {
    expect(new URL(url).search + new URL(url).hash).toBe('');
    expect(init).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' });
    const headers = new Headers(init.headers);
    expect(headers.has('DPoP')).toBe(true);
    expect(headers.has('X-Portal-Session')).toBe(false);
    expect(headers.has('Authorization')).toBe(false);
    expect(headers.has('X-Hatef-Notification-Locale')).toBe(false);
  }
  flow.dispose();
});

it('preserves exact password/username bytes and accepts only a strict empty 204 or MFA envelope', async () => {
  const fetcher = jest.fn().mockResolvedValue(new Response(null, { status: 204 }));
  const flow = coordinator(fetcher);
  await flow.password('هاتف۱۲', '  گذرواژه۱۲۳\u200c\u202e  ');
  expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ username: 'هاتف۱۲', password: '  گذرواژه۱۲۳\u200c\u202e  ' });
  expect(flow.state.stage).toBe('session');
  flow.dispose();
});

it.each([
  { value: { status: 'mfa_required', expires_at: new Date(Date.now() + 300000).toISOString() }, status: 200 },
  { value: { ...mfaResponse(), session: 'forbidden' }, status: 200 },
  { value: { ...mfaResponse(), preauthentication: 'private secret' }, status: 200 },
  { value: { ...mfaResponse(), expires_at: new Date(Date.now() + 600000).toISOString() }, status: 200 },
  { value: mfaResponse(), status: 202 },
  { value: {}, status: 200 },
])('rejects malformed or widened session/MFA success without replay: $status', async ({ value, status }) => {
  const fetcher = jest.fn().mockResolvedValue(json(value, status));
  const flow = coordinator(fetcher);
  await expect(flow.password('username', 'exact password')).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
  expect(flow.state.stage).toBe('unconfirmed');
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});

it.each([{}, { ...codeResponse(), destination: 'private@example.test' }, { ...codeResponse(), expires_at: 'not-iso' }])('rejects contact response details instead of disclosing a destination', async (value) => {
  const fetcher = jest.fn().mockResolvedValue(json(value, 202));
  const flow = coordinator(fetcher);
  await expect(flow.requestCode('username', 'email')).rejects.toMatchObject({ code: 'invalid_response' });
  expect(flow.state.stage).toBe('unconfirmed');
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});

it('retries only one explicit pre-handler nonce challenge with a new proof and identical exact mutation body', async () => {
  const fetcher = jest.fn().mockResolvedValueOnce(json({ error: 'use_dpop_nonce' }, 401, {
    'DPoP-Nonce': 'safe-nonce', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
  })).mockResolvedValueOnce(new Response(null, { status: 204 }));
  const flow = coordinator(fetcher);
  await flow.password('username', '  exact  ');
  const [first, second] = fetcher.mock.calls.map(([, init]) => init);
  expect(first.body).toBe(second.body);
  const claims = (init: RequestInit) => JSON.parse(Buffer.from((new Headers(init.headers).get('DPoP') ?? '').split('.')[1], 'base64url').toString());
  expect(claims(first).nonce).toBeUndefined();
  expect(claims(second).nonce).toBe('safe-nonce');
  expect(claims(first).jti).not.toBe(claims(second).jti);
  expect(fetcher).toHaveBeenCalledTimes(2);
  flow.dispose();
});

it.each(['network', 'unknown', 'headerless-nonce'] as const)('never retries %s mutation outcomes', async (kind) => {
  const fetcher = jest.fn();
  if (kind === 'network') fetcher.mockRejectedValue(new Error('private network diagnostic'));
  else fetcher.mockResolvedValue(kind === 'unknown' ? json({ error: 'outcome_unknown' }, 503) : json({ error: 'use_dpop_nonce' }, 401, { 'DPoP-Nonce': 'unsafe-nonce' }));
  const flow = coordinator(fetcher);
  await expect(flow.requestCode('username', 'email')).rejects.toBeDefined();
  expect(flow.state.stage).toBe(kind === 'headerless-nonce' ? 'credentials' : 'unconfirmed');
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});

it('retains only definitive wrong-code authority for at most three explicit attempts and the original expiry', async () => {
  const response = codeResponse();
  const fetcher = jest.fn().mockResolvedValueOnce(json(response, 202)).mockImplementation(async () => json({ error: 'invalid_credentials' }, 401));
  const flow = coordinator(fetcher);
  await flow.requestCode('username', 'email');
  for (let attempt = 0; attempt < 3; attempt++) {
    await expect(flow.verifyCode('012345')).rejects.toMatchObject({ code: 'invalid_credentials' });
    if (attempt < 2) expect(flow.state).toEqual({ stage: 'delivered', channel: 'email', expiresAt: response.expires_at });
  }
  expect(flow.state.stage).toBe('expired');
  expect(() => flow.verifyCode('012345')).toThrow();
  expect(fetcher).toHaveBeenCalledTimes(4);
  flow.dispose();
});

it('checks monotonic as well as wall expiry without extending verification on a state read', async () => {
  let monotonic = 1000;
  jest.spyOn(performance, 'now').mockImplementation(() => monotonic);
  const fetcher = jest.fn().mockResolvedValue(json(codeResponse(), 202));
  const flow = coordinator(fetcher);
  await flow.requestCode('username', 'sms');
  const initial = flow.state;
  expect(flow.state).toEqual(initial);
  monotonic += 180001;
  expect(flow.state.stage).toBe('expired');
  expect(() => flow.verifyCode('012345')).toThrow();
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});

it('accepts bounded response latency without extending the local maximum verification lifetime', async () => {
  const now = Date.now();
  const clock = jest.spyOn(Date, 'now').mockReturnValue(now);
  const fetcher = jest.fn().mockResolvedValue(json({ ...codeResponse(), expires_at: new Date(now + 180500).toISOString() }, 202));
  const flow = coordinator(fetcher);
  await flow.requestCode('username', 'email');
  expect(flow.state.stage).toBe('delivered');
  clock.mockReturnValue(now + 180001);
  expect(flow.state.stage).toBe('expired');
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});

it('keeps raw numeric contracts ASCII-only and clears state on dispose', async () => {
  const fetcher = jest.fn().mockResolvedValue(json(mfaResponse()));
  const flow = coordinator(fetcher);
  await flow.password('username', 'password');
  for (const code of ['۰۱۲۳۴۵', '٠١٢٣٤٥', '０１２３４５', '01 345', '\u202e012345', '0123456'])
    expect(() => flow.verifyTotp(code)).toThrow();
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
  expect(flow.state.stage).toBe('closed');
  expect(() => flow.verifyTotp('012345')).toThrow();
});

it('accepts passkey MFA without issuing a session and rejects non-204 MFA completion', async () => {
  const fetcher = jest.fn().mockResolvedValue(json({ status: 'session' }));
  const flow = coordinator(fetcher);
  flow.acceptPasskeyMfa({ ...mfaResponse(), status: 'mfa_required' });
  expect(flow.state.stage).toBe('mfa');
  await expect(flow.verifyTotp('012345')).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
  expect(flow.state.stage).toBe('unconfirmed');
  expect(fetcher).toHaveBeenCalledTimes(1);
  flow.dispose();
});
