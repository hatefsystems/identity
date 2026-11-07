/** @jest-environment node */
import { webcrypto } from 'node:crypto';
import { RegistrationClient } from '../app/_lib/portal/registration-client';
import type { BrowserKey } from '../app/_lib/portal/dpop';
import { PortalError } from '../app/_lib/portal/errors';
import { validateRegistration, validateSignupEmail } from '../app/(auth)/_lib/validation';

const origin = 'https://identity.example.test';
const attemptID = '11111111-1111-4111-8111-111111111111';
const capability = 'A'.repeat(43);
const token = 'B'.repeat(42) + 'A';
const verificationID = 'C'.repeat(42) + 'A';
const canonical = '\u0647\u0627\u062a\u0641@example.test';
const contacts = { email: ` ${canonical.split('@')[0]}@EXAMPLE.test `, phone: '+989123456789' };
let expires: string;
let key: BrowserKey;
let otherKey: BrowserKey;
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
async function makeKey(): Promise<BrowserKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !jwk.x || !jwk.y)
    throw new Error('Missing test public key coordinates');
  return {
    privateKey: pair.privateKey,
    publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
  };
}
beforeAll(async () => {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  key = await makeKey();
  otherKey = await makeKey();
});
afterAll(() => {
  if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto);
});
beforeEach(() => {
  expires = new Date(Date.now() + 890000).toISOString();
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const startResponse = (override: Record<string, unknown> = {}) =>
  json(
    {
      attempt_id: attemptID,
      capability,
      canonical_email: canonical,
      expires_at: expires,
      email_sent: true,
      ...override,
    },
    201
  );
const pending = (email_verified = false, phone_verified = false) => ({
  state: 'pending',
  expires_at: expires,
  email_verified,
  phone_verified,
});
const completed = () => ({
  state: 'completed',
  next: 'login',
  receipt_expires_at: new Date(Date.now() + 3599000).toISOString(),
  email_verified: true,
  phone_verified: true,
});
const options = (override: Record<string, unknown> = {}) => ({
  publicKey: {
    rp: { id: 'identity.example.test', name: 'Identity' },
    user: { id: 'AQIDBAUGBwg', name: canonical, displayName: canonical },
    challenge: 'AQID',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 120000,
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
    ...override,
  },
});
const credential = {
  id: 'AQID',
  rawId: 'AQID',
  type: 'public-key',
  response: { clientDataJSON: 'BAUG', attestationObject: 'BwgJ', transports: ['internal'] },
  clientExtensionResults: { credProps: { rk: true } },
};
function dpopProof(init: RequestInit): string {
  const proof = new Headers(init.headers).get('DPoP');
  if (!proof) throw new Error('Missing test DPoP proof');
  return proof;
}
const claims = (init: RequestInit) =>
  JSON.parse(Buffer.from(dpopProof(init).split('.')[1], 'base64url').toString());
function client(fetcher: jest.Mock, getKey = async () => key) {
  return new RegistrationClient({ origin, fetcher, getKey });
}

it('simulates the complete signup contract, keeping canonical email authoritative and all authority in JSON only', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(startResponse())
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockResolvedValueOnce(json(pending(true)))
    .mockResolvedValueOnce(json({ verification_id: verificationID }))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockResolvedValueOnce(json(options()))
    .mockResolvedValueOnce(json(completed()));
  const api = client(fetcher);
  const signal = new AbortController().signal;
  const view = await api.start(Object.freeze(contacts), signal);
  expect(view).toEqual({ canonical_email: canonical, expires_at: expires, email_sent: true });
  expect(JSON.stringify(api)).not.toContain(capability);
  expect(fetcher).toHaveBeenCalledTimes(1);
  const emailTab = client(fetcher);
  await emailTab.verifyEmail({ attempt_id: attemptID, token }, signal);
  expect(await api.result(signal)).toEqual(pending(true));
  await api.sendPhone(signal);
  await api.verifyPhone('012345', signal);
  expect(await api.passkeyOptions(signal)).toEqual(options());
  expect(await api.complete(credential, signal)).toMatchObject({
    state: 'completed',
    next: 'login',
  });
  const bodies = fetcher.mock.calls.map(([, init]) => JSON.parse(init.body));
  expect(bodies).toEqual([
    contacts,
    { attempt_id: attemptID, token },
    { attempt_id: attemptID, capability },
    { attempt_id: attemptID, capability },
    { attempt_id: attemptID, capability, verification_id: verificationID, code: '012345' },
    { attempt_id: attemptID, capability },
    { attempt_id: attemptID, capability, credential },
  ]);
  for (const [url, init] of fetcher.mock.calls) {
    expect(new URL(url).search).toBe('');
    expect(new URL(url).hash).toBe('');
    expect(url).not.toContain(capability);
    expect(url).not.toContain(token);
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      mode: 'cors',
    });
    expect(new Headers(init.headers).has('Authorization')).toBe(false);
    expect(new Headers(init.headers).has('X-Portal-Session')).toBe(false);
    expect(claims(init).ath).toBeUndefined();
  }
  expect(new Set(fetcher.mock.calls.map(([, init]) => claims(init).jti)).size).toBe(7);
  emailTab.dispose();
  api.dispose();
});

it('retries only a complete pre-handler nonce challenge, with fresh JTI and the same pinned key/body', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(
      json({ error: 'use_dpop_nonce' }, 401, {
        'DPoP-Nonce': 'nonce',
        'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
      })
    )
    .mockResolvedValueOnce(startResponse());
  await client(fetcher).start(contacts, new AbortController().signal);
  expect(fetcher).toHaveBeenCalledTimes(2);
  const first = fetcher.mock.calls[0][1],
    second = fetcher.mock.calls[1][1];
  expect(first.body).toBe(second.body);
  expect(claims(first).jti).not.toBe(claims(second).jti);
  expect(claims(second)).toMatchObject({
    nonce: 'nonce',
    htm: 'POST',
    htu: `${origin}/api/v1/auth/register/start`,
  });
  expect(
    JSON.parse(Buffer.from(dpopProof(first).split('.')[0], 'base64url').toString()).jwk
  ).toEqual(key.publicJwk);
});

it.each([400, 401, 429, 503])(
  'does not automatically send again after a %i failure',
  async (status) => {
    const fetcher = jest
      .fn()
      .mockResolvedValue(json({ error: 'rate_limited' }, status, { 'Retry-After': '60' }));
    await expect(
      client(fetcher).start(contacts, new AbortController().signal)
    ).rejects.toMatchObject({ status, retryAfterSeconds: 60 });
    expect(fetcher).toHaveBeenCalledTimes(1);
  }
);

it('keeps email_sent=false unverified, permits only explicit resend, and never automatically sends SMS', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(startResponse({ email_sent: false }))
    .mockResolvedValueOnce(json(pending()))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const api = client(fetcher),
    signal = new AbortController().signal;
  expect((await api.start(contacts, signal)).email_sent).toBe(false);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(await api.result(signal)).toEqual(pending());
  await api.resendEmail(signal);
  expect(fetcher.mock.calls.map(([url]) => url)).not.toContain(
    `${origin}/api/v1/auth/register/phone/send`
  );
});

it.each([
  { session: 'forbidden' },
  { capability: 'not-a-capability' },
  { attempt_id: attemptID.toUpperCase().replace('1111', 'AAAA') },
  { canonical_email: 'a\u202e@example.test' },
  { canonical_email: 'a'.repeat(65) + '@example.test' },
  { canonical_email: 'a@EXAMPLE.test' },
  { expires_at: new Date(Date.now() + 3600000).toISOString() },
  { email_sent: 'yes' },
])('rejects malformed/undeclared signup response fields', async (override) => {
  await expect(
    client(jest.fn().mockResolvedValue(startResponse(override))).start(
      contacts,
      new AbortController().signal
    )
  ).rejects.toMatchObject({ code: 'invalid_response' });
});

it.each([
  { user: { id: 'AQIDBAUGBwg', name: 'other@example.test', displayName: 'other@example.test' } },
  { user: { id: 'AQID', name: canonical, displayName: canonical } },
  {
    authenticatorSelection: {
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'required',
    },
  },
  {
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred',
    },
  },
  { rp: { id: 'evil.test', name: 'Identity' } },
  { extra: true },
])(
  'rejects passkey responses not bound to canonical email, handle, RP, discoverability or UV',
  async (override) => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(startResponse())
      .mockResolvedValueOnce(json(options(override)));
    const api = client(fetcher),
      signal = new AbortController().signal;
    await api.start(contacts, signal);
    await expect(api.passkeyOptions(signal)).rejects.toMatchObject({ code: 'invalid_response' });
  }
);

it('rejects a result changing the frozen expiry, introducing sessions, or claiming phone proof without email', async () => {
  for (const result of [
    { ...pending(), expires_at: new Date(Date.now() + 500000).toISOString() },
    { ...completed(), session: {} },
    pending(false, true),
  ]) {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(startResponse())
      .mockResolvedValueOnce(json(result));
    const api = client(fetcher),
      signal = new AbortController().signal;
    await api.start(contacts, signal);
    await expect(api.result(signal)).rejects.toMatchObject({ code: 'invalid_response' });
  }
});

it('checks durable results with fresh DPoP after a lost completion response, including after pending expiry, without replaying creation', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(startResponse())
    .mockResolvedValueOnce(json(options()))
    .mockRejectedValueOnce(new TypeError('private detail'))
    .mockResolvedValueOnce(json(completed()));
  const api = client(fetcher),
    signal = new AbortController().signal;
  await api.start(contacts, signal);
  await api.passkeyOptions(signal);
  await expect(api.complete(credential, signal)).rejects.toMatchObject({
    code: 'network_error',
    uncertain: true,
  });
  const initial = Date.now();
  jest.spyOn(Date, 'now').mockReturnValue(initial + 900000);
  fetcher.mockResolvedValueOnce(json(completed()));
  expect(await api.result(signal)).toMatchObject({ state: 'completed' });
  expect(
    fetcher.mock.calls.filter(([url]) => url === `${origin}/api/v1/auth/register`)
  ).toHaveLength(1);
  expect(claims(fetcher.mock.calls[2][1]).jti).not.toBe(claims(fetcher.mock.calls[3][1]).jti);
});

it('clears authority and prevents a request after the persisted key changes', async () => {
  let current = key;
  const fetcher = jest.fn().mockResolvedValue(startResponse());
  const api = client(fetcher, async () => current),
    signal = new AbortController().signal;
  await api.start(contacts, signal);
  current = otherKey;
  await expect(api.result(signal)).rejects.toMatchObject({ code: 'registration_key_changed' });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(() => api.result(signal)).toThrow('invalid_registration');
});

it('does not accept a reply if the key changes during its network request', async () => {
  let current = key;
  const fetcher = jest.fn(async () => {
    current = otherKey;
    return startResponse();
  });
  await expect(
    client(fetcher, async () => current).start(contacts, new AbortController().signal)
  ).rejects.toMatchObject({ code: 'registration_key_changed' });
});

it('email verification uses the existing key without capability or key initialization; wrong browsers cannot verify', async () => {
  const getKey = jest.fn(async (initialize: boolean) => {
    if (initialize) throw new Error('Must not initialize');
    return otherKey;
  });
  const fetcher = jest.fn().mockResolvedValue(json({ error: 'invalid_registration' }, 401));
  const api = new RegistrationClient({ origin, fetcher, getKey });
  await expect(
    api.verifyEmail({ attempt_id: attemptID, token }, new AbortController().signal)
  ).rejects.toMatchObject({ code: 'invalid_registration' });
  expect(getKey.mock.calls.every(([initialize]) => initialize === false)).toBe(true);
  expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ attempt_id: attemptID, token });
  const missing = new RegistrationClient({
    origin,
    fetcher,
    getKey: async () => {
      throw new PortalError('key_unavailable');
    },
  });
  await expect(
    missing.verifyEmail({ attempt_id: attemptID, token }, new AbortController().signal)
  ).rejects.toMatchObject({ code: 'key_unavailable' });
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('rejects caller authority overrides and invalid Unicode/raw bytes before allocation', async () => {
  const fetcher = jest.fn();
  for (const values of [
    { ...contacts, role: 'admin' },
    { ...contacts, email: 'a\ud800@example.test' },
    { ...contacts, email: 'a\ufffd@example.test' },
    { ...contacts, email: '\u00e9'.repeat(512) + '@example.test' },
    { ...contacts, phone: '+12025550123' },
  ])
    await expect(client(fetcher).start(values, new AbortController().signal)).rejects.toMatchObject(
      { code: 'invalid_request' }
    );
  expect(fetcher).not.toHaveBeenCalled();
});

it('uses raw UTF-8 bounds and preserves NFC/IDNA-distinct input rather than JS canonicalizing', async () => {
  const email = ' '.repeat(1024 - 8) + 'a@b.test';
  expect(validateSignupEmail(email)).toEqual({});
  expect(validateSignupEmail(' ' + email)).toHaveProperty('email');
  expect(validateSignupEmail('a\u200c@example.test')).toHaveProperty('email');
  expect(validateSignupEmail('a\ufe0f@example.test')).toHaveProperty('email');
  expect(validateSignupEmail('\ud800@example.test')).toHaveProperty('email');
  expect(
    validateRegistration({ email: 'cafe\u0301@\u0645\u062b\u0627\u0644.ir', phone: '09123456789' })
  ).toEqual({});
  const fetcher = jest.fn().mockResolvedValue(startResponse());
  await client(fetcher).start(
    { ...contacts, email: 'cafe\u0301@\u0645\u062b\u0627\u0644.ir' },
    new AbortController().signal
  );
  expect(JSON.parse(fetcher.mock.calls[0][1].body).email).toBe(
    'cafe\u0301@\u0645\u062b\u0627\u0644.ir'
  );
});

it('cancellation rejects a late response and cannot restore forgotten authority', async () => {
  let finish!: (response: Response) => void;
  const fetcher = jest.fn(
    () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      })
  );
  const api = client(fetcher),
    controller = new AbortController();
  const request = api.start(contacts, controller.signal);
  while (!finish) await new Promise((resolve) => setImmediate(resolve));
  controller.abort();
  finish(startResponse());
  await expect(request).rejects.toMatchObject({ name: 'AbortError' });
  expect(() => api.result(new AbortController().signal)).toThrow('invalid_registration');
});
