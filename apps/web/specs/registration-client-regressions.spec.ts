/** @jest-environment node */
import { webcrypto } from 'node:crypto';
import { RegistrationClient } from '../app/_lib/portal/registration-client';
import type { BrowserKey } from '../app/_lib/portal/dpop';

const origin = 'https://identity.example.test';
const root = `${origin}/api/v1/auth/register`;
const attempt_id = '11111111-1111-4111-8111-111111111111';
const capability = 'A'.repeat(43);
const verification_id = 'B'.repeat(42) + 'A';
const replacement = 'C'.repeat(42) + 'A';
const contacts = { email: 'test@example.test', phone: '+989123456789' };
const credential = {
  id: 'AQID',
  rawId: 'AQID',
  type: 'public-key',
  response: { clientDataJSON: 'BAUG', attestationObject: 'BwgJ' },
  clientExtensionResults: { credProps: { rk: true } },
};
const options = {
  publicKey: {
    rp: { id: 'identity.example.test', name: 'Identity' },
    user: { id: 'AQIDBAUGBwg', name: contacts.email, displayName: contacts.email },
    challenge: 'AQID',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 120000,
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
  },
};
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
let key: BrowserKey;
let otherKey: BrowserKey;
async function makeKey(): Promise<BrowserKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  if (!jwk.x || !jwk.y) throw new Error('Missing test key coordinates');
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
  else Reflect.deleteProperty(globalThis, 'crypto');
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
const started = (expires_at: string, email_sent = true) =>
  json(
    {
      attempt_id,
      capability,
      canonical_email: contacts.email,
      expires_at,
      email_sent,
    },
    201
  );
const pending = (expires_at: string, email_verified = true, phone_verified = true) => ({
  state: 'pending',
  expires_at,
  email_verified,
  phone_verified,
});
const receipt = (receipt_expires_at: string) => ({
  state: 'completed',
  next: 'login',
  receipt_expires_at,
  email_verified: true,
  phone_verified: true,
});
function proof(init: RequestInit) {
  const encoded = new Headers(init.headers).get('DPoP');
  if (!encoded) throw new Error('Missing test DPoP');
  return JSON.parse(Buffer.from(encoded.split('.')[1], 'base64url').toString());
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (failure: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

it.each(['delayed OK', 'lost response'])(
  'preserves a durable committed result across pending expiry after %s with fresh DPoP and one account only',
  async (response) => {
    jest.useFakeTimers();
    const expires = new Date(Date.now() + 1379).toISOString();
    const receiptExpiry = new Date(Date.now() + 3599000).toISOString();
    const committed = deferred<void>();
    const transport = deferred<Response>();
    let accounts = 0;
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(started(expires))
      .mockResolvedValueOnce(json(options))
      .mockImplementationOnce(() => {
        accounts++;
        committed.resolve();
        return transport.promise;
      })
      .mockResolvedValueOnce(json(receipt(receiptExpiry)));
    const api = new RegistrationClient({ origin, fetcher, getKey: async () => key });
    const signal = new AbortController().signal;
    await api.start(contacts, signal);
    await api.passkeyOptions(signal);
    const completion = api.complete(credential, signal);
    const observed =
      response === 'lost response'
        ? expect(completion).rejects.toMatchObject({ code: 'network_error', uncertain: true })
        : expect(completion).resolves.toEqual(receipt(receiptExpiry));
    await committed.promise;
    jest.advanceTimersByTime(1380);
    expect(accounts).toBe(1);
    expect(fetcher).toHaveBeenCalledTimes(3);
    if (response === 'lost response') transport.reject(new TypeError('private transport detail'));
    else transport.resolve(json(receipt(receiptExpiry)));
    await observed;
    expect(await api.result(signal)).toEqual(receipt(receiptExpiry));
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      `${root}/start`,
      `${root}/passkey/options`,
      root,
      `${root}/result`,
    ]);
    expect(JSON.parse(fetcher.mock.calls[3][1].body)).toEqual({ attempt_id, capability });
    expect(proof(fetcher.mock.calls[2][1]).jti).not.toBe(proof(fetcher.mock.calls[3][1]).jti);
    expect(accounts).toBe(1);
    for (const [, init] of fetcher.mock.calls) {
      expect(init).toMatchObject({
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      });
      expect(new Headers(init.headers).has('Authorization')).toBe(false);
      expect(proof(init).ath).toBeUndefined();
    }
    api.dispose();
  }
);

it.each([false, true])(
  'revokes completion recovery on pending result, retaining only original monotonic proof expiry (expired: %s)',
  async (expired) => {
    jest.useFakeTimers();
    const expires = new Date(Date.now() + 1379).toISOString();
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(started(expires))
      .mockResolvedValueOnce(json(options))
      .mockRejectedValueOnce(new TypeError('lost response'))
      .mockResolvedValueOnce(json(pending(expires)));
    const api = new RegistrationClient({ origin, fetcher, getKey: async () => key });
    const signal = new AbortController().signal;
    await api.start(contacts, signal);
    await api.passkeyOptions(signal);
    await expect(api.complete(credential, signal)).rejects.toMatchObject({ uncertain: true });
    jest.advanceTimersByTime(expired ? 1380 : 500);
    if (expired)
      await expect(api.result(signal)).rejects.toMatchObject({ code: 'registration_expired' });
    else {
      expect(await api.result(signal)).toEqual(pending(expires));
      jest.setSystemTime(Date.now() - 3600000);
      jest.advanceTimersByTime(880);
      expect(() => api.result(signal)).toThrow('registration_expired');
    }
    expect(() => api.result(signal)).toThrow('invalid_registration');
    expect(fetcher).toHaveBeenCalledTimes(4);
  }
);

it('cannot renew recovery by losing a result response or rolling the wall clock back', async () => {
  jest.useFakeTimers();
  const expires = new Date(Date.now() + 1379).toISOString();
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(started(expires))
    .mockResolvedValueOnce(json(options))
    .mockRejectedValue(new TypeError('lost response'));
  const api = new RegistrationClient({ origin, fetcher, getKey: async () => key });
  const signal = new AbortController().signal;
  await api.start(contacts, signal);
  await api.passkeyOptions(signal);
  await expect(api.complete(credential, signal)).rejects.toMatchObject({ uncertain: true });
  jest.advanceTimersByTime(3500000);
  await expect(api.result(signal)).rejects.toMatchObject({ code: 'network_error' });
  jest.setSystemTime(Date.now() - 3600000);
  jest.advanceTimersByTime(100001);
  expect(() => api.result(signal)).toThrow('registration_expired');
  expect(fetcher).toHaveBeenCalledTimes(4);
});

it.each(['dispose', 'cancel', 'key change'])(
  'rejects late completion and forgets receipt authority after %s',
  async (reason) => {
    const expires = new Date(Date.now() + 890000).toISOString();
    const dispatched = deferred<void>();
    const transport = deferred<Response>();
    let current = key;
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(started(expires))
      .mockResolvedValueOnce(json(options))
      .mockImplementationOnce(() => {
        dispatched.resolve();
        return transport.promise;
      });
    const api = new RegistrationClient({ origin, fetcher, getKey: async () => current });
    const controller = new AbortController();
    await api.start(contacts, controller.signal);
    await api.passkeyOptions(controller.signal);
    const completion = api.complete(credential, controller.signal);
    const observed = expect(completion).rejects.toMatchObject(
      reason === 'key change' ? { code: 'registration_key_changed' } : { name: 'AbortError' }
    );
    await dispatched.promise;
    if (reason === 'dispose') api.dispose();
    else if (reason === 'cancel') controller.abort();
    else current = otherKey;
    transport.resolve(json(receipt(new Date(Date.now() + 3599000).toISOString())));
    await observed;
    expect(() => api.result(new AbortController().signal)).toThrow('invalid_registration');
    expect(fetcher).toHaveBeenCalledTimes(3);
  }
);

it('retries the same SMS verification reference on explicit wrong-then-leading-zero-correct entry without an extra SMS', async () => {
  const expires = new Date(Date.now() + 890000).toISOString();
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(started(expires, false))
    .mockResolvedValueOnce(json(pending(expires, false, false)))
    .mockResolvedValueOnce(json({ verification_id }))
    .mockResolvedValueOnce(json({ error: 'proof_required' }, 409))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const api = new RegistrationClient({ origin, fetcher, getKey: async () => key });
  const signal = new AbortController().signal;
  expect((await api.start(contacts, signal)).email_sent).toBe(false);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(await api.result(signal)).toEqual(pending(expires, false, false));
  expect(fetcher).toHaveBeenCalledTimes(2);
  await api.sendPhone(signal);
  await expect(api.verifyPhone('000000', signal)).rejects.toMatchObject({
    code: 'proof_required',
    status: 409,
    uncertain: false,
  });
  expect(api.hasPhoneVerification()).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(4);
  await api.verifyPhone('012345', signal);
  expect(api.hasPhoneVerification()).toBe(false);
  const retries = fetcher.mock.calls.slice(3);
  expect(retries.map(([url]) => url)).toEqual([`${root}/phone/verify`, `${root}/phone/verify`]);
  expect(retries.map(([, init]) => JSON.parse(init.body))).toEqual([
    { attempt_id, capability, verification_id, code: '000000' },
    { attempt_id, capability, verification_id, code: '012345' },
  ]);
  expect(proof(retries[0][1]).jti).not.toBe(proof(retries[1][1]).jti);
  expect(fetcher.mock.calls.filter(([url]) => url === `${root}/phone/send`)).toHaveLength(1);
  await expect(api.verifyPhone('012345', signal)).rejects.toMatchObject({
    code: 'invalid_request',
  });
});

it('preserves the three-attempt challenge counter, drops lockout authority, and uses only explicit replacement SMS', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(started(new Date(Date.now() + 890000).toISOString()))
    .mockResolvedValueOnce(json({ verification_id }))
    .mockResolvedValueOnce(json({ error: 'proof_required' }, 409))
    .mockResolvedValueOnce(json({ error: 'proof_required' }, 409))
    .mockResolvedValueOnce(json({ error: 'rate_limited' }, 429))
    .mockResolvedValueOnce(json({ error: 'rate_limited' }, 429))
    .mockResolvedValueOnce(json({ verification_id: replacement }))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const api = new RegistrationClient({ origin, fetcher, getKey: async () => key });
  const signal = new AbortController().signal;
  await api.start(contacts, signal);
  await api.sendPhone(signal);
  for (let attempt = 0; attempt < 3; attempt++) {
    await expect(api.verifyPhone('000000', signal)).rejects.toMatchObject({
      code: attempt < 2 ? 'proof_required' : 'rate_limited',
    });
    expect(api.hasPhoneVerification()).toBe(attempt < 2);
  }
  expect(
    fetcher.mock.calls.slice(2, 5).map(([, init]) => JSON.parse(init.body).verification_id)
  ).toEqual([verification_id, verification_id, verification_id]);
  await expect(api.verifyPhone('012345', signal)).rejects.toMatchObject({
    code: 'invalid_request',
  });
  expect(fetcher).toHaveBeenCalledTimes(5);
  await expect(api.sendPhone(signal)).rejects.toMatchObject({ code: 'rate_limited' });
  expect(api.hasPhoneVerification()).toBe(false);
  await api.sendPhone(signal);
  await api.verifyPhone('012345', signal);
  expect(JSON.parse(fetcher.mock.calls[7][1].body).verification_id).toBe(replacement);
  api.dispose();
});

it.each([
  'network',
  'unknown API',
  'consumed SQL proof',
  'registration expired',
  'dispose',
  'key change',
  'replacement SMS',
  'OTP expiry',
  'monotonic OTP expiry',
])(
  'discards the SMS reference after %s and never recreates or resends it automatically',
  async (reason) => {
    jest.useFakeTimers();
    let current = key;
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(started(new Date(Date.now() + 890000).toISOString()))
      .mockResolvedValueOnce(json({ verification_id }));
    const api = new RegistrationClient({ origin, fetcher, getKey: async () => current });
    const signal = new AbortController().signal;
    await api.start(contacts, signal);
    await api.sendPhone(signal);
    if (reason === 'dispose') api.dispose();
    else if (reason === 'key change') current = otherKey;
    else if (reason === 'replacement SMS') {
      fetcher.mockResolvedValueOnce(json({ error: 'send_failed' }, 503));
      await expect(api.sendPhone(signal)).rejects.toMatchObject({ code: 'send_failed' });
    } else if (reason.includes('OTP expiry')) {
      if (reason === 'monotonic OTP expiry') jest.setSystemTime(Date.now() - 3600000);
      jest.advanceTimersByTime(180001);
    } else {
      if (reason === 'network') fetcher.mockRejectedValueOnce(new TypeError('private detail'));
      else
        fetcher.mockResolvedValueOnce(
          json(
            {
              error:
                reason === 'unknown API'
                  ? 'temporarily_unavailable'
                  : reason === 'consumed SQL proof'
                    ? 'restart_phone_proof'
                    : 'registration_expired',
            },
            reason === 'unknown API' ? 503 : reason === 'consumed SQL proof' ? 409 : 410
          )
        );
    }
    await expect(api.verifyPhone('012345', signal)).rejects.toBeDefined();
    expect(api.hasPhoneVerification()).toBe(false);
    const count = fetcher.mock.calls.length;
    await expect(api.verifyPhone('012345', signal)).rejects.toMatchObject({
      code: 'invalid_request',
    });
    expect(fetcher).toHaveBeenCalledTimes(count);
    expect(fetcher.mock.calls.filter(([url]) => url === `${root}/phone/send`)).toHaveLength(
      reason === 'replacement SMS' ? 2 : 1
    );
    expect(
      fetcher.mock.calls.some(
        ([url]) => url === root || url === `${root}/result` || url === `${root}/email/resend`
      )
    ).toBe(false);
    api.dispose();
  }
);
