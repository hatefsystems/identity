/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import { PortalClient } from '../app/_lib/portal/client';
import { type BrowserKey } from '../app/_lib/portal/dpop';
import { FirstPasskeyError, PortalError } from '../app/_lib/portal/errors';
import { StepUpGrant, type FirstPasskeyAuthority } from '../app/_lib/portal/contracts';

const origin = 'https://identity.example.test';
const signal = () => new AbortController().signal;
const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const nonce = () => json({ error: 'use_dpop_nonce' }, 401, {
  'DPoP-Nonce': 'fixture-nonce', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
});
const profile = () => ({
  id: 'fixture-user', email: null, display_name: '', status: 'active', lifecycle_revision: '1',
  session: { id: 'fixture-session', expires_at: new Date(Date.now() + 3600000).toISOString() },
});
const credential = {
  id: 'fixture-key', name: 'Device', created_at: '2026-11-22T00:00:00Z',
  user_verified: true, backup_eligible: false, backup_state: false,
};
const options = (expires_at: string) => ({
  publicKey: {
    rp: { id: 'identity.example.test', name: 'Identity' },
    user: { id: 'AAECAwQFBgc', name: '\u0639\u0644\u064a.e\u0301', displayName: '\u0639\u0644\u064a.e\u0301' },
    challenge: 'AQIDBA', pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 120000,
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    attestation: 'none',
  },
  expires_at,
});
let key: BrowserKey, otherKey: BrowserKey;
const descriptors = ['crypto', 'navigator', 'PublicKeyCredential', 'isSecureContext'].map(
  (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)] as const
);
const create = jest.fn();
beforeAll(async () => {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  async function makeKey(): Promise<BrowserKey> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    if (!jwk.x || !jwk.y) throw new Error('Missing fixture key');
    return { privateKey: pair.privateKey, publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
  }
  key = await makeKey();
  otherKey = await makeKey();
  Object.defineProperty(globalThis, 'navigator', { value: { credentials: { create, get: jest.fn() } }, configurable: true });
  Object.defineProperty(globalThis, 'PublicKeyCredential', { value: class {}, configurable: true });
  Object.defineProperty(globalThis, 'isSecureContext', { value: true, configurable: true });
});
afterAll(() => {
  for (const [name, descriptor] of descriptors) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else Reflect.deleteProperty(globalThis, name);
  }
});
beforeEach(() => {
  create.mockReset().mockImplementation(async () => ({
    type: 'public-key', rawId: Uint8Array.of(255, 0, 1).buffer,
    authenticatorAttachment: 'platform', getClientExtensionResults: () => ({ credProps: { rk: true } }),
    response: { clientDataJSON: Uint8Array.of(0, 1, 255).buffer,
      attestationObject: Uint8Array.of(255, 2, 0).buffer, getTransports: () => ['internal'] },
  }));
});
afterEach(() => { jest.restoreAllMocks(); jest.useRealTimers(); });

async function fixture(tail: () => Promise<Response> = async () => json(credential, 201), lifetime = 120000) {
  const expires_at = new Date(Date.now() + lifetime).toISOString();
  const challenge = { challenge: 'fixture-challenge', expires_at };
  const proof = { action_proof: 'fixture-proof', expires_at };
  const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json(challenge, 202))
    .mockResolvedValueOnce(json(proof)).mockResolvedValueOnce(json(options(expires_at))).mockImplementation(tail);
  const getKey = jest.fn().mockResolvedValue(key);
  const api = new PortalClient({ origin, fetcher, getKey });
  await api.bootstrap();
  return { api, fetcher, getKey, expires_at };
}
async function earn(api: PortalClient, channel: 'email' | 'sms' = 'email') {
  const challenge = await api.firstPasskeyChallenge(' \u00e9\u0301\u200f\tpassword\u0000 ', channel, signal());
  const proof = await api.firstPasskeyVerify('000123', signal());
  return { challenge, proof };
}
async function ready(api: PortalClient) {
  await earn(api);
  return api.startFirstPasskey(' Device ', signal());
}

it.each(['email', 'sms'] as const)('uses the fixed %s proof routes and keeps every secret private until explicit native and finish actions', async (channel) => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    const { challenge, proof } = await earn(api, channel);
    const safe = { purpose: 'first_passkey_enrollment', expires_at };
    expect(challenge).toEqual(safe);
    expect(proof).toEqual(safe);
    expect(await api.startFirstPasskey(' Device ', signal())).toEqual(safe);
    expect(create).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(JSON.stringify(api)).not.toMatch(/fixture-(challenge|proof)|attestationObject|password/);
    await api.createFirstPasskey(signal());
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(4);
    const native = create.mock.calls[0][0];
    expect(native.publicKey.user.name).toBe(options(expires_at).publicKey.user.name);
    expect(native.publicKey.user.displayName).toBe(native.publicKey.user.name);
    expect(new Uint8Array(native.publicKey.user.id)).toEqual(Uint8Array.of(0, 1, 2, 3, 4, 5, 6, 7));
    expect(native.publicKey.authenticatorSelection.userVerification).toBe('required');
    expect(native.publicKey.timeout).toBeLessThanOrEqual(120000);
    api.onSecurityChange = jest.fn();
    const onSend = jest.fn();
    expect(await api.finishFirstPasskey(signal(), onSend)).toEqual(credential);
    expect(api.onSecurityChange).toHaveBeenCalledWith('passkeyAdded');
    expect(api.profile).toBeUndefined();
    expect(onSend).toHaveBeenCalledTimes(1);
    const routes = fetcher.mock.calls.slice(1).map(([url, init]) => {
      expect(init).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      const headers = new Headers(init.headers);
      expect(headers.get('X-Portal-Session')).toBe('fixture-session');
      expect(headers.has('DPoP')).toBe(true);
      expect(headers.has('X-Step-Up-Auth')).toBe(false);
      expect(headers.has('Authorization')).toBe(false);
      expect(headers.get('X-Action-Proof')).toBe(url.endsWith('generate-options') ? 'fixture-proof' : null);
      return url;
    });
    expect(routes).toEqual([
      `${origin}/api/v1/auth/action-proofs/first-passkey/challenge`,
      `${origin}/api/v1/auth/action-proofs/first-passkey/verify`,
      `${origin}/api/v1/auth/webauthn/register/generate-options`,
      `${origin}/api/v1/auth/webauthn/register/verify`,
    ]);
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ password: ' \u00e9\u0301\u200f\tpassword\u0000 ', channel });
    expect(JSON.parse(fetcher.mock.calls[2][1].body)).toEqual({ challenge: 'fixture-challenge', code: '000123' });
    expect(JSON.parse(fetcher.mock.calls[3][1].body)).toEqual({ name: 'Device' });
    expect(JSON.parse(fetcher.mock.calls[4][1].body).response).toEqual({
      clientDataJSON: 'AAH_', attestationObject: '_wIA', transports: ['internal'],
    });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ phase: 'finish', code: 'cancelled', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(5);
  } finally { api.dispose(); }
});

it('never infers first enrollment authority from profile, username or an empty key list', async () => {
  const fetcher = jest.fn().mockResolvedValueOnce(json(profile())).mockResolvedValueOnce(json([]));
  const api = new PortalClient({ origin, fetcher, getKey: async () => key });
  try {
    await api.bootstrap();
    expect(await api.keys(signal())).toEqual([]);
    await expect(api.startFirstPasskey('', signal())).rejects.toMatchObject({ phase: 'start', code: 'proof_required' });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ phase: 'native', code: 'proof_required' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ phase: 'finish', code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(create).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it.each(['start', 'native', 'finish'] as const)('rejects out-of-order %s calls and withdraws the incompatible local authority', async (phase) => {
  const { api, fetcher } = await fixture();
  try {
    await api.firstPasskeyChallenge('password', 'email', signal());
    const run = phase === 'start' ? () => api.startFirstPasskey('', signal()) :
      phase === 'native' ? () => api.createFirstPasskey(signal()) : () => api.finishFirstPasskey(signal());
    await expect(run()).rejects.toMatchObject({ code: 'proof_required', phase });
    await expect(api.firstPasskeyVerify('000123', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  } finally { api.dispose(); }
});

it.each(['00012', '000123 ', '\u06f0\u06f0\u06f0\u06f1\u06f2\u06f3', '000\u200f123'])('rejects noncanonical OTP %p without normalizing bytes or replaying a challenge', async (code) => {
  const { api, fetcher } = await fixture();
  try {
    await api.firstPasskeyChallenge('password', 'email', signal());
    await expect(api.firstPasskeyVerify(code, signal())).rejects.toMatchObject({ code: 'invalid_request', phase: 'proof' });
    await expect(api.firstPasskeyVerify('000123', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  } finally { api.dispose(); }
});

it('does not apply new-password strength limits to fresh verification of an existing password', async () => {
  const { api, fetcher } = await fixture();
  try {
    const password = 'p'.repeat(1025);
    await api.firstPasskeyChallenge(password, 'email', signal());
    expect(JSON.parse(fetcher.mock.calls[1][1].body).password).toBe(password);
  } finally { api.dispose(); }
});

it.each(['bad-channel', 'email\r\nInjected: value'])('rejects unsupported channels %p before delivery', async (channel) => {
  const { api, fetcher } = await fixture();
  try {
    await expect(api.firstPasskeyChallenge('password', channel as 'email', signal())).rejects.toMatchObject({ code: 'invalid_request' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each(['\ud800', 'x'.repeat(8192)])('bounds exact UTF-8/password JSON before sending without creating weaker password policy', async (password) => {
  const { api, fetcher } = await fixture();
  try {
    await expect(api.firstPasskeyChallenge(password, 'email', signal())).rejects.toMatchObject({ code: 'invalid_request', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('does not interchange safe first-purpose metadata with StepUpGrant or permit action-proof injection into public transport', async () => {
  const { api, fetcher } = await fixture();
  try {
    const { proof } = await earn(api);
    await expect(api.deleteAccount(proof as unknown as StepUpGrant, signal())).rejects.toMatchObject({ code: 'invalid_request' });
    for (const path of ['/api/v1/users/me', '/api/v1/auth/webauthn/register/verify', '/api/v1/auth/webauthn/register/generate-options']) {
      await expect(api.request(path, (v) => v, {
        method: 'POST', firstPasskey: { proof: 'injected' },
      } as Parameters<PortalClient['request']>[2])).rejects.toMatchObject({ code: 'invalid_request' });
    }
    expect(fetcher).toHaveBeenCalledTimes(3);
  } finally { api.dispose(); }
});

it('clears proof before options validation/signing and never refunds a pre-send failure', async () => {
  const { api, fetcher, getKey } = await fixture();
  try {
    await earn(api);
    getKey.mockRejectedValue(new PortalError('key_unavailable'));
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ phase: 'start', uncertain: false });
    getKey.mockResolvedValue(key);
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(create).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it('drops proof before invalid cosmetic-name validation without transmitting it', async () => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    await expect(api.startFirstPasskey('bad\nname', signal())).rejects.toMatchObject({ phase: 'start', code: 'name_single_line' });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  } finally { api.dispose(); }
});

it.each(['start', 'finish'] as const)('allows exactly one strictly identified pre-handler nonce retry for %s with unchanged logical authority/body', async (phase) => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    if (phase === 'start') fetcher.mockReset().mockResolvedValueOnce(nonce())
      .mockResolvedValueOnce(json(options(new Date(Date.now() + 60000).toISOString())))
      .mockImplementation(async () => json(credential, 201));
    await api.startFirstPasskey('Device', signal());
    await api.createFirstPasskey(signal());
    if (phase === 'finish') fetcher.mockReset().mockResolvedValueOnce(nonce()).mockResolvedValueOnce(json(credential, 201));
    await api.finishFirstPasskey(signal());
    const [first, second] = fetcher.mock.calls;
    expect(first[1].body).toBe(second[1].body);
    const a = new Headers(first[1].headers), b = new Headers(second[1].headers);
    expect(a.get('X-Action-Proof')).toBe(phase === 'start' ? 'fixture-proof' : null);
    expect(b.get('X-Action-Proof')).toBe(a.get('X-Action-Proof'));
    expect(a.has('X-Step-Up-Auth')).toBe(false);
    expect(a.get('DPoP')).not.toBe(b.get('DPoP'));
    const claims = JSON.parse(Buffer.from((b.get('DPoP') ?? '').split('.')[1], 'base64url').toString());
    expect(claims.nonce).toBe('fixture-nonce');
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(phase === 'start' ? 3 : 2);
  } finally { api.dispose(); }
});

it.each([
  ['conflict', 409, { error: 'enrollment_in_progress' }, false],
  ['policy', 403, { error: 'insufficient_user_authentication' }, false],
  ['outage', 503, { error: 'temporarily_unavailable' }, true],
  ['malformed', 200, {}, true],
] as const)('reports %s options as start-only uncertainty without a saved-credential claim or replay', async (_case, status, body, uncertain) => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    fetcher.mockReset().mockResolvedValue(json(body, status, { 'Retry-After': '8' }));
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ phase: 'start', uncertain, credentialMayHaveBeenSaved: false, retryAfterSeconds: 8 });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(create).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it.each([
  ['missing UV', { ...credential, user_verified: undefined }, 201],
  ['false UV', { ...credential, user_verified: false }, 201],
  ['untruthful UV', { ...credential, user_verified: 'true' }, 201],
  ['wrong status', credential, 200],
  ['missing credential', {}, 201],
] as const)('treats %s first finish success as uncertain, never native/attestation retry permission', async (_case, body, status) => {
  const { api, fetcher } = await fixture(async () => json(body, status));
  try {
    await ready(api);
    await api.createFirstPasskey(signal());
    api.onSecurityChange = jest.fn();
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ phase: 'finish', code: 'invalid_response', uncertain: true, credentialMayHaveBeenSaved: true });
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required', uncertain: false });
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(5);
  } finally { api.dispose(); }
});

it.each(['start', 'finish'] as const)('does not replay %s network uncertainty', async (phase) => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    if (phase === 'finish') { await api.startFirstPasskey('Device', signal()); await api.createFirstPasskey(signal()); }
    fetcher.mockReset().mockRejectedValue(new TypeError('fixture transport failure'));
    const run = () => phase === 'start' ? api.startFirstPasskey('Device', signal()) : api.finishFirstPasskey(signal());
    await expect(run()).rejects.toMatchObject({ phase, code: 'network_error', uncertain: true, credentialMayHaveBeenSaved: phase === 'finish' });
    await expect(run()).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each(['NotAllowedError', 'AbortError', 'SecurityError'])('clears the ceremony after native %s without finishing, recreating or refunding', async (name) => {
  const { api, fetcher } = await fixture();
  try {
    await ready(api);
    create.mockRejectedValueOnce(new DOMException('Fixture native refusal', name));
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ phase: 'native', uncertain: false });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(4);
  } finally { api.dispose(); }
});

it.each(['proof', 'native', 'finish'] as const)('rejects browser key replacement at the %s boundary before sending or native work', async (stage) => {
  const { api, fetcher, getKey } = await fixture();
  try {
    await earn(api);
    if (stage !== 'proof') await api.startFirstPasskey('Device', signal());
    if (stage === 'finish') await api.createFirstPasskey(signal());
    const before = fetcher.mock.calls.length;
    getKey.mockResolvedValue(otherKey);
    const run = stage === 'proof' ? () => api.startFirstPasskey('Device', signal()) :
      stage === 'native' ? () => api.createFirstPasskey(signal()) : () => api.finishFirstPasskey(signal());
    await expect(run()).rejects.toMatchObject({ code: 'key_unavailable', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(before);
    expect(create).toHaveBeenCalledTimes(stage === 'finish' ? 1 : 0);
    getKey.mockResolvedValue(key);
    await expect(run()).rejects.toBeInstanceOf(FirstPasskeyError);
  } finally { api.dispose(); }
});

it('cannot move earned authority to another PortalClient even with the same session and browser key', async () => {
  const first = await fixture(), second = await fixture();
  try {
    await earn(first.api);
    await expect(second.api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(second.fetcher).toHaveBeenCalledTimes(1);
  } finally { first.api.dispose(); second.api.dispose(); }
});

it.each(['challenge', 'proof', 'native', 'finish'] as const)('explicit clear discards %s stage and exposes no resume receipt', async (stage) => {
  const { api, fetcher } = await fixture();
  try {
    await api.firstPasskeyChallenge('password', 'email', signal());
    if (stage !== 'challenge') await api.firstPasskeyVerify('000123', signal());
    if (stage === 'native' || stage === 'finish') await api.startFirstPasskey('Device', signal());
    if (stage === 'finish') await api.createFirstPasskey(signal());
    const before = fetcher.mock.calls.length;
    api.clearFirstPasskey();
    await expect(api.firstPasskeyVerify('000123', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(before);
  } finally { api.dispose(); }
});

it.each([
  ['missing expiry', (value: Record<string, unknown>) => { delete value.expires_at; }],
  ['extended expiry', (value: Record<string, unknown>) => { value.expires_at = new Date(Date.now() + 300000).toISOString(); }],
  ['expired expiry', (value: Record<string, unknown>) => { value.expires_at = new Date(Date.now() - 1000).toISOString(); }],
  ['submillisecond expiry', (value: Record<string, unknown>) => { value.expires_at = String(value.expires_at).replace('Z', '123Z'); }],
  ['foreign RP', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).rp.id = 'evil.test'; }],
  ['omitted RP', (value: Record<string, unknown>) => { delete (value.publicKey as { rp: { id?: string } }).rp.id; }],
  ['noncanonical RP', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).rp.id = 'Identity.example.test'; }],
  ['sibling RP', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).rp.id = 'notidentity.example.test'; }],
  ['short handle', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.id = 'AA'; }],
  ['noncanonical handle', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.id = 'AAECAwQFBgd'; }],
  ['long handle', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.id = 'AAAAAAAAAAAA'; }],
  ['padded handle', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.id += '='; }],
  ['preferred UV', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).authenticatorSelection.userVerification = 'preferred'; }],
  ['missing UV', (value: Record<string, unknown>) => { delete (value.publicKey as { authenticatorSelection: { userVerification?: string } }).authenticatorSelection.userVerification; }],
  ['empty identity', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.name = ''; }],
  ['different identity fields', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).user.displayName = 'Email fallback'; }],
  ['oversized UTF-8 identity', (value: Record<string, unknown>) => {
    const user = (value.publicKey as ReturnType<typeof options>['publicKey']).user;
    user.name = user.displayName = '\u0639'.repeat(513);
  }],
  ['control identity', (value: Record<string, unknown>) => {
    const user = (value.publicKey as ReturnType<typeof options>['publicKey']).user;
    user.name = user.displayName = 'User\u0000name';
  }],
  ['empty algorithms', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).pubKeyCredParams = []; }],
  ['invalid timeout', (value: Record<string, unknown>) => { (value.publicKey as ReturnType<typeof options>['publicKey']).timeout = 180001; }],
] as const)('fails closed on %s options and never coerces first authority into an ordinary creation', async (_case, mutate) => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    await earn(api);
    const value = options(expires_at);
    mutate(value);
    fetcher.mockReset().mockResolvedValue(json(value));
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ phase: 'start', code: 'invalid_response', uncertain: true });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(create).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('accepts the server-owned parent RP and opaque identity without username/email inference', async () => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    await earn(api);
    const value = options(expires_at);
    value.publicKey.rp.id = 'example.test';
    value.publicKey.user.name = value.publicKey.user.displayName = value.publicKey.user.id;
    fetcher.mockReset().mockResolvedValue(json(value));
    await api.startFirstPasskey('Cosmetic', signal());
    await api.createFirstPasskey(signal());
    expect(create.mock.calls[0][0].publicKey.user.name).toBe(value.publicKey.user.id);
    expect(create.mock.calls[0][0].publicKey.rp.id).toBe('example.test');
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each(['challenge', 'proof'] as const)('requires the exact %s response shape, fixed route and truthful original deadline', async (phase) => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    if (phase === 'proof') await api.firstPasskeyChallenge('password', 'email', signal());
    fetcher.mockReset().mockResolvedValue(json(phase === 'challenge' ?
      { challenge: 'fixture', expires_at, purpose: 'password_change' } :
      { action_proof: 'fixture', expires_at: new Date(Date.parse(expires_at) + 1000).toISOString() },
    phase === 'challenge' ? 202 : 200));
    const run = () => phase === 'challenge' ? api.firstPasskeyChallenge('password', 'email', signal()) : api.firstPasskeyVerify('000123', signal());
    await expect(run()).rejects.toMatchObject({ phase, code: 'invalid_response', uncertain: true });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
  } finally { api.dispose(); }
});

it.each(['challenge', 'proof', 'native', 'finish'] as const)('keeps the original monotonic expiry at %s despite wall-clock rollback', async (stage) => {
  const { api, fetcher } = await fixture();
  try {
    await api.firstPasskeyChallenge('password', 'email', signal());
    if (stage !== 'challenge') await api.firstPasskeyVerify('000123', signal());
    if (stage === 'native' || stage === 'finish') await api.startFirstPasskey('Device', signal());
    if (stage === 'finish') await api.createFirstPasskey(signal());
    const before = fetcher.mock.calls.length, monotonic = performance.now(), wall = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(wall - 3600000);
    jest.spyOn(performance, 'now').mockReturnValue(monotonic + 120001);
    const run = stage === 'challenge' ? () => api.firstPasskeyVerify('000123', signal()) :
      stage === 'proof' ? () => api.startFirstPasskey('Device', signal()) :
        stage === 'native' ? () => api.createFirstPasskey(signal()) : () => api.finishFirstPasskey(signal());
    await expect(run()).rejects.toMatchObject({ code: 'first_passkey_expired', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(before);
  } finally { api.dispose(); }
});

it('expires idle authority automatically at the original deadline without requests or keepalive', async () => {
  jest.useFakeTimers();
  jest.spyOn(crypto.subtle, 'sign').mockResolvedValue(new Uint8Array(64).buffer);
  const { api, fetcher } = await fixture(undefined, 3000);
  try {
    await earn(api);
    jest.setSystemTime(Date.now() - 3600000);
    jest.advanceTimersByTime(3001);
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(3);
  } finally { api.dispose(); }
});

it('caps native time by a shorter authoritative options expiry without resetting the proof lifetime', async () => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    const expires_at = new Date(Date.now() + 25000).toISOString();
    fetcher.mockReset().mockResolvedValue(json(options(expires_at)));
    expect(await api.startFirstPasskey('Device', signal())).toEqual({ purpose: 'first_passkey_enrollment', expires_at });
    await api.createFirstPasskey(signal());
    expect(create.mock.calls[0][0].publicKey.timeout).toBeLessThanOrEqual(25000);
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each(['start', 'finish'] as const)('withdraws %s authority on transmitted abort or late response without replay', async (phase) => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    await earn(api);
    if (phase === 'finish') { await api.startFirstPasskey('Device', signal()); await api.createFirstPasskey(signal()); }
    let finish!: (response: Response) => void;
    let started!: () => void;
    const sent = new Promise<void>((resolve) => { started = resolve; });
    fetcher.mockReset().mockImplementation(() => new Promise<Response>((resolve) => { finish = resolve; started(); }));
    const controller = new AbortController();
    const run = () => phase === 'start' ? api.startFirstPasskey('Device', controller.signal) : api.finishFirstPasskey(controller.signal);
    const pending = run();
    const rejected = expect(pending).rejects.toMatchObject({ phase, uncertain: true, credentialMayHaveBeenSaved: phase === 'finish' });
    await sent;
    controller.abort();
    finish(json(phase === 'start' ? options(expires_at) : credential, phase === 'start' ? 200 : 201));
    await rejected;
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each(['start', 'finish'] as const)('rejects late %s success after the original deadline even when wall time moved backward', async (phase) => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    await earn(api);
    if (phase === 'finish') { await api.startFirstPasskey('Device', signal()); await api.createFirstPasskey(signal()); }
    let finish!: (response: Response) => void, started!: () => void;
    const sent = new Promise<void>((resolve) => { started = resolve; });
    fetcher.mockReset().mockImplementation(() => new Promise<Response>((resolve) => { finish = resolve; started(); }));
    const pending = phase === 'start' ? api.startFirstPasskey('Device', signal()) : api.finishFirstPasskey(signal());
    const rejected = expect(pending).rejects.toMatchObject({ phase, code: 'first_passkey_expired', uncertain: true });
    await sent;
    const wall = Date.now(), monotonic = performance.now();
    jest.spyOn(Date, 'now').mockReturnValue(wall - 3600000);
    jest.spyOn(performance, 'now').mockReturnValue(monotonic + 120001);
    finish(json(phase === 'start' ? options(expires_at) : credential, phase === 'start' ? 200 : 201));
    await rejected;
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('drops late native success after cancellation and never sends or retries the attestation', async () => {
  const { api, fetcher } = await fixture();
  try {
    await ready(api);
    const response = await create();
    create.mockClear();
    let finish!: (credential: unknown) => void, started!: () => void;
    const opened = new Promise<void>((resolve) => { started = resolve; });
    create.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; started(); }));
    const controller = new AbortController();
    const pending = api.createFirstPasskey(controller.signal);
    const rejected = expect(pending).rejects.toMatchObject({ phase: 'native', code: 'cancelled', uncertain: false });
    await opened;
    controller.abort();
    finish(response);
    await rejected;
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(create).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('refuses parallel native calls without issuing another native prompt', async () => {
  const { api, fetcher } = await fixture();
  try {
    await ready(api);
    const response = await create();
    create.mockClear();
    let finish!: (credential: unknown) => void, started!: () => void;
    const opened = new Promise<void>((resolve) => { started = resolve; });
    create.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; started(); }));
    const pending = api.createFirstPasskey(signal());
    await opened;
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ code: 'enrollment_in_progress', phase: 'native' });
    finish(response);
    await pending;
    expect(create).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(4);
  } finally { api.dispose(); }
});

it('clears first-purpose authority when bootstrap detects a different account/session', async () => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    fetcher.mockReset().mockResolvedValue(json({ ...profile(), id: 'other-user', session: { ...profile().session, id: 'other-session' } }));
    await expect(api.bootstrap()).rejects.toMatchObject({ code: 'session_changed' });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('fails a late options response after browser-key replacement without creating native work', async () => {
  const { api, fetcher, getKey, expires_at } = await fixture();
  try {
    await earn(api);
    fetcher.mockReset().mockImplementation(async () => {
      getKey.mockResolvedValue(otherKey);
      return json(options(expires_at));
    });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'key_unavailable', phase: 'start', uncertain: true });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(create).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it.each(['challenge', 'proof', 'native', 'finish'] as const)('aborting the completed %s owner signal clears idle authority', async (stage) => {
  const { api, fetcher } = await fixture();
  const controller = new AbortController();
  try {
    await api.firstPasskeyChallenge('password', 'email', controller.signal);
    if (stage !== 'challenge') await api.firstPasskeyVerify('000123', controller.signal);
    if (stage === 'native' || stage === 'finish') await api.startFirstPasskey('Device', controller.signal);
    if (stage === 'finish') await api.createFirstPasskey(controller.signal);
    const before = fetcher.mock.calls.length;
    controller.abort();
    await expect(api.firstPasskeyVerify('000123', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(before);
  } finally { api.dispose(); }
});

it('rejects a changed earning session before consuming first-purpose proof', async () => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    const current = api.profile;
    if (!current) throw new Error('Missing fixture profile');
    current.session.id = 'different-session';
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'session_changed', phase: 'start', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(3);
  } finally { api.dispose(); }
});

it('rejects authority whose original deadline exceeds the earning session', async () => {
  const { api, fetcher, expires_at } = await fixture();
  try {
    const current = api.profile;
    if (!current) throw new Error('Missing fixture profile');
    current.session.expires_at = new Date(Date.now() + 30000).toISOString();
    fetcher.mockReset().mockResolvedValue(json({ challenge: 'fixture-challenge', expires_at }, 202));
    await expect(api.firstPasskeyChallenge('password', 'email', signal())).rejects.toMatchObject({ code: 'invalid_response', uncertain: true });
    await expect(api.firstPasskeyVerify('000123', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('caps a legitimate delayed challenge issuance from its original deadline instead of request initiation', async () => {
  const { api, fetcher } = await fixture();
  try {
    fetcher.mockReset().mockImplementation(async () =>
      json({ challenge: 'fixture-challenge', expires_at: new Date(Date.now() + 180000).toISOString() }, 202));
    await expect(api.firstPasskeyChallenge('password', 'email', signal())).resolves.toMatchObject({ purpose: 'first_passkey_enrollment' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it.each([
  ['second nonce', () => nonce(), 2],
  ['unmarked nonce', () => json({ error: 'use_dpop_nonce' }, 401, { 'DPoP-Nonce': 'fixture-nonce' }), 1],
  ['wrong error', () => json({ error: 'insufficient_user_authentication' }, 401, { 'DPoP-Nonce': 'fixture-nonce', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' }), 1],
] as const)('does not replay options authority after %s', async (_case, response, count) => {
  const { api, fetcher } = await fixture();
  try {
    await earn(api);
    fetcher.mockReset().mockImplementation(async () => response());
    await expect(api.startFirstPasskey('Device', signal())).rejects.toBeInstanceOf(FirstPasskeyError);
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(count);
    expect(create).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it('never accepts a native assertion as a first-passkey creation result', async () => {
  const { api, fetcher } = await fixture();
  try {
    await ready(api);
    create.mockResolvedValueOnce({ type: 'public-key', response: { signature: new ArrayBuffer(2) } });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ phase: 'native', code: 'invalid_response', uncertain: false });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ code: 'proof_required' });
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(create).toHaveBeenCalledTimes(1);
  } finally { api.dispose(); }
});

it('lets a strictly decoded first finish win concurrent session loss without rebootstrap or new key acquisition', async () => {
  const { api, fetcher, getKey } = await fixture();
  try {
    await ready(api);
    await api.createFirstPasskey(signal());
    let finish!: (response: Response) => void, started!: () => void;
    const sent = new Promise<void>((resolve) => { started = resolve; });
    fetcher.mockReset().mockImplementationOnce(() => new Promise<Response>((resolve) => { finish = resolve; started(); }))
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const ui = new AbortController();
    api.onSessionLoss = jest.fn(() => ui.abort());
    api.onSecurityChange = jest.fn();
    const pending = api.finishFirstPasskey(ui.signal);
    await sent;
    await expect(api.keys(signal())).rejects.toMatchObject({ code: 'session_required' });
    getKey.mockRejectedValue(new PortalError('key_unavailable'));
    finish(json(credential, 201));
    expect(await pending).toEqual(credential);
    expect(api.onSecurityChange).toHaveBeenCalledWith('passkeyAdded');
    expect(api.profile).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
  } finally { api.dispose(); }
});

it('treats browser-key replacement after finish transmission as uncertain without replay or replacement authority', async () => {
  const { api, fetcher, getKey } = await fixture();
  try {
    await ready(api);
    await api.createFirstPasskey(signal());
    let finish!: (response: Response) => void, started!: () => void;
    const sent = new Promise<void>((resolve) => { started = resolve; });
    fetcher.mockReset().mockImplementationOnce(() => new Promise<Response>((resolve) => { finish = resolve; started(); }));
    api.onSessionLoss = jest.fn();
    api.onSecurityChange = jest.fn();
    const pending = api.finishFirstPasskey(signal());
    const rejected = expect(pending).rejects.toMatchObject({
      phase: 'finish', code: 'key_unavailable', uncertain: true, credentialMayHaveBeenSaved: true,
    });
    await sent;
    getKey.mockResolvedValue(otherKey);
    finish(json(credential, 201, { 'X-Identity-Auth-Invalidated': 'true' }));
    await rejected;
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.profile).toBeUndefined();
    getKey.mockResolvedValue(key);
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ phase: 'finish', uncertain: false });
    await expect(api.startFirstPasskey('Device', signal())).rejects.toMatchObject({ phase: 'start', uncertain: false });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ phase: 'native', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe(`${origin}/api/v1/auth/webauthn/register/verify`);
    expect(create).toHaveBeenCalledTimes(1);
    expect(api.onSecurityChange).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

it.each([
  ['malformed credential', {}],
  ['non-UV credential', { ...credential, user_verified: false }],
] as const)('never claims a preserved first finish with %s after concurrent GET401 as committed', async (_case, body) => {
  const { api, fetcher, getKey } = await fixture();
  try {
    await ready(api);
    await api.createFirstPasskey(signal());
    let finish!: (response: Response) => void, started!: () => void;
    const sent = new Promise<void>((resolve) => { started = resolve; });
    fetcher.mockReset().mockImplementationOnce(() => new Promise<Response>((resolve) => { finish = resolve; started(); }))
      .mockResolvedValueOnce(json({ error: 'session_required' }, 401));
    const ui = new AbortController();
    api.onSessionLoss = jest.fn(() => ui.abort());
    api.onSecurityChange = jest.fn();
    const pending = api.finishFirstPasskey(ui.signal);
    const rejected = expect(pending).rejects.toMatchObject({
      phase: 'finish', code: 'invalid_response', uncertain: true, credentialMayHaveBeenSaved: true,
    });
    await sent;
    await expect(api.keys(signal())).rejects.toMatchObject({ code: 'session_required' });
    expect(ui.signal.aborted).toBe(true);
    expect(fetcher.mock.calls[0][1].signal.aborted).toBe(false);
    getKey.mockRejectedValue(new PortalError('key_unavailable'));
    finish(json(body, 201, { 'X-Identity-Auth-Invalidated': 'true' }));
    await rejected;
    expect(api.profile).toBeUndefined();
    expect(api.onSecurityChange).not.toHaveBeenCalled();
    expect(api.onSessionLoss).toHaveBeenLastCalledWith(expect.objectContaining({ code: 'session_required' }));
    await expect(api.bootstrap()).rejects.toMatchObject({ name: 'AbortError' });
    await expect(api.finishFirstPasskey(signal())).rejects.toMatchObject({ phase: 'finish', uncertain: false });
    await expect(api.createFirstPasskey(signal())).rejects.toMatchObject({ phase: 'native', uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      `${origin}/api/v1/auth/webauthn/register/verify`, `${origin}/api/v1/auth/webauthn/keys`,
    ]);
    expect(create).toHaveBeenCalledTimes(1);
    expect(api.onSecurityChange).not.toHaveBeenCalled();
  } finally { api.dispose(); }
});

// Type-level separation: public metadata does not carry a grant or token API.
function authorityTypes(first: FirstPasskeyAuthority, stepup: StepUpGrant) {
  // @ts-expect-error first-purpose metadata is not a StepUpGrant
  const grant: StepUpGrant = first;
  // @ts-expect-error generic Step-up has no fixed first purpose/deadline projection
  const proof: FirstPasskeyAuthority = stepup;
  return { grant, proof };
}
void authorityTypes;
