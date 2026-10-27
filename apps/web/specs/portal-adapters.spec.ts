/** @jest-environment node */

import { webcrypto } from 'node:crypto';
import {
  assertionOptions,
  base64url,
  creationOptions,
  serializeCredential,
  unbase64url,
} from '../app/_lib/portal/webauthn';
import { normalizeName, safeReturnPath } from '../app/_lib/portal/validation';
import { profileResponse, StepUpGrant } from '../app/_lib/portal/contracts';
import { isSessionLoss, PortalError } from '../app/_lib/portal/errors';
import { signProof, type BrowserKey } from '../app/_lib/portal/dpop';

const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
beforeAll(() =>
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true })
);
afterAll(() => {
  if (originalCrypto) Object.defineProperty(globalThis, 'crypto', originalCrypto);
});

describe('WebAuthn binary adapters', () => {
  it('round-trips all byte values, preserves view offsets and rejects noncanonical encodings', () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
    expect(new Uint8Array(unbase64url(base64url(bytes)))).toEqual(bytes);
    expect(base64url(bytes.subarray(10, 14))).toBe(base64url(Uint8Array.of(10, 11, 12, 13)));
    for (const invalid of ['', 'a', 'AA==', '+/8', 'AB', 'AA\n'])
      expect(() => unbase64url(invalid)).toThrow();
    expect(() => unbase64url('AAAA', 2)).toThrow();
  });

  it('converts assertion challenges and IDs, and requires UV for step-up', () => {
    const decoded = assertionOptions(
      {
        publicKey: {
          challenge: 'AAEC',
          rpId: 'identity.test',
          timeout: 999999,
          userVerification: 'preferred',
          allowCredentials: [{ type: 'public-key', id: 'AwQ', transports: ['internal'] }],
        },
      },
      true
    );
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(Uint8Array.of(0, 1, 2));
    expect(new Uint8Array(decoded.allowCredentials?.[0].id as ArrayBuffer)).toEqual(
      Uint8Array.of(3, 4)
    );
    expect(decoded.userVerification).toBe('required');
    expect(decoded.timeout).toBe(120000);
    expect(assertionOptions({ publicKey: { challenge: 'AA' } }).allowCredentials).toBeUndefined();
  });

  it('converts creation user handles and exclusion IDs without mutating server options', () => {
    const json = {
      publicKey: {
        challenge: 'AAEC',
        rp: { id: 'identity.test', name: 'Identity' },
        user: { id: 'AQI', name: 'opaque-user', displayName: 'Account' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        excludeCredentials: [{ type: 'public-key', id: 'AwQ' }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      },
    };
    const decoded = creationOptions(json);
    expect(new Uint8Array(decoded.user.id as ArrayBuffer)).toEqual(Uint8Array.of(1, 2));
    expect(new Uint8Array(decoded.excludeCredentials?.[0].id as ArrayBuffer)).toEqual(
      Uint8Array.of(3, 4)
    );
    expect(json.publicKey.user.id).toBe('AQI');
    expect(decoded.extensions).toEqual({ credProps: true });
  });

  it('serializes assertion and attestation buffers in the existing Go response shape', () => {
    const buffer = Uint8Array.of(0, 255, 1).buffer;
    const common = {
      type: 'public-key',
      id: 'ignored',
      rawId: buffer,
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    const assertion = serializeCredential({
      ...common,
      response: {
        clientDataJSON: buffer,
        authenticatorData: buffer,
        signature: buffer,
        userHandle: null,
      },
    } as unknown as PublicKeyCredential);
    expect(assertion).toEqual({
      id: 'AP8B',
      rawId: 'AP8B',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
      response: {
        clientDataJSON: 'AP8B',
        authenticatorData: 'AP8B',
        signature: 'AP8B',
        userHandle: null,
      },
    });
    const attestation = serializeCredential({
      ...common,
      response: { clientDataJSON: buffer, attestationObject: buffer, getTransports: () => ['usb'] },
    } as unknown as PublicKeyCredential);
    expect(attestation.response).toEqual({
      clientDataJSON: 'AP8B',
      attestationObject: 'AP8B',
      transports: ['usb'],
    });
  });
});

describe('portal validation and transient authority', () => {
  it('matches Unicode name constraints without normalizing or counting UTF-16 units', () => {
    expect(normalizeName(`\u2002 ${'\u{1f600}'.repeat(80)}\u3000`)).toBe('\u{1f600}'.repeat(80));
    expect(normalizeName('   ')).toBe('');
    expect(normalizeName('\ufeffName')).toBe('\ufeffName');
    for (const invalid of [
      'x'.repeat(81),
      '\nName',
      'Name\t',
      'a\u0000b',
      'a\u0085b',
      'a\u2028b',
      'a\u2029b',
      '\ud800',
    ])
      expect(() => normalizeName(invalid)).toThrow();
  });

  it('allows only fixed portal return paths', () => {
    expect(safeReturnPath('/dashboard/security')).toBe('/dashboard/security');
    expect(safeReturnPath('/dashboard/privacy')).toBe('/dashboard/privacy');
    for (const value of [
      null,
      'https://evil.test',
      '//evil.test',
      '/dashboard?next=https://evil.test',
      '/dashboard/../login',
      '/oauth2/authorize',
      '/dashboard#hash',
      '/dashboard/privacy?token=secret',
      '/dashboard/privacy/',
      '\\evil.test',
    ])
      expect(safeReturnPath(value)).toBe('/dashboard');
  });

  it('preserves decimal revisions beyond JS precision and rejects numeric or noncanonical ones', () => {
    const value = {
      id: 'user-id',
      email: 'user@example.test',
      display_name: '',
      status: 'active',
      lifecycle_revision: '9223372036854775807',
      session: { id: 'session-id', expires_at: '2030-01-01T00:00:00Z' },
    };
    expect(profileResponse(value).lifecycle_revision).toBe('9223372036854775807');
    expect(profileResponse(value).deletion_enabled).toBe(false);
    for (const enabled of [true, false])
      expect(profileResponse({ ...value, deletion_enabled: enabled }).deletion_enabled).toBe(
        enabled
      );
    for (const invalid of [null, 'true', 1, {}, []])
      expect(() => profileResponse({ ...value, deletion_enabled: invalid })).toThrow();
    for (const revision of [123, '01', '-1', '9223372036854775808', '+1'])
      expect(() => profileResponse({ ...value, lifecycle_revision: revision })).toThrow();
  });

  it('consumes a grant once, including failed wrong-session consumption, and checks deadlines', () => {
    const grant = () =>
      new StepUpGrant(
        { token: 'opaque-grant', token_type: 'StepUp', expires_in: 60 },
        'session-id',
        Date.now(),
        Date.now() + 300000
      );
    const first = grant();
    expect(first.take('session-id')).toBe('opaque-grant');
    expect(() => first.take('session-id')).toThrow('grant_expired');
    const wrong = grant();
    expect(() => wrong.take('other')).toThrow('grant_expired');
    expect(() => wrong.take('session-id')).toThrow('grant_expired');
    const expired = new StepUpGrant(
      { token: 'secret', token_type: 'StepUp', expires_in: 60 },
      'session-id',
      Date.now() - 61000,
      Date.now() + 300000
    );
    expect(() => expired.take('session-id')).toThrow('grant_expired');
    const bounded = new StepUpGrant(
      { token: 'secret', token_type: 'StepUp', expires_in: 60 },
      'session-id',
      Date.now(),
      Date.now() - 1
    );
    expect(() => bounded.take('session-id')).toThrow('grant_expired');
  });

  it('does not confuse nonce challenges or failed TOTP with lost cookie authority', () => {
    for (const code of ['invalid_credentials', 'use_dpop_nonce'])
      expect(isSessionLoss(new PortalError(code, 401))).toBe(false);
    expect(isSessionLoss(new PortalError('insufficient_user_authentication', 403))).toBe(false);
    for (const code of ['session_required', 'unauthorized', 'invalid_dpop_proof'])
      expect(isSessionLoss(new PortalError(code, 401))).toBe(true);
    expect(isSessionLoss(new PortalError('session_changed', 409))).toBe(true);
  });

  it('creates real ES256 proofs with non-exportable private keys and no invented ath', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    if (!publicJwk.x || !publicJwk.y) throw new Error('Missing test public key');
    const key: BrowserKey = {
      privateKey: pair.privateKey,
      publicJwk: { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y },
    };
    await expect(crypto.subtle.exportKey('jwk', pair.privateKey)).rejects.toThrow();
    const first = await signProof(
      key,
      'PATCH',
      'https://identity.test/api/v1/users/me',
      'server-nonce'
    );
    const second = await signProof(
      key,
      'PATCH',
      'https://identity.test/api/v1/users/me',
      'server-nonce'
    );
    const [header, payload, signature] = first.split('.');
    expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: key.publicJwk,
    });
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    expect(claims).toMatchObject({
      htm: 'PATCH',
      htu: 'https://identity.test/api/v1/users/me',
      nonce: 'server-nonce',
    });
    expect(claims.ath).toBeUndefined();
    expect(claims.iat).toBeCloseTo(Date.now() / 1000, -1);
    expect(claims.jti).not.toBe(
      JSON.parse(Buffer.from(second.split('.')[1], 'base64url').toString()).jti
    );
    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.publicKey,
        unbase64url(signature),
        new TextEncoder().encode(`${header}.${payload}`)
      )
    ).toBe(true);
  });
});
