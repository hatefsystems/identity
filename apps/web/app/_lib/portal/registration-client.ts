import {
  validateRegistration,
  validateSignupEmail,
  type RegistrationValues,
} from '../../(auth)/_lib/validation';
import { browserKey, signProof, type BrowserKey } from './dpop';
import { isAborted, parseRetryAfter, PortalError, throwIfAborted } from './errors';
import { emptyResponse, readResponse } from './json-response';
import { isReclaimToken } from './reclaim-client';
import { record, timestamp } from './validation';
import { base64url, creationOptions, unbase64url } from './webauthn';

const root = '/api/v1/auth/register';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export type EmailProof = { attempt_id: string; token: string };
export type RegistrationAttempt = {
  canonical_email: string;
  expires_at: string;
  email_sent: boolean;
};
export type RegistrationOutcome =
  | { state: 'pending'; expires_at: string; email_verified: boolean; phone_verified: boolean }
  | {
      state: 'failed';
      receipt_expires_at: string;
      email_verified: boolean;
      phone_verified: boolean;
    }
  | {
      state: 'completed';
      next: 'login';
      receipt_expires_at: string;
      email_verified: true;
      phone_verified: true;
    };

function exact(value: unknown, keys: string[]): Record<string, unknown> {
  const item = record(value);
  if (Object.keys(item).length !== keys.length || keys.some((key) => !Object.hasOwn(item, key)))
    throw new PortalError('invalid_response');
  return item;
}
function id(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !uuid.test(value) ||
    value === '00000000-0000-0000-0000-000000000000'
  )
    throw new PortalError('invalid_response');
  return value;
}
function secret(value: unknown): string {
  if (!isReclaimToken(value)) throw new PortalError('invalid_response');
  return value;
}
function canonicalEmail(value: unknown): string {
  if (
    typeof value !== 'string' ||
    Object.keys(validateSignupEmail(value)).length ||
    value.trim() !== value ||
    value.normalize('NFC') !== value ||
    new TextEncoder().encode(value).length > 254 ||
    new TextEncoder().encode(value.split('@')[0]).length > 64 ||
    !/^[a-z0-9.-]+$/.test(value.split('@')[1])
  )
    throw new PortalError('invalid_response');
  return value;
}

export function scrubRegistrationFragment(): EmailProof | undefined {
  const fragment = window.location.hash;
  const query = window.location.search;
  // Scrub before parsing or constructing a client. Never retain history state.
  window.history.replaceState(null, '', window.location.pathname);
  const match = /^#attempt_id=([0-9a-f-]{36})&token=([A-Za-z0-9_-]{43})$/.exec(fragment);
  if (query || !match) return undefined;
  try {
    return { attempt_id: id(match[1]), token: secret(match[2]) };
  } catch {
    return undefined;
  }
}

// This client has no authenticated-session methods, persistence, or mutation
// replay. Only the server's explicit pre-handler nonce challenge may be retried.
export class RegistrationClient {
  #lifetime = new AbortController();
  #jkt?: string;
  #authority?: { attempt_id: string; capability: string; expires_at: string; email: string };
  #verification?: { id: string; wall: number; monotonic: number; failures: number };
  #handle?: string;
  #recoverUntil = 0;
  #pendingMonotonic = 0;
  #recoverMonotonic = 0;
  #busy = false;
  readonly origin: string;
  private readonly fetcher: typeof fetch;
  private readonly getKey: (initialize: boolean, signal: AbortSignal) => Promise<BrowserKey>;

  constructor(
    options: {
      origin?: string;
      fetcher?: typeof fetch;
      getKey?: (initialize: boolean, signal: AbortSignal) => Promise<BrowserKey>;
    } = {}
  ) {
    this.origin = options.origin ?? window.location.origin;
    const origin = new URL(this.origin);
    if (origin.origin !== this.origin || !['https:', 'http:'].includes(origin.protocol))
      throw new PortalError('invalid_origin');
    this.fetcher = options.fetcher ?? ((...args) => fetch(...args));
    this.getKey = options.getKey ?? browserKey;
  }
  dispose(): void {
    this.#authority = undefined;
    this.#verification = undefined;
    this.#handle = undefined;
    this.#jkt = undefined;
    this.#lifetime.abort();
  }
  async assertKey(signal: AbortSignal, initialize = false): Promise<BrowserKey> {
    throwIfAborted(signal);
    throwIfAborted(this.#lifetime.signal);
    try {
      const key = await this.getKey(initialize, signal);
      const { kty, crv, x, y } = key.publicJwk;
      const jkt = base64url(
        await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(JSON.stringify({ crv, kty, x, y }))
        )
      );
      throwIfAborted(signal);
      throwIfAborted(this.#lifetime.signal);
      if (this.#jkt && this.#jkt !== jkt) throw new PortalError('registration_key_changed');
      this.#jkt = jkt;
      return key;
    } catch (failure) {
      if (!isAborted(failure)) this.dispose();
      throw failure;
    }
  }
  async start(values: RegistrationValues, signal: AbortSignal): Promise<RegistrationAttempt> {
    if (
      this.#authority ||
      Object.keys(values).sort().join(',') !== 'email,phone' ||
      Object.keys(validateRegistration(values)).length
    )
      throw new PortalError('invalid_request');
    const requestedAt = Date.now();
    return this.request(
      'start',
      { email: values.email, phone: values.phone },
      (value) => {
        const item = exact(value, [
          'attempt_id',
          'capability',
          'canonical_email',
          'expires_at',
          'email_sent',
        ]);
        const expires_at = timestamp(item.expires_at);
        const email = canonicalEmail(item.canonical_email);
        if (
          typeof item.email_sent !== 'boolean' ||
          Date.parse(expires_at) <= Date.now() ||
          Date.parse(expires_at) > requestedAt + 920000
        )
          throw new PortalError('invalid_response');
        this.#authority = {
          attempt_id: id(item.attempt_id),
          capability: secret(item.capability),
          expires_at,
          email,
        };
        this.#pendingMonotonic = performance.now() + Date.parse(expires_at) - Date.now();
        return { canonical_email: email, expires_at, email_sent: item.email_sent };
      },
      signal,
      true
    );
  }
  verifyEmail(proof: EmailProof, signal: AbortSignal): Promise<void> {
    if (Object.keys(proof).sort().join(',') !== 'attempt_id,token')
      return Promise.reject(new PortalError('invalid_request'));
    try {
      id(proof.attempt_id);
      secret(proof.token);
    } catch {
      return Promise.reject(new PortalError('invalid_request'));
    }
    return this.request(
      'email/verify',
      { attempt_id: proof.attempt_id, token: proof.token },
      emptyResponse,
      signal
    );
  }
  resendEmail(signal: AbortSignal): Promise<void> {
    this.#verification = undefined;
    this.#handle = undefined;
    return this.request('email/resend', this.authority(), emptyResponse, signal);
  }
  async sendPhone(signal: AbortSignal): Promise<void> {
    this.#verification = undefined;
    this.#handle = undefined;
    const wall = Date.now() + 180000;
    const monotonic = performance.now() + 180000;
    await this.request(
      'phone/send',
      this.authority(),
      (value) => {
        this.#verification = {
          id: secret(exact(value, ['verification_id']).verification_id),
          wall,
          monotonic,
          failures: 0,
        };
      },
      signal
    );
  }
  hasPhoneVerification(): boolean {
    if (
      this.#verification &&
      (Date.now() >= this.#verification.wall || performance.now() >= this.#verification.monotonic)
    )
      this.#verification = undefined;
    return Boolean(this.#verification);
  }
  async verifyPhone(code: string, signal: AbortSignal): Promise<void> {
    if (!/^[0-9]{6}$/.test(code) || !this.hasPhoneVerification() || !this.#verification)
      throw new PortalError('invalid_request');
    const verification = this.#verification;
    // Only a definitive incorrect-code rejection can retain the same challenge.
    this.#verification = undefined;
    try {
      await this.request(
        'phone/verify',
        { ...this.authority(), verification_id: verification.id, code },
        emptyResponse,
        signal
      );
    } catch (failure) {
      if (
        failure instanceof PortalError &&
        failure.code === 'proof_required' &&
        failure.status === 409 &&
        !failure.uncertain &&
        !signal.aborted &&
        !this.#lifetime.signal.aborted &&
        ++verification.failures < 3 &&
        Date.now() < verification.wall &&
        performance.now() < verification.monotonic
      )
        this.#verification = verification;
      throw failure;
    }
  }
  passkeyOptions(signal: AbortSignal): Promise<unknown> {
    const authority = this.authority();
    return this.request(
      'passkey/options',
      authority,
      (value) => {
        const envelope = exact(value, ['publicKey']);
        const options = record(envelope.publicKey);
        const required = [
          'rp',
          'user',
          'challenge',
          'pubKeyCredParams',
          'timeout',
          'authenticatorSelection',
        ];
        if (
          required.some((key) => !Object.hasOwn(options, key)) ||
          Object.keys(options).some(
            (key) =>
              ![...required, 'attestation', 'excludeCredentials', 'extensions', 'hints'].includes(
                key
              )
          )
        )
          throw new PortalError('invalid_response');
        const user = exact(options.user, ['id', 'name', 'displayName']);
        const rp = exact(options.rp, ['id', 'name']);
        const selection = record(options.authenticatorSelection);
        if (
          Object.keys(selection).some(
            (key) =>
              ![
                'residentKey',
                'requireResidentKey',
                'userVerification',
                'authenticatorAttachment',
              ].includes(key)
          ) ||
          selection.residentKey !== 'required' ||
          selection.requireResidentKey !== true ||
          selection.userVerification !== 'required' ||
          user.name !== this.#authority?.email ||
          user.displayName !== user.name ||
          unbase64url(user.id, 8).byteLength !== 8 ||
          (this.#handle && this.#handle !== user.id) ||
          typeof rp.id !== 'string' ||
          !/^[a-z0-9.-]{1,253}$/.test(rp.id) ||
          (new URL(this.origin).hostname !== rp.id &&
            !new URL(this.origin).hostname.endsWith(`.${rp.id}`)) ||
          typeof options.timeout !== 'number' ||
          !Number.isSafeInteger(options.timeout) ||
          options.timeout <= 0 ||
          options.timeout > 300000
        )
          throw new PortalError('invalid_response');
        if (
          options.extensions !== undefined &&
          exact(options.extensions, ['credProps']).credProps !== true
        )
          throw new PortalError('invalid_response');
        if (
          options.hints !== undefined ||
          (options.excludeCredentials !== undefined &&
            (!Array.isArray(options.excludeCredentials) || options.excludeCredentials.length !== 0))
        )
          throw new PortalError('invalid_response');
        if (!Array.isArray(options.pubKeyCredParams) || options.pubKeyCredParams.length === 0)
          throw new PortalError('invalid_response');
        for (const param of options.pubKeyCredParams) exact(param, ['type', 'alg']);
        creationOptions(value);
        this.#handle = user.id as string;
        return value;
      },
      signal
    );
  }
  complete(credential: unknown, signal: AbortSignal): Promise<RegistrationOutcome> {
    const authority = this.authority();
    if (!this.#handle) return Promise.reject(new PortalError('proof_required'));
    try {
      const item = record(credential);
      if (
        ['id', 'rawId', 'type', 'response'].some((key) => !Object.hasOwn(item, key)) ||
        Object.keys(item).some(
          (key) =>
            ![
              'id',
              'rawId',
              'type',
              'response',
              'authenticatorAttachment',
              'clientExtensionResults',
            ].includes(key)
        ) ||
        item.type !== 'public-key' ||
        item.id !== item.rawId
      )
        throw new PortalError('invalid_request');
      unbase64url(item.id, 1024);
      const response = record(item.response);
      if (
        !Object.hasOwn(response, 'clientDataJSON') ||
        !Object.hasOwn(response, 'attestationObject') ||
        Object.keys(response).some(
          (key) => !['clientDataJSON', 'attestationObject', 'transports'].includes(key)
        )
      )
        throw new PortalError('invalid_request');
      unbase64url(response.clientDataJSON);
      unbase64url(response.attestationObject);
      if (
        response.transports !== undefined &&
        (!Array.isArray(response.transports) ||
          response.transports.length > 5 ||
          response.transports.some(
            (value) => !['usb', 'nfc', 'ble', 'internal', 'hybrid'].includes(value)
          ))
      )
        throw new PortalError('invalid_request');
      if (
        item.authenticatorAttachment !== undefined &&
        item.authenticatorAttachment !== null &&
        !['platform', 'cross-platform'].includes(String(item.authenticatorAttachment))
      )
        throw new PortalError('invalid_request');
      if (item.clientExtensionResults !== undefined) {
        const extensions = record(item.clientExtensionResults);
        if (
          Object.keys(extensions).some((key) => key !== 'credProps') ||
          (extensions.credProps !== undefined && exact(extensions.credProps, ['rk']).rk !== true)
        )
          throw new PortalError('invalid_request');
      }
    } catch {
      return Promise.reject(new PortalError('invalid_request'));
    }
    this.#handle = undefined;
    this.#recoverUntil = Date.now() + 3600000;
    this.#recoverMonotonic = performance.now() + 3600000;
    return this.request(
      '',
      { ...authority, credential },
      (value) => {
        const result = this.outcome(value);
        if (result.state !== 'completed') throw new PortalError('invalid_response');
        return result;
      },
      signal
    );
  }
  result(signal: AbortSignal): Promise<RegistrationOutcome> {
    return this.request('result', this.authority(true), (value) => this.outcome(value), signal);
  }
  private authority(receipt = false) {
    const a = this.#authority;
    if (!a) throw new PortalError('invalid_registration');
    if (
      (Date.now() >= Date.parse(a.expires_at) || performance.now() >= this.#pendingMonotonic) &&
      !(receipt && Date.now() < this.#recoverUntil && performance.now() < this.#recoverMonotonic)
    ) {
      this.dispose();
      throw new PortalError('registration_expired');
    }
    return { attempt_id: a.attempt_id, capability: a.capability };
  }
  private outcome(value: unknown): RegistrationOutcome {
    const item = record(value);
    if (item.state === 'completed') {
      exact(item, ['state', 'next', 'receipt_expires_at', 'email_verified', 'phone_verified']);
      const expiry = timestamp(item.receipt_expires_at);
      if (
        item.next !== 'login' ||
        item.email_verified !== true ||
        item.phone_verified !== true ||
        Date.parse(expiry) <= Date.now() ||
        Date.parse(expiry) > Date.now() + 3600000
      )
        throw new PortalError('invalid_response');
      return {
        state: 'completed',
        next: 'login',
        receipt_expires_at: expiry,
        email_verified: true,
        phone_verified: true,
      };
    }
    if (item.state === 'failed') {
      exact(item, ['state', 'receipt_expires_at', 'email_verified', 'phone_verified']);
      timestamp(item.receipt_expires_at);
    } else exact(item, ['state', 'expires_at', 'email_verified', 'phone_verified']);
    if (
      !['pending', 'failed'].includes(String(item.state)) ||
      (item.state === 'pending' && item.expires_at !== this.#authority?.expires_at) ||
      typeof item.email_verified !== 'boolean' ||
      typeof item.phone_verified !== 'boolean' ||
      (item.phone_verified && !item.email_verified)
    )
      throw new PortalError('invalid_response');
    if (item.state === 'pending') {
      this.#recoverUntil = 0;
      this.#recoverMonotonic = 0;
      if (
        Date.now() >= Date.parse(item.expires_at as string) ||
        performance.now() >= this.#pendingMonotonic
      )
        throw new PortalError('registration_expired');
    }
    return item as RegistrationOutcome;
  }
  private async request<T>(
    operation:
      | 'start'
      | 'email/resend'
      | 'email/verify'
      | 'phone/send'
      | 'phone/verify'
      | 'passkey/options'
      | ''
      | 'result',
    payload: unknown,
    decode: (value: unknown) => T,
    signal: AbortSignal,
    initialize = false
  ): Promise<T> {
    throwIfAborted(signal);
    throwIfAborted(this.#lifetime.signal);
    if (this.#busy) throw new PortalError('registration_busy');
    this.#busy = true;
    const url = `${this.origin}${root}${operation ? `/${operation}` : ''}`;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const signals = [signal, this.#lifetime.signal];
    for (const input of signals) input.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 20000);
    let sent = false;
    let response: Response | undefined;
    try {
      const body = JSON.stringify(payload);
      if (new TextEncoder().encode(body).length > 64 * 1024)
        throw new PortalError('invalid_request');
      let nonce: string | undefined;
      for (let attempt = 0; attempt < 2; attempt++) {
        const key = await this.assertKey(controller.signal, initialize && attempt === 0);
        const proof = await signProof(key, 'POST', url, nonce);
        // Re-read persisted key after signing, before transmitting old authority.
        await this.assertKey(controller.signal);
        sent = true;
        response = await this.fetcher(url, {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json', DPoP: proof },
          body,
          credentials: 'omit',
          mode: 'cors',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          signal: controller.signal,
        });
        if (response.redirected || (response.url && response.url !== url))
          throw new PortalError('invalid_response');
        const value = await readResponse(response, controller.signal);
        await this.assertKey(controller.signal);
        if (response.ok) {
          const status =
            operation === 'start'
              ? 201
              : ['email/resend', 'email/verify', 'phone/verify'].includes(operation)
                ? 204
                : 200;
          if (response.status !== status) throw new PortalError('invalid_response');
          return decode(value);
        }
        const error = exact(value, ['error']).error;
        if (typeof error !== 'string' || !/^[a-z_]{1,80}$/.test(error))
          throw new PortalError('invalid_response');
        const challenge = response.headers.get('DPoP-Nonce');
        if (
          attempt === 0 &&
          response.status === 401 &&
          error === 'use_dpop_nonce' &&
          /^DPoP[ \t]+error="use_dpop_nonce"$/i.test(
            response.headers.get('WWW-Authenticate') ?? ''
          ) &&
          challenge &&
          /^[A-Za-z0-9._~-]{1,1024}$/.test(challenge)
        ) {
          nonce = challenge;
          continue;
        }
        throw new PortalError(
          error,
          response.status,
          operation === '' && response.status >= 500,
          parseRetryAfter(response.headers.get('Retry-After'))
        );
      }
      throw new PortalError('use_dpop_nonce', 401);
    } catch (failure) {
      if (
        failure instanceof PortalError &&
        ['registration_key_changed', 'key_unavailable'].includes(failure.code)
      )
        throw failure;
      if (signal.aborted || this.#lifetime.signal.aborted) {
        this.dispose();
        throwIfAborted(signal);
        throwIfAborted(this.#lifetime.signal);
      }
      const error = failure instanceof PortalError ? failure : new PortalError('network_error');
      if (
        [
          'invalid_registration',
          'registration_expired',
          'registration_conflict',
          'restart_registration',
          'invalid_dpop_proof',
        ].includes(error.code)
      )
        this.dispose();
      throw new PortalError(
        error.code,
        error.status || response?.status || 0,
        error.uncertain ||
          (operation === '' &&
            sent &&
            (!response || response.status < 400 || response.status >= 500)),
        error.retryAfterSeconds
      );
    } finally {
      this.#busy = false;
      clearTimeout(timer);
      for (const input of signals) input.removeEventListener('abort', abort);
    }
  }
}
