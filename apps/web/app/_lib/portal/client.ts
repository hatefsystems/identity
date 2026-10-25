import { browserKey, signProof, type BrowserKey } from './dpop';
import { isSessionLoss, PortalError, throwIfAborted } from './errors';
import {
  passkeyResponse,
  profileResponse,
  recoveryBatchResponse,
  recoveryStatusResponse,
  sessionsResponse,
  stepUpChallengeResponse,
  StepUpGrant,
  type Profile,
} from './contracts';
import { identifier, list, normalizeName, record } from './validation';

type RequestOptions = {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
  anonymous?: boolean;
  grant?: StepUpGrant;
  onSend?: () => void;
};
type Decoder<T> = (value: unknown) => T;
const emptyResponse = (value: unknown): void => {
  if (value !== undefined) throw new PortalError('invalid_response');
};
const responseLimit = 256 * 1024;

async function readResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  if (response.status === 204) return undefined;
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > responseLimit)) {
    await response.body?.cancel();
    throw new PortalError('invalid_response');
  }
  if (
    !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') ||
    !response.body
  ) {
    await response.body?.cancel();
    throw new PortalError('invalid_response');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      throwIfAborted(signal);
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > responseLimit) {
        await reader.cancel();
        throw new PortalError('invalid_response');
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    reader.releaseLock();
  }
}

export class PortalClient {
  #lifetime = new AbortController();
  #profile?: Profile;
  readonly origin: string;
  private readonly fetcher: typeof fetch;
  private readonly getKey: () => Promise<BrowserKey>;
  onSessionLoss?: (error: PortalError) => void;

  constructor(
    options: { origin?: string; fetcher?: typeof fetch; getKey?: () => Promise<BrowserKey> } = {}
  ) {
    this.origin = options.origin ?? window.location.origin;
    const origin = new URL(this.origin);
    if (origin.origin !== this.origin || !['https:', 'http:'].includes(origin.protocol))
      throw new PortalError('invalid_origin');
    this.fetcher = options.fetcher ?? ((...args) => fetch(...args));
    this.getKey = options.getKey ?? (() => browserKey(false, this.#lifetime.signal));
  }

  get profile(): Profile | undefined {
    return this.#profile;
  }

  assertSession(): Profile {
    throwIfAborted(this.#lifetime.signal);
    if (!this.#profile || Date.now() >= Date.parse(this.#profile.session.expires_at)) {
      const error = new PortalError('session_expired', 401);
      this.onSessionLoss?.(error);
      throw error;
    }
    return this.#profile;
  }

  dispose(): void {
    this.#profile = undefined;
    this.#lifetime.abort();
  }

  async request<T>(path: string, decode: Decoder<T>, options: RequestOptions = {}): Promise<T> {
    const method = options.method ?? 'GET';
    const mutation = method !== 'GET';
    const url = new URL(path, this.origin);
    if (
      !/^\/api\/v1\/[A-Za-z0-9/_-]+$/.test(path) ||
      url.origin !== this.origin ||
      url.pathname !== path ||
      url.search ||
      url.hash
    )
      throw new PortalError('invalid_request');
    const snapshot = options.anonymous ? this.#profile : this.assertSession();
    throwIfAborted(options.signal);
    throwIfAborted(this.#lifetime.signal);
    const controller = new AbortController();
    const abort = () => controller.abort();
    const signals = [options.signal, this.#lifetime.signal].filter(
      (signal): signal is AbortSignal => Boolean(signal)
    );
    for (const signal of signals) signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 20000);
    let sent = false;
    let response: Response | undefined;
    try {
      const body = options.body === undefined ? undefined : JSON.stringify(options.body);
      if (body !== undefined && new TextEncoder().encode(body).length > 64 * 1024)
        throw new PortalError('invalid_request');
      const headers = new Headers({ Accept: 'application/json' });
      if (body !== undefined) headers.set('Content-Type', 'application/json');
      if (snapshot) headers.set('X-Portal-Session', snapshot.session.id);
      // take() clears the grant before any transmission. Only the explicit
      // pre-handler nonce branch below may resend this same logical operation.
      if (options.grant)
        headers.set('X-Step-Up-Auth', options.grant.take(this.assertSession().session.id));
      let nonce: string | undefined;
      for (let attempt = 0; attempt < 2; attempt++) {
        const key = await this.getKey();
        throwIfAborted(controller.signal);
        headers.set('DPoP', await signProof(key, method, url.href, nonce));
        throwIfAborted(controller.signal);
        if (!sent) options.onSend?.();
        sent = true;
        response = await this.fetcher(url.href, {
          method,
          headers: new Headers(headers),
          body,
          credentials: 'same-origin',
          // Fetch otherwise replaces unsafe-request Origin with null when
          // no-referrer is used. URL/path checks still forbid cross-origin targets.
          mode: 'cors',
          cache: 'no-store',
          redirect: 'error',
          referrerPolicy: 'no-referrer',
          signal: controller.signal,
        });
        if (response.redirected || (response.url && response.url !== url.href))
          throw new PortalError('invalid_response');
        const value = await readResponse(response, controller.signal);
        throwIfAborted(controller.signal);
        if (response.ok) {
          if (snapshot && this.#profile?.session.id !== snapshot.session.id)
            throw new PortalError('session_changed', 409);
          return decode(value);
        }
        const code =
          typeof record(value).error === 'string' &&
          /^[a-z_]{1,80}$/.test(record(value).error as string)
            ? (record(value).error as string)
            : 'request_failed';
        const challenge = response.headers.get('DPoP-Nonce');
        if (
          attempt === 0 &&
          response.status === 401 &&
          code === 'use_dpop_nonce' &&
          /\bDPoP\s+error="use_dpop_nonce"/i.test(response.headers.get('WWW-Authenticate') ?? '') &&
          challenge &&
          /^[A-Za-z0-9._~-]{1,1024}$/.test(challenge)
        ) {
          nonce = challenge;
          continue;
        }
        throw new PortalError(code, response.status, mutation && response.status >= 500);
      }
      throw new PortalError('use_dpop_nonce', 401);
    } catch (failure) {
      for (const signal of signals) throwIfAborted(signal);
      const error =
        failure instanceof PortalError
          ? failure
          : new PortalError('network_error', response?.status ?? 0, sent && mutation);
      // An unreadable success body is also an uncertain mutation, not a reason
      // to replay an authenticator response or silently replace recovery codes.
      const reported =
        error.code === 'invalid_response' &&
        sent &&
        mutation &&
        (!response || response.status < 400 || response.status >= 500)
          ? new PortalError(error.code, response?.status ?? 0, true)
          : error;
      if (isSessionLoss(reported)) this.onSessionLoss?.(reported);
      throw reported;
    } finally {
      clearTimeout(timer);
      for (const signal of signals) signal.removeEventListener('abort', abort);
    }
  }

  async bootstrap(signal?: AbortSignal): Promise<Profile> {
    const result = await this.request('/api/v1/users/me', profileResponse, {
      signal,
      anonymous: true,
    });
    if (
      this.#profile &&
      (result.session.id !== this.#profile.session.id || result.id !== this.#profile.id)
    ) {
      const error = new PortalError('session_changed', 409);
      this.onSessionLoss?.(error);
      throw error;
    }
    this.#profile = result;
    return this.assertSession();
  }

  async saveProfile(displayName: string, revision: string, signal?: AbortSignal): Promise<Profile> {
    const result = await this.request('/api/v1/users/me', profileResponse, {
      method: 'PATCH',
      body: { display_name: normalizeName(displayName), expected_revision: revision },
      signal,
    });
    const snapshot = this.assertSession();
    if (result.id !== snapshot.id || result.session.id !== snapshot.session.id) {
      const error = new PortalError('session_changed', 409);
      this.onSessionLoss?.(error);
      throw error;
    }
    this.#profile = result;
    return result;
  }

  loginOptions(signal: AbortSignal) {
    return this.request('/api/v1/auth/webauthn/login/generate-options', record, {
      method: 'POST',
      body: {},
      signal,
      anonymous: true,
    });
  }
  loginVerify(assertion: unknown, signal: AbortSignal) {
    return this.request('/api/v1/auth/webauthn/login/verify', emptyResponse, {
      method: 'POST',
      body: assertion,
      signal,
      anonymous: true,
    });
  }
  keys(signal: AbortSignal) {
    return this.request('/api/v1/auth/webauthn/keys', (value) => list(value, passkeyResponse), {
      signal,
    });
  }
  registerOptions(name: string, grant: StepUpGrant, signal: AbortSignal) {
    return this.request('/api/v1/auth/webauthn/register/generate-options', record, {
      method: 'POST',
      body: { name: normalizeName(name) },
      grant,
      signal,
    });
  }
  registerVerify(attestation: unknown, signal: AbortSignal, onSend?: () => void) {
    return this.request('/api/v1/auth/webauthn/register/verify', passkeyResponse, {
      method: 'POST',
      body: attestation,
      signal,
      onSend,
    });
  }
  renameKey(
    id: string,
    name: string,
    grant: StepUpGrant,
    signal: AbortSignal,
    onSend?: () => void
  ) {
    return this.request(`/api/v1/auth/webauthn/keys/${identifier(id, 1400)}`, passkeyResponse, {
      method: 'PATCH',
      body: { name: normalizeName(name) },
      grant,
      signal,
      onSend,
    });
  }
  removeKey(id: string, grant: StepUpGrant, signal: AbortSignal, onSend?: () => void) {
    return this.request(`/api/v1/auth/webauthn/keys/${identifier(id, 1400)}`, emptyResponse, {
      method: 'DELETE',
      grant,
      signal,
      onSend,
    });
  }
  sessions(signal: AbortSignal) {
    return this.request('/api/v1/users/me/sessions', sessionsResponse, { signal });
  }
  revokeSession(id: string, signal?: AbortSignal) {
    return this.request(`/api/v1/users/me/sessions/${identifier(id)}`, emptyResponse, {
      method: 'DELETE',
      signal,
    });
  }
  logout(signal?: AbortSignal) {
    return this.request('/api/v1/auth/logout', emptyResponse, { method: 'POST', body: {}, signal });
  }
  recoveryStatus(signal: AbortSignal) {
    return this.request('/api/v1/auth/recovery-codes/status', recoveryStatusResponse, { signal });
  }
  generateRecovery(grant: StepUpGrant, signal: AbortSignal) {
    return this.request('/api/v1/auth/recovery-codes/generate', recoveryBatchResponse, {
      method: 'POST',
      body: {},
      grant,
      signal,
    });
  }
  stepUpChallenge(signal: AbortSignal) {
    return this.request('/api/v1/auth/stepup/challenge', stepUpChallengeResponse, {
      method: 'POST',
      body: {},
      signal,
    });
  }
  stepUpVerify(
    body: { method: 'webauthn'; assertion: unknown } | { method: 'totp'; code: string },
    signal: AbortSignal
  ) {
    const profile = this.assertSession();
    const requestedAt = Date.now();
    return this.request(
      '/api/v1/auth/stepup/verify',
      (value) =>
        new StepUpGrant(
          value,
          profile.session.id,
          requestedAt,
          Date.parse(profile.session.expires_at)
        ),
      { method: 'POST', body, signal }
    );
  }
}
