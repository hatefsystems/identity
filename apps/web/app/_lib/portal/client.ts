import { isLocale, type Locale } from '../../../i18n/config';
import { browserKey, signProof, type BrowserKey } from './dpop';
import { FirstPasskeyError, isSessionLoss, parseRetryAfter, PortalError, throwIfAborted, type FirstPasskeyPhase } from './errors';
import {
  passkeyResponse,
  passkeyListEntryResponse,
  profileResponse,
  recoveryBatchResponse,
  recoveryStatusResponse,
  sessionsResponse,
  stepUpChallengeResponse,
  StepUpGrant,
  firstPasskeyAuthorityResponse,
  firstPasskeyResponse,
  type FirstPasskeyAuthority,
  type FirstPasskeyChannel,
  type Profile,
} from './contracts';
import { identifier, list, normalizeName, record, timestamp } from './validation';
import { emptyResponse, readResponse } from './json-response';
import { nonzeroUUID } from '../admin/validation';
import { createPasskey, firstPasskeyCreationOptions } from './webauthn';

type RequestOptions = {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  query?: Readonly<Record<string, string | number | undefined>>;
  body?: unknown;
  signal?: AbortSignal;
  anonymous?: boolean;
  grant?: StepUpGrant;
  onSend?: () => void;
  idempotencyKey?: string;
  notificationLocale?: Locale;
};
type Decoder<T> = (value: unknown, status: number) => T;
type FirstPasskeyBinding = {
  userID: string;
  sessionID: string;
  keyID: string;
  wall: number;
  monotonic: number;
};
type FirstPasskeyState = FirstPasskeyAuthority & {
  binding: FirstPasskeyBinding;
} & (
  | { stage: 'challenge' | 'proof'; token: string }
  | { stage: 'native'; options: PublicKeyCredentialCreationOptions }
  | { stage: 'finish'; attestation: unknown }
);
type FirstPasskeyRequestOptions = RequestOptions & {
  firstPasskey?: { binding: FirstPasskeyBinding; proof?: string };
};
export type LoginMfa = { status: 'mfa_required'; preauthentication: string; expires_at: string };
export type SecurityChange =
  | 'passkeyAdded' | 'passkeyRemoved' | 'totpEnabled' | 'totpDisabled'
  | 'phoneVerified' | 'phoneRemoved';

const adminQueryKeys: Readonly<Record<string, readonly string[]>> = {
  '/api/v1/admin/users': ['limit', 'offset', 'status'],
  '/api/v1/admin/audit-logs': ['start_time', 'end_time', 'event_type', 'limit', 'before_seq'],
  '/api/v1/admin/audit-logs/verify': ['after_seq', 'through_seq', 'predecessor_hash', 'limit'],
  '/api/v1/admin/ledger/verify': ['after_seq', 'through_seq', 'predecessor_hash', 'limit'],
  '/api/v1/admin/legal-holds': ['account_ref', 'status', 'limit', 'offset'],
};

export class PortalClient {
  #lifetime = new AbortController();
  #profile?: Profile;
  #securityRequests = new Set<{
    sent: boolean;
    preserved: boolean;
    controller: AbortController;
    detach: () => void;
  }>();
  #pendingSessionLoss?: PortalError;
  #firstPasskey?: FirstPasskeyState;
  #firstPasskeyBusy = false;
  #firstPasskeyController?: AbortController;
  #firstPasskeyTimer?: ReturnType<typeof setTimeout>;
  #firstPasskeyDetach?: () => void;
  readonly origin: string;
  private readonly fetcher: typeof fetch;
  private readonly getKey: () => Promise<BrowserKey>;
  onSessionLoss?: (error: PortalError, settlingSecurity?: boolean) => void;
  onSecurityChange?: (outcome: SecurityChange) => void;

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
      this.loseSession(error);
      throw error;
    }
    return this.#profile;
  }

  dispose(): void {
    this.clearFirstPasskey();
    this.#profile = undefined;
    this.#pendingSessionLoss = undefined;
    this.#lifetime.abort();
    for (const request of this.#securityRequests) request.controller.abort();
  }

  private loseSession(error: PortalError): void {
    if (this.#pendingSessionLoss) return;
    const pending = [...this.#securityRequests].filter(
      (request) => request.sent && !request.controller.signal.aborted
    );
    if (pending.length) {
      this.#pendingSessionLoss = error;
      for (const request of pending) {
        request.preserved = true;
        request.detach();
      }
      // Withdraw authority now, preserving only bounded, already-sent responses.
      // Dialog teardown cannot cancel them, but explicit disposal still can.
      this.#profile = undefined;
      this.clearFirstPasskey();
      this.#lifetime.abort();
    } else this.clearFirstPasskey();
    this.onSessionLoss?.(error, pending.length > 0);
  }

  request<T>(path: string, decode: Decoder<T>, options: RequestOptions = {}): Promise<T> {
    // First-purpose authority can only enter transport from the owning methods.
    if ('firstPasskey' in options) return Promise.reject(new PortalError('invalid_request'));
    return this.#sendRequest(path, decode, options);
  }

  async #sendRequest<T>(path: string, decode: Decoder<T>, options: FirstPasskeyRequestOptions = {}): Promise<T> {
    const method = options.method ?? 'GET';
    const firstPasskey = options.firstPasskey;
    if (firstPasskey && (options.anonymous || options.grant || method !== 'POST' ||
      (firstPasskey.proof !== undefined && path !== '/api/v1/auth/webauthn/register/generate-options') ||
      !['/api/v1/auth/action-proofs/first-passkey/challenge',
        '/api/v1/auth/action-proofs/first-passkey/verify',
        '/api/v1/auth/webauthn/register/generate-options',
        '/api/v1/auth/webauthn/register/verify'].includes(path)))
      throw new PortalError('invalid_request');
    const notificationLocale = options.notificationLocale;
    const mutation = method !== 'GET';
    const legalLookup = method === 'POST' && path === '/api/v1/admin/legal-inquiry/lookup';
    const legalCreate =
      method === 'POST' &&
      (path === '/api/v1/admin/legal-holds' || path === '/api/v1/admin/preservation-requests');
    const uncertainMutation = mutation && !legalLookup;
    if (
      typeof path !== 'string' ||
      !/^\/api\/v1\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(path) ||
      !['GET', 'POST', 'PATCH', 'DELETE'].includes(method) ||
      (!mutation && options.body !== undefined)
    )
      throw new PortalError('invalid_request');
    // Presentation authority is confined to the single notification-producing route.
    if (
      notificationLocale !== undefined &&
      (path !== '/api/v1/users/me' || method !== 'DELETE' || !isLocale(notificationLocale))
    )
      throw new PortalError('invalid_request');
    let idempotencyKey: string | undefined;
    if (options.idempotencyKey !== undefined) {
      if (!legalCreate) throw new PortalError('invalid_request');
      try {
        idempotencyKey = nonzeroUUID(options.idempotencyKey);
      } catch {
        throw new PortalError('invalid_request');
      }
    }
    const url = new URL(path, this.origin);
    if (url.origin !== this.origin || url.pathname !== path || url.search || url.hash)
      throw new PortalError('invalid_request');
    if (options.query !== undefined) {
      const allowed = Object.hasOwn(adminQueryKeys, path) ? adminQueryKeys[path] : undefined;
      const query = options.query;
      if (
        mutation ||
        !allowed ||
        !query ||
        (Object.getPrototypeOf(query) !== Object.prototype && Object.getPrototypeOf(query) !== null)
      )
        throw new PortalError('invalid_request');
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        if (!allowed.includes(key)) throw new PortalError('invalid_request');
        if (value === undefined) continue;
        if (path === '/api/v1/admin/legal-holds') {
          try {
            if (key === 'account_ref') nonzeroUUID(value);
            else if (key === 'status' && !['active', 'released', 'all'].includes(String(value)))
              throw new PortalError('invalid_request');
            else if (
              (key === 'limit' || key === 'offset') &&
              (!/^(0|[1-9][0-9]*)$/.test(String(value)) || Number(value) > 2147483647)
            )
              throw new PortalError('invalid_request');
          } catch {
            throw new PortalError('invalid_request');
          }
        }
        if (
          (typeof value !== 'string' && typeof value !== 'number') ||
          (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) ||
          (key.endsWith('_seq') &&
            (typeof value !== 'string' ||
              !/^(0|[1-9][0-9]{0,18})$/.test(value) ||
              value.trim() !== value ||
              (value.length === 19 && value > '9223372036854775807'))) ||
          String(value).length > 128 ||
          /[\p{Cc}\p{Cs}]/u.test(String(value))
        )
          throw new PortalError('invalid_request');
        params.set(key, String(value));
      }
      url.search = params.toString();
    }
    // The browser fetches the full query, but the server binds DPoP to htu
    // without query/fragment. No caller can widen another route's body budget.
    const proofURL = `${url.origin}${url.pathname}`;
    const responseLimit =
      (method === 'GET' &&
        (path === '/api/v1/admin/audit-logs' || path === '/api/v1/admin/legal-holds')) ||
      legalLookup
        ? 4 * 1024 * 1024
        : undefined;
    let securityTarget: SecurityChange | undefined;
    if (!options.anonymous) {
      if (method === 'POST' && path === '/api/v1/auth/webauthn/register/verify')
        securityTarget = 'passkeyAdded';
      else if (method === 'DELETE' && /^\/api\/v1\/auth\/webauthn\/keys\/[^/]+$/.test(path))
        securityTarget = 'passkeyRemoved';
      else if (method === 'POST' && path === '/api/v1/auth/mfa/verify')
        securityTarget = 'totpEnabled';
      else if (method === 'DELETE' && path === '/api/v1/auth/mfa')
        securityTarget = 'totpDisabled';
      else if (method === 'POST' && path === '/api/v1/users/me/phone/verify')
        securityTarget = 'phoneVerified';
      else if (method === 'DELETE' && path === '/api/v1/users/me/phone')
        securityTarget = 'phoneRemoved';
    }
    const snapshot = options.anonymous ? this.#profile : this.assertSession();
    throwIfAborted(options.signal);
    throwIfAborted(this.#lifetime.signal);
    const controller = new AbortController();
    const abort = () => controller.abort();
    const signals = [options.signal, this.#lifetime.signal].filter(
      (signal): signal is AbortSignal => Boolean(signal)
    );
    for (const signal of signals) signal.addEventListener('abort', abort, { once: true });
    const securityRequest = securityTarget ? {
      sent: false,
      preserved: false,
      controller,
      detach: () => {
        for (const signal of signals) signal.removeEventListener('abort', abort);
      },
    } : undefined;
    const timer = setTimeout(abort, 20000);
    let sent = false;
    let response: Response | undefined;
    let securityChange: SecurityChange | undefined;
    try {
      let body: string | undefined;
      try {
        body = options.body === undefined ? undefined : JSON.stringify(options.body);
      } catch {
        throw new PortalError('invalid_request');
      }
      if (
        body !== undefined &&
        new TextEncoder().encode(body).length > (firstPasskey && path.includes('/action-proofs/') ? 8 :
          legalCreate || legalLookup ? 32 : 64) * 1024
      )
        throw new PortalError('invalid_request');
      const headers = new Headers({ Accept: 'application/json' });
      if (body !== undefined) headers.set('Content-Type', 'application/json');
      if (idempotencyKey !== undefined) headers.set('Idempotency-Key', idempotencyKey);
      if (notificationLocale !== undefined)
        headers.set('X-Hatef-Notification-Locale', notificationLocale);
      if (snapshot) headers.set('X-Portal-Session', snapshot.session.id);
      // take() clears the grant before any transmission. Only the explicit
      // pre-handler nonce branch below may resend this same logical operation.
      if (options.grant) {
        if (options.grant instanceof StepUpGrant)
          headers.set('X-Step-Up-Auth', options.grant.take(this.assertSession().session.id));
        else throw new PortalError('invalid_request');
      }
      if (firstPasskey?.proof !== undefined) headers.set('X-Action-Proof', firstPasskey.proof);
      let nonce: string | undefined;
      for (let attempt = 0; attempt < 2; attempt++) {
        throwIfAborted(this.#lifetime.signal);
        const key = await this.getKey();
        throwIfAborted(controller.signal);
        if (this.#firstPasskey && this.firstPasskeyKeyID(key) !== this.#firstPasskey.binding.keyID)
          this.clearFirstPasskey();
        if (firstPasskey) {
          if (this.firstPasskeyKeyID(key) !== firstPasskey.binding.keyID)
            throw new PortalError('key_unavailable');
          this.assertFirstPasskeyBinding(firstPasskey.binding);
        }
        headers.set('DPoP', await signProof(key, method, proofURL, nonce));
        throwIfAborted(controller.signal);
        if (firstPasskey) this.assertFirstPasskeyBinding(firstPasskey.binding);
        if (!sent) options.onSend?.();
        sent = true;
        if (securityRequest) {
          securityRequest.sent = true;
          this.#securityRequests.add(securityRequest);
        }
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
        if (response.redirected || (response.url && response.url !== url.href)) {
          await response.body?.cancel().catch(() => undefined);
          throw new PortalError('invalid_response');
        }
        const value = await readResponse(response, controller.signal, responseLimit);
        throwIfAborted(controller.signal);
        if (response.ok) {
          if (snapshot && this.#profile?.session.id !== snapshot.session.id && !securityRequest?.preserved)
            throw new PortalError('session_changed', 409);
          if (firstPasskey) {
            if (!securityRequest?.preserved) {
              const currentKey = await this.getKey();
              throwIfAborted(controller.signal);
              if (this.firstPasskeyKeyID(currentKey) !== firstPasskey.binding.keyID)
                throw new PortalError('key_unavailable');
            }
            this.assertFirstPasskeyBinding(firstPasskey.binding, securityRequest?.preserved);
          }
          const result = decode(value, response.status);
          if (securityTarget && (
            securityTarget === 'passkeyAdded' || securityTarget === 'passkeyRemoved' ||
            response.headers.get('X-Identity-Auth-Invalidated') === 'true'
          )) securityChange = securityTarget;
          return result;
        }
        const errorCode = record(value).error;
        const code =
          typeof errorCode === 'string' &&
          /^[a-z_]{1,80}$/.test(errorCode) &&
          errorCode.trim() === errorCode
            ? errorCode
            : 'request_failed';
        const challenge = response.headers.get('DPoP-Nonce');
        if (
          attempt === 0 &&
          response.status === 401 &&
          code === 'use_dpop_nonce' &&
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
          code,
          response.status,
          uncertainMutation && response.status >= 500,
          parseRetryAfter(response.headers.get('Retry-After'))
        );
      }
      throw new PortalError('use_dpop_nonce', 401);
    } catch (failure) {
      if (!securityRequest?.preserved) {
        if (!firstPasskey) for (const signal of signals) throwIfAborted(signal);
      }
      const error =
        failure instanceof PortalError
          ? failure
          : new PortalError('network_error', response?.status ?? 0, sent && uncertainMutation);
      // An unreadable success body is also an uncertain mutation, not a reason
      // to replay an authenticator response or silently replace recovery codes.
      const reported = new PortalError(
        error.code,
        error.status || response?.status || 0,
        error.uncertain ||
          (Boolean(firstPasskey) && sent &&
            ['first_passkey_expired', 'session_changed', 'key_unavailable'].includes(error.code)) ||
          (error.code === 'invalid_response' &&
            sent &&
            uncertainMutation &&
            (!response || response.status < 400 || response.status >= 500)),
        error.retryAfterSeconds ?? parseRetryAfter(response?.headers.get('Retry-After') ?? null)
      );
      if (isSessionLoss(reported)) this.loseSession(reported);
      throw reported;
    } finally {
      clearTimeout(timer);
      for (const signal of signals) signal.removeEventListener('abort', abort);
      if (securityRequest) this.#securityRequests.delete(securityRequest);
      if (securityChange) {
        // Decode the committed response before clearing authority. Never refresh
        // a revoked session or reinterpret its subsequent 401 as mutation failure.
        this.dispose();
        this.onSecurityChange?.(securityChange);
      } else if (this.#pendingSessionLoss && this.#securityRequests.size === 0) {
        const failure = this.#pendingSessionLoss;
        this.dispose();
        this.onSessionLoss?.(failure);
      }
    }
  }

  clearFirstPasskey(): void {
    this.#firstPasskey = undefined;
    clearTimeout(this.#firstPasskeyTimer);
    this.#firstPasskeyTimer = undefined;
    this.#firstPasskeyDetach?.();
    this.#firstPasskeyDetach = undefined;
    this.#firstPasskeyController?.abort();
  }

  private keepFirstPasskey(authority: FirstPasskeyState, signal: AbortSignal): void {
    this.#firstPasskey = authority;
    clearTimeout(this.#firstPasskeyTimer);
    this.#firstPasskeyDetach?.();
    const abort = () => this.clearFirstPasskey();
    signal.addEventListener('abort', abort, { once: true });
    this.#firstPasskeyDetach = () => signal.removeEventListener('abort', abort);
    this.#firstPasskeyTimer = setTimeout(() => this.clearFirstPasskey(),
      Math.min(authority.binding.wall - Date.now(), authority.binding.monotonic - performance.now()));
  }

  private firstPasskeyKeyID(key: BrowserKey): string {
    const { crv, kty, x, y } = key.publicJwk;
    return JSON.stringify({ crv, kty, x, y });
  }

  private assertFirstPasskeyBinding(binding: FirstPasskeyBinding, preserved = false): void {
    if (Date.now() >= binding.wall || performance.now() >= binding.monotonic)
      throw new PortalError('first_passkey_expired');
    if (!preserved) {
      const profile = this.assertSession();
      if (profile.id !== binding.userID || profile.session.id !== binding.sessionID)
        throw new PortalError('session_changed', 409);
    }
  }

  private async firstPasskeyOperation<T>(
    phase: FirstPasskeyPhase,
    signal: AbortSignal,
    run: (signal: AbortSignal, ownerSignal: AbortSignal) => Promise<T>
  ): Promise<T> {
    if (this.#firstPasskeyBusy)
      throw new FirstPasskeyError(phase, new PortalError('enrollment_in_progress', 409));
    this.#firstPasskeyBusy = true;
    const controller = new AbortController();
    this.#firstPasskeyController = controller;
    const abort = () => { this.#firstPasskey = undefined; controller.abort(); };
    const signals = [signal, this.#lifetime.signal];
    for (const source of signals) source.addEventListener('abort', abort, { once: true });
    try {
      for (const source of signals) throwIfAborted(source);
      return await run(controller.signal, signal);
    } catch (failure) {
      const error = failure instanceof PortalError ? failure :
        new PortalError(controller.signal.aborted ||
          ((failure instanceof Error || failure instanceof DOMException) && failure.name === 'AbortError')
          ? 'cancelled' : 'request_failed');
      this.clearFirstPasskey();
      throw new FirstPasskeyError(phase, error);
    } finally {
      for (const source of signals) source.removeEventListener('abort', abort);
      this.#firstPasskeyController = undefined;
      this.#firstPasskeyBusy = false;
    }
  }

  firstPasskeyChallenge(password: string, channel: FirstPasskeyChannel, signal: AbortSignal): Promise<FirstPasskeyAuthority> {
    return this.firstPasskeyOperation('challenge', signal, async (signal, ownerSignal) => {
      this.#firstPasskey = undefined;
      clearTimeout(this.#firstPasskeyTimer);
      this.#firstPasskeyDetach?.();
      this.#firstPasskeyDetach = undefined;
      if (typeof password !== 'string' || /\p{Cs}/u.test(password) || !['email', 'sms'].includes(channel))
        throw new PortalError('invalid_request');
      const profile = this.assertSession();
      const wall = Date.now(), monotonic = performance.now();
      const binding: FirstPasskeyBinding = {
        userID: profile.id, sessionID: profile.session.id,
        keyID: this.firstPasskeyKeyID(await this.getKey()),
        // Before issuance is known, allow only the existing transport budget plus
        // the three-minute contact ceiling. The returned deadline replaces it.
        wall: Math.min(wall + 200000, Date.parse(profile.session.expires_at)),
        monotonic: monotonic + Math.min(200000, Date.parse(profile.session.expires_at) - wall),
      };
      return this.#sendRequest('/api/v1/auth/action-proofs/first-passkey/challenge', (value, status) => {
        const result = firstPasskeyAuthorityResponse(value, 'challenge');
        const expiry = Date.parse(result.expires_at);
        if (status !== 202 || expiry > binding.wall || expiry > Date.now() + 180000 || expiry <= Date.now())
          throw new PortalError('invalid_response');
        binding.monotonic = Math.min(binding.monotonic, monotonic + expiry - wall);
        binding.wall = expiry;
        this.assertFirstPasskeyBinding(binding);
        const authority: FirstPasskeyAuthority = { purpose: 'first_passkey_enrollment', expires_at: result.expires_at };
        this.keepFirstPasskey({ ...authority, binding, stage: 'challenge', token: result.token }, ownerSignal);
        return authority;
      }, { method: 'POST', body: { password, channel }, signal, firstPasskey: { binding } });
    });
  }

  firstPasskeyVerify(code: string, signal: AbortSignal): Promise<FirstPasskeyAuthority> {
    return this.firstPasskeyOperation('proof', signal, async (signal, ownerSignal) => {
      const challenge = this.#firstPasskey;
      this.#firstPasskey = undefined;
      if (!challenge || challenge.stage !== 'challenge') throw new PortalError('proof_required');
      if (typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) throw new PortalError('invalid_request');
      this.assertFirstPasskeyBinding(challenge.binding);
      return this.#sendRequest('/api/v1/auth/action-proofs/first-passkey/verify', (value, status) => {
        const result = firstPasskeyAuthorityResponse(value, 'action_proof');
        if (status !== 200 || result.expires_at !== challenge.expires_at)
          throw new PortalError('invalid_response');
        const authority: FirstPasskeyAuthority = { purpose: 'first_passkey_enrollment', expires_at: result.expires_at };
        this.keepFirstPasskey({ ...authority, binding: challenge.binding, stage: 'proof', token: result.token }, ownerSignal);
        return authority;
      }, { method: 'POST', body: { challenge: challenge.token, code }, signal,
        firstPasskey: { binding: challenge.binding } });
    });
  }

  startFirstPasskey(name: string, signal: AbortSignal): Promise<FirstPasskeyAuthority> {
    return this.firstPasskeyOperation('start', signal, async (signal, ownerSignal) => {
      const proof = this.#firstPasskey;
      // Discard before validation, signing or sending. Never refund local proof.
      this.#firstPasskey = undefined;
      if (!proof || proof.stage !== 'proof') throw new PortalError('proof_required');
      this.assertFirstPasskeyBinding(proof.binding);
      return this.#sendRequest('/api/v1/auth/webauthn/register/generate-options', (value, status) => {
        const expires_at = timestamp(record(value).expires_at);
        const expiry = Date.parse(expires_at);
        if (status !== 200 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(expires_at) ||
          new Date(expiry).toISOString().slice(0, 19) !== expires_at.slice(0, 19) ||
          expiry > proof.binding.wall || expiry <= Date.now()) throw new PortalError('invalid_response');
        const binding = { ...proof.binding,
          wall: expiry,
          monotonic: proof.binding.monotonic - (proof.binding.wall - expiry),
        };
        this.assertFirstPasskeyBinding(binding);
        const options = firstPasskeyCreationOptions(value, this.origin,
          Math.min(binding.wall - Date.now(), binding.monotonic - performance.now()));
        const authority: FirstPasskeyAuthority = { purpose: 'first_passkey_enrollment', expires_at };
        this.keepFirstPasskey({ ...authority, binding, stage: 'native', options }, ownerSignal);
        return authority;
      }, { method: 'POST', body: { name: normalizeName(name) }, signal,
        firstPasskey: { binding: proof.binding, proof: proof.token } });
    });
  }

  createFirstPasskey(signal: AbortSignal): Promise<void> {
    return this.firstPasskeyOperation('native', signal, async (signal, ownerSignal) => {
      const ceremony = this.#firstPasskey;
      this.#firstPasskey = undefined;
      if (!ceremony || ceremony.stage !== 'native') throw new PortalError('proof_required');
      this.assertFirstPasskeyBinding(ceremony.binding);
      if (this.firstPasskeyKeyID(await this.getKey()) !== ceremony.binding.keyID)
        throw new PortalError('key_unavailable');
      throwIfAborted(signal);
      this.assertFirstPasskeyBinding(ceremony.binding);
      const remaining = Math.min(ceremony.binding.wall - Date.now(), ceremony.binding.monotonic - performance.now());
      if (remaining < 1) throw new PortalError('first_passkey_expired');
      const options = { ...ceremony.options,
        timeout: Math.min(ceremony.options.timeout ?? remaining, Math.floor(remaining)) };
      const attestation = await createPasskey(options, signal);
      if (this.firstPasskeyKeyID(await this.getKey()) !== ceremony.binding.keyID)
        throw new PortalError('key_unavailable');
      throwIfAborted(signal);
      this.assertFirstPasskeyBinding(ceremony.binding);
      this.keepFirstPasskey({ purpose: ceremony.purpose, expires_at: ceremony.expires_at,
        binding: ceremony.binding, stage: 'finish', attestation }, ownerSignal);
    });
  }

  finishFirstPasskey(signal: AbortSignal, onSend?: () => void) {
    return this.firstPasskeyOperation('finish', signal, async (signal) => {
      const ceremony = this.#firstPasskey;
      this.#firstPasskey = undefined;
      if (!ceremony || ceremony.stage !== 'finish') throw new PortalError('proof_required');
      this.assertFirstPasskeyBinding(ceremony.binding);
      return this.#sendRequest('/api/v1/auth/webauthn/register/verify', firstPasskeyResponse,
        { method: 'POST', body: ceremony.attestation, signal, onSend,
          firstPasskey: { binding: ceremony.binding } });
    });
  }

  async bootstrap(signal?: AbortSignal): Promise<Profile> {
    const result = await this.request('/api/v1/users/me', profileResponse, {
      signal,
      anonymous: true,
    });
    throwIfAborted(this.#lifetime.signal);
    if (
      this.#profile &&
      (result.session.id !== this.#profile.session.id || result.id !== this.#profile.id)
    ) {
      const error = new PortalError('session_changed', 409);
      this.loseSession(error);
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
      this.loseSession(error);
      throw error;
    }
    this.#profile = result;
    return result;
  }

  username(signal: AbortSignal): Promise<{ display: string } | null> {
    return this.request(
      '/api/v1/users/me/username',
      (value, status) => {
        const envelope = record(value);
        if (status !== 200 || Object.keys(envelope).length !== 1 || !Object.hasOwn(envelope, 'username'))
          throw new PortalError('invalid_response');
        if (envelope.username === null) return null;
        const username = record(envelope.username);
        if (
          Object.keys(username).length !== 1 || typeof username.display !== 'string' ||
          !username.display || new TextEncoder().encode(username.display).length > 1024
        )
          throw new PortalError('invalid_response');
        return { display: username.display };
      },
      { signal }
    );
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
    const requestedAt = Date.now();
    return this.request('/api/v1/auth/webauthn/login/verify', (value, status): LoginMfa | undefined => {
      if (status === 204) {
        emptyResponse(value);
        return undefined;
      }
      const item = record(value);
      if (status !== 200 || item.status !== 'mfa_required' || Object.keys(item).length !== 3 ||
        !Object.hasOwn(item, 'preauthentication') || !Object.hasOwn(item, 'expires_at'))
        throw new PortalError('invalid_response');
      const expires_at = timestamp(item.expires_at);
      if (Date.parse(expires_at) <= Date.now() || Date.parse(expires_at) > requestedAt + 320000)
        throw new PortalError('invalid_response');
      return { status: 'mfa_required', preauthentication: identifier(item.preauthentication, 1024), expires_at };
    }, {
      method: 'POST',
      body: assertion,
      signal,
      anonymous: true,
    });
  }
  keys(signal: AbortSignal) {
    return this.request('/api/v1/auth/webauthn/keys', (value) => list(value, passkeyListEntryResponse), {
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
  deleteAccount(
    grant: StepUpGrant,
    signal: AbortSignal,
    onSend?: () => void,
    notificationLocale?: Locale
  ) {
    return this.request('/api/v1/users/me', emptyResponse, {
      method: 'DELETE',
      notificationLocale,
      grant,
      signal,
      onSend,
    });
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
