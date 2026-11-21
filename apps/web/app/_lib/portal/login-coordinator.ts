import { PortalClient, type LoginMfa } from './client';
import { PortalError, throwIfAborted } from './errors';
import { emptyResponse } from './json-response';
import { identifier, record, timestamp } from './validation';

export type LoginChannel = 'email' | 'sms';
export type LoginState =
  | { stage: 'credentials' | 'session' | 'unconfirmed' | 'expired' | 'closed' }
  | { stage: 'delivered'; channel: LoginChannel; expiresAt: string }
  | { stage: 'mfa'; expiresAt: string };
type Authority = { handle: string; wall: number; monotonic: number; attempts: number };

function exact(value: unknown, keys: string[]) {
  const item = record(value);
  if (Object.keys(item).length !== keys.length || keys.some((key) => !Object.hasOwn(item, key)))
    throw new PortalError('invalid_response');
  return item;
}

// Handles never leave this object: the view receives only stage and original expiry.
// Transport owns the one safe pre-handler nonce retry; this coordinator never retries.
export class LoginCoordinator {
  #state: LoginState = { stage: 'credentials' };
  #authority?: Authority;
  #lifetime = new AbortController();
  #busy = false;

  constructor(readonly client: PortalClient) {}

  get state(): LoginState {
    this.checkExpiry();
    return { ...this.#state };
  }

  dispose(): void {
    this.#authority = undefined;
    this.#state = { stage: 'closed' };
    this.#lifetime.abort();
    this.client.dispose();
  }

  unconfirmed(): void {
    this.#authority = undefined;
    this.#state = { stage: 'unconfirmed' };
  }

  acceptPasskeyMfa(result: LoginMfa): void {
    if (this.#state.stage !== 'credentials' || this.#busy) throw new PortalError('invalid_request');
    this.outcome(result, 200, Date.now());
  }

  password(username: string, password: string): Promise<void> {
    this.credentials(username);
    if (typeof password !== 'string' || !password || /\p{Cs}/u.test(password) ||
      new TextEncoder().encode(password).length > 1024)
      return Promise.reject(new PortalError('invalid_request'));
    return this.run('/api/v1/auth/login', { username, password }, (value, status, requestedAt) =>
      this.outcome(value, status, requestedAt));
  }

  requestCode(username: string, channel: LoginChannel): Promise<void> {
    this.credentials(username);
    if (channel !== 'email' && channel !== 'sms')
      return Promise.reject(new PortalError('invalid_request'));
    return this.run('/api/v1/auth/login/code/request', { username, channel }, (value, status, requestedAt) => {
      const item = exact(value, ['status', 'challenge', 'expires_at']);
      if (status !== 202 || item.status !== 'code_requested') throw new PortalError('invalid_response');
      const expiresAt = this.authority(item.challenge, item.expires_at, requestedAt, 180000);
      this.#state = { stage: 'delivered', channel, expiresAt };
    });
  }

  verifyCode(code: string): Promise<void> {
    const authority = this.verification('delivered', code);
    return this.run('/api/v1/auth/login/code/verify', { challenge: authority.handle, code },
      (value, status, requestedAt) => this.outcome(value, status, requestedAt), authority);
  }

  verifyTotp(code: string): Promise<void> {
    const authority = this.verification('mfa', code);
    return this.run('/api/v1/auth/login/mfa', { preauthentication: authority.handle, code }, (value, status) => {
      if (status !== 204) throw new PortalError('invalid_response');
      emptyResponse(value);
      this.#state = { stage: 'session' };
    }, authority);
  }

  private credentials(username: string): void {
    if (this.#state.stage !== 'credentials' || typeof username !== 'string' || !username ||
      new TextEncoder().encode(username).length > 1024 ||
      /[\p{Cc}\p{Cs}]/u.test(username))
      throw new PortalError('invalid_request');
    // Username canonicalization remains server-owned. Never apply OTP conversion here.
  }

  private checkExpiry(): void {
    if (this.#authority && (Date.now() >= this.#authority.wall ||
      performance.now() >= this.#authority.monotonic)) {
      this.#authority = undefined;
      this.#state = { stage: 'expired' };
    }
  }

  private verification(stage: 'delivered' | 'mfa', code: string): Authority {
    this.checkExpiry();
    if (this.#state.stage === 'expired') throw new PortalError('login_expired');
    if (this.#state.stage !== stage || !this.#authority || !/^[0-9]{6}$/.test(code))
      throw new PortalError('invalid_request');
    return this.#authority;
  }

  private authority(handle: unknown, expiry: unknown, requestedAt: number, max: number): string {
    const secret = identifier(handle, 1024);
    const expiresAt = timestamp(expiry);
    const serverDeadline = Date.parse(expiresAt);
    // Allow transport latency, but never retain authority beyond the local maximum.
    const wall = Math.min(serverDeadline, requestedAt + max);
    if (wall <= Date.now() || serverDeadline > requestedAt + max + 20000)
      throw new PortalError('invalid_response');
    this.#authority = { handle: secret, wall, monotonic: performance.now() + wall - Date.now(), attempts: 0 };
    return expiresAt;
  }

  private outcome(value: unknown, status: number, requestedAt: number): void {
    if (status === 204) {
      emptyResponse(value);
      this.#state = { stage: 'session' };
      return;
    }
    const item = exact(value, ['status', 'preauthentication', 'expires_at']);
    if (status !== 200 || item.status !== 'mfa_required') throw new PortalError('invalid_response');
    const expiresAt = this.authority(item.preauthentication, item.expires_at, requestedAt, 300000);
    this.#state = { stage: 'mfa', expiresAt };
  }

  private async run(path: string, body: unknown,
    decode: (value: unknown, status: number, requestedAt: number) => void,
    authority?: Authority): Promise<void> {
    throwIfAborted(this.#lifetime.signal);
    if (this.#busy) throw new PortalError('login_busy');
    this.#busy = true;
    const previous = this.#state;
    this.#authority = undefined;
    const requestedAt = Date.now();
    try {
      await this.client.request(path, (value, status) => {
        throwIfAborted(this.#lifetime.signal);
        decode(value, status, requestedAt);
      }, { method: 'POST', body, anonymous: true, signal: this.#lifetime.signal });
    } catch (failure) {
      if (this.#lifetime.signal.aborted) throw failure;
      const error = failure instanceof PortalError ? failure : new PortalError('network_error', 0, true);
      if (error.uncertain || ['network_error', 'invalid_response', 'cancelled'].includes(error.code)) {
        this.unconfirmed();
      } else if (authority) {
        // Only a definitive wrong-code response retains the original authority.
        if (error.status === 401 && error.code === 'invalid_credentials' && ++authority.attempts < 3 &&
          Date.now() < authority.wall && performance.now() < authority.monotonic) {
          this.#authority = authority;
          this.#state = previous;
        } else this.#state = { stage: 'expired' };
      }
      throw error;
    } finally {
      this.#busy = false;
    }
  }
}
