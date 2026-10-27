import { PortalError, throwIfAborted } from './errors';
import { emptyResponse, readResponse } from './json-response';
import { record } from './validation';

export type ReclaimOptions = { factor: 'webauthn'; webauthn: unknown } | { factor: 'totp' };
export type ReclaimProof =
  | { token: string; factor: 'webauthn'; assertion: unknown }
  | { token: string; factor: 'totp'; code: string };

export function isReclaimToken(value: unknown): value is string {
  // A 32-byte unpadded base64url token has two zero pad bits in its last character.
  return (
    typeof value === 'string' &&
    value.length === 43 &&
    /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value)
  );
}

function reclaimOptionsResponse(value: unknown): ReclaimOptions {
  const item = record(value);
  if (item.factor === 'totp') return { factor: 'totp' };
  if (item.factor === 'webauthn') {
    record(record(item.webauthn).publicKey);
    return { factor: 'webauthn', webauthn: item.webauthn };
  }
  throw new PortalError('invalid_response');
}

// These two anonymous, Origin-protected endpoints intentionally use neither the
// portal session nor its IndexedDB/DPoP key. No arbitrary path can use this client.
export class ReclaimClient {
  private readonly origin: string;
  private readonly fetcher: typeof fetch;

  constructor(options: { origin?: string; fetcher?: typeof fetch } = {}) {
    this.origin = options.origin ?? window.location.origin;
    const origin = new URL(this.origin);
    if (origin.origin !== this.origin || !['https:', 'http:'].includes(origin.protocol))
      throw new PortalError('invalid_origin');
    this.fetcher = options.fetcher ?? ((...args) => fetch(...args));
  }

  options(token: string, signal: AbortSignal): Promise<ReclaimOptions> {
    return this.request('options', { token }, reclaimOptionsResponse, signal);
  }

  complete(proof: ReclaimProof, signal: AbortSignal, onSend?: () => void): Promise<void> {
    if (
      (proof.factor !== 'webauthn' && proof.factor !== 'totp') ||
      (proof.factor === 'totp' && (proof.code.length !== 6 || !/^[0-9]{6}$/.test(proof.code)))
    )
      return Promise.reject(new PortalError('invalid_request'));
    return this.request('complete', proof, emptyResponse, signal, onSend);
  }

  private async request<T>(
    operation: 'options' | 'complete',
    payload: { token: string },
    decode: (value: unknown) => T,
    signal: AbortSignal,
    onSend?: () => void
  ): Promise<T> {
    throwIfAborted(signal);
    if (!isReclaimToken(payload.token)) throw new PortalError('invalid_request');
    const completing = operation === 'complete';
    const url = `${this.origin}/api/v1/auth/deletion/reclaim/${completing ? '' : 'options'}`;
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 20000);
    let sent = false;
    let response: Response | undefined;
    try {
      const body = JSON.stringify(payload);
      if (new TextEncoder().encode(body).length > 64 * 1024)
        throw new PortalError('invalid_request');
      throwIfAborted(controller.signal);
      onSend?.();
      sent = true;
      response = await this.fetcher(url, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body,
        credentials: 'omit',
        // Preserve Fetch's Origin header with no-referrer, as in PortalClient.
        mode: 'cors',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      if (response.redirected || (response.url && response.url !== url))
        throw new PortalError('invalid_response');
      const value = await readResponse(response, controller.signal);
      throwIfAborted(controller.signal);
      if (response.ok) {
        if (response.status !== (completing ? 204 : 200)) throw new PortalError('invalid_response');
        return decode(value);
      }
      const error = record(value).error;
      const code =
        typeof error === 'string' && /^[a-z_]{1,80}$/.test(error) ? error : 'request_failed';
      throw new PortalError(code, response.status, completing && response.status >= 500);
    } catch (failure) {
      if (signal.aborted && !(sent && completing)) throwIfAborted(signal);
      const error =
        failure instanceof PortalError
          ? failure
          : new PortalError('network_error', response?.status ?? 0, sent && completing);
      if (
        sent &&
        completing &&
        (controller.signal.aborted ||
          (error.code === 'invalid_response' &&
            (!response || response.status < 400 || response.status >= 500)))
      )
        throw new PortalError(error.code, response?.status ?? 0, true);
      throw error;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
    }
  }
}
