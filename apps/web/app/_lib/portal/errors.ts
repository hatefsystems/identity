import type { MessageDescriptor } from '../../../i18n/messages';

export class PortalError extends Error {
  constructor(
    readonly code: string,
    readonly status = 0,
    readonly uncertain = false,
    readonly retryAfterSeconds?: number
  ) {
    // Do not retain response bodies, credential material, or identity-bearing URLs.
    super(code);
    this.name = 'PortalError';
  }
}

// Feedback only: never schedule a retry, keepalive, or replay from this header.
export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (value === null || value.length > 80 || value.trim() !== value) return undefined;
  if (/^[0-9]{1,10}$/.test(value)) return Math.min(Number(value), 3600);
  if (
    !/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(
      value
    )
  )
    return undefined;
  const deadline = Date.parse(value);
  if (!Number.isFinite(deadline) || new Date(deadline).toUTCString() !== value) return undefined;
  return Math.min(3600, Math.max(0, Math.ceil((deadline - now) / 1000)));
}

export function isSessionLoss(error: unknown): boolean {
  return (
    error instanceof PortalError &&
    (error.code === 'session_changed' ||
      error.code === 'key_unavailable' ||
      (error.status === 401 &&
        [
          'unauthorized',
          'session_required',
          'invalid_session',
          'session_expired',
          'invalid_dpop_proof',
        ].includes(error.code)))
  );
}

export function errorMessage(error: unknown, method?: 'webauthn'): MessageDescriptor {
  if (error instanceof PortalError) {
    if (error.uncertain)
      return { key: 'errors.uncertain' };
    switch (error.code) {
      case 'key_unavailable':
        return { key: 'errors.keyUnavailable' };
      case 'unsupported':
        return { key: 'errors.unsupported' };
      case 'cancelled':
        return { key: 'errors.cancelled' };
      case 'authenticator_security':
        return { key: 'errors.authenticatorSecurity' };
      case 'invalid_credentials':
        return method === 'webauthn'
          ? { key: 'errors.invalidCredentialsWebauthn' }
          : { key: 'errors.invalidCredentials' };
      case 'challenge_invalid':
      case 'verification_failed':
        return { key: 'errors.challengeInvalid' };
      case 'user_verification_required':
        return method === 'webauthn'
          ? { key: 'errors.userVerificationWebauthn' }
          : { key: 'errors.userVerification' };
      case 'no_stepup_factor':
        return method === 'webauthn'
          ? { key: 'errors.noFactorWebauthn' }
          : { key: 'errors.noFactor' };
      case 'deletion_disabled':
        return { key: 'errors.deletionDisabled' };
      case 'insufficient_user_authentication':
      case 'grant_expired':
        return { key: 'errors.freshVerification' };
      case 'last_credential':
        return { key: 'errors.lastCredential' };
      case 'credential_not_found':
      case 'user_not_found':
      case 'not_found':
        return { key: 'errors.notFound' };
      case 'profile_conflict':
        return { key: 'errors.profileConflict' };
      case 'account_conflict':
        return { key: 'errors.accountConflict' };
      case 'account_not_moderatable':
        return { key: 'errors.notModeratable' };
      case 'forbidden':
        return { key: 'errors.forbidden' };
      case 'session_changed':
        return { key: 'errors.sessionChanged' };
      case 'unauthorized':
      case 'session_required':
      case 'invalid_session':
      case 'session_expired':
      case 'invalid_dpop_proof':
        return { key: 'errors.sessionRequired' };
      case 'rate_limited':
        return error.retryAfterSeconds
          ? { key: 'errors.rateLimitedSeconds', values: { seconds: error.retryAfterSeconds } }
          : { key: 'errors.rateLimited' };
      case 'use_dpop_nonce':
        return { key: 'errors.nonce' };
      case 'network_error':
        return { key: 'errors.network' };
      case 'temporarily_unavailable':
        return { key: 'errors.temporarilyUnavailable' };
      case 'audit_unavailable':
      case 'service_unavailable':
      case 'rate_limit_unavailable':
        return { key: 'errors.serviceUnavailable' };
      case 'invalid_response':
        return { key: 'errors.invalidResponse' };
      case 'unknown_seq':
        return { key: 'errors.unknownSequence' };
      case 'missing_head':
        return { key: 'errors.missingHead' };
      case 'name_single_line':
        return { key: 'errors.nameSingleLine' };
      case 'name_too_long':
        return { key: 'errors.nameTooLong' };
    }
    if (error.status === 429) return { key: 'errors.rateLimited' };
  }
  return { key: 'errors.requestFailed' };
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('The operation was cancelled.', 'AbortError');
}

export function isAborted(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}
