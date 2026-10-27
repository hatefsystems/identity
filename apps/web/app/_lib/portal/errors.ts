export class PortalError extends Error {
  constructor(
    readonly code: string,
    readonly status = 0,
    readonly uncertain = false
  ) {
    // Do not retain response bodies, credential material, or identity-bearing URLs.
    super(code);
    this.name = 'PortalError';
  }
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

export function errorMessage(error: unknown, method?: 'webauthn'): string {
  if (error instanceof PortalError) {
    if (error.uncertain)
      return 'The response was lost. The action may already have completed. Refresh the saved state before trying a new action.';
    switch (error.code) {
      case 'key_unavailable':
        return 'Secure browser key storage is unavailable. Allow IndexedDB and Web Crypto, then sign in again. If site storage is damaged, clear it before signing in. Access cannot continue without the browser key.';
      case 'unsupported':
        return 'Passkeys require a supported browser and a secure connection. Use a supported browser to continue.';
      case 'cancelled':
        return 'The passkey request was cancelled or timed out. Start a new verification to try again.';
      case 'authenticator_security':
        return 'The passkey could not be used on this origin. Check the secure site address and try again.';
      case 'invalid_credentials':
        return method === 'webauthn'
          ? 'Verification failed or expired. Start a new passkey verification with a device PIN or biometrics.'
          : 'Verification failed or expired. Use a current authenticator code or start a new passkey verification.';
      case 'challenge_invalid':
      case 'verification_failed':
        return 'The passkey ceremony expired or could not be verified. Start again with fresh verification.';
      case 'user_verification_required':
        return method === 'webauthn'
          ? 'This action requires a passkey with a device PIN or biometric verification.'
          : 'Use a passkey with a device PIN or biometric verification, or your enrolled authenticator app.';
      case 'no_stepup_factor':
        return method === 'webauthn'
          ? 'This action requires a passkey with a device PIN or biometric verification. No suitable passkey verification is available. You can manage your passkeys in Security.'
          : 'No supported verification factor is available for this account.';
      case 'deletion_disabled':
        return 'Account deletion is currently unavailable.';
      case 'insufficient_user_authentication':
      case 'grant_expired':
        return 'Fresh verification is required. Start the action again.';
      case 'last_credential':
        return 'Your last passkey cannot be removed. Add another passkey first.';
      case 'credential_not_found':
      case 'not_found':
        return 'This item is no longer available. Refresh the list to see its current state.';
      case 'profile_conflict':
        return 'The saved profile changed. Refresh the saved profile, review your draft, then save again.';
      case 'session_changed':
        return 'The browser session changed. Private data has been cleared. Verify the current session before continuing.';
      case 'unauthorized':
      case 'session_required':
      case 'invalid_session':
      case 'session_expired':
      case 'invalid_dpop_proof':
        return 'Your session is no longer available. Sign in again to continue.';
      case 'rate_limited':
        return 'Too many attempts. Please try again later.';
      case 'use_dpop_nonce':
        return 'The secure request could not be authorized. Start a new action to try again.';
      case 'network_error':
        return 'The service could not be reached. Check your connection and try again.';
      case 'temporarily_unavailable':
        return 'The service is temporarily unavailable. Your session could not be verified. Please try again later.';
    }
    if (error.status === 429) return 'Too many attempts. Please try again later.';
  }
  return 'The request could not be completed. Please try again.';
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('The operation was cancelled.', 'AbortError');
}

export function isAborted(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}
