import { PortalError } from '../../_lib/portal/errors';

// React removal alone leaves values on detached controls held by browser code.
export function clearLegalRegion(region: HTMLElement | null): void {
  if (!region) return;
  region.hidden = true;
  clearLegalControls(region);
}

export function clearLegalControls(region: HTMLElement | null): void {
  if (!region) return;
  for (const control of region.querySelectorAll('input, textarea, select')) {
    if (control instanceof HTMLInputElement) {
      control.defaultChecked = false;
      control.checked = false;
    }
    if (control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement)
      control.defaultValue = '';
    if (control instanceof HTMLSelectElement)
      for (const option of control.options) option.defaultSelected = false;
    if (
      control instanceof HTMLInputElement ||
      control instanceof HTMLTextAreaElement ||
      control instanceof HTMLSelectElement
    )
      control.value = '';
  }
}

export function legalFailureMessage(failure: unknown): string {
  if (failure instanceof PortalError) {
    if (failure.code === 'idempotency_conflict')
      return 'The original operation conflicts with these inputs or its retained tombstone. Reconcile the exact original request in controlled external intake. Do not replace the UUID or try to reactivate a released request.';
    if (failure.code === 'hold_not_found')
      return 'The API could not find this hold request. This is not proof that no historical hold or activity existed.';
    if (failure.code === 'insufficient_user_authentication' || failure.code === 'grant_expired')
      return 'Fresh single-use verification is required. Reenter the request and verify again; no old grant will be reused.';
    if (failure.status === 403)
      return 'Legal access was denied. Private legal data was cleared. Recheck capabilities; your ordinary account session has not been signed out.';
    if (failure.status === 401 || failure.code === 'session_changed')
      return 'The session must be checked again. No result was accepted and no write success is inferred from session loss.';
    if (failure.status === 404)
      return 'This legal endpoint is unavailable on this deployment. No result was accepted.';
    if (failure.status === 429)
      return failure.retryAfterSeconds === undefined
        ? 'The request was rate limited. Wait before another explicit attempt; nothing will retry automatically.'
        : `The request was rate limited. Wait ${failure.retryAfterSeconds} seconds before another explicit attempt; nothing will retry automatically.`;
    if (failure.code === 'invalid_request' || failure.code === 'unsupported_identifier_type')
      return 'The legal inputs or continuation scope were rejected. Correct the inputs or explicitly start a new inquiry; no filter or cursor was silently removed.';
    if (failure.code === 'invalid_response' || failure.code === 'response_too_large')
      return 'The response was malformed, oversized, or inconsistent with this request. No result was accepted. Use an explicitly smaller page or inquiry scope, never an automatic retry.';
    if (failure.status >= 500)
      return 'The legal service could not provide an audited result. No result was accepted; this is not an empty result or a promise of rollback.';
  }
  return 'No legal result was accepted. Check availability before an explicit new attempt; nothing was retried.';
}

export const legalClearedMessage =
  'Private legal inputs, references, results, operation UUIDs, cursors, and verification were cleared. Recheck your session and access before continuing.';

export const legalFieldLabels = {
  client_ip: 'Client IP',
  ip_subnet: 'IP subnet',
  user_agent: 'User agent',
  device_fingerprint: 'Device fingerprint',
  client_id: 'Client ID',
  scope: 'Scope',
} as const;
