import type { MessageDescriptor } from '../../../i18n/messages';
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

export function legalFailureMessage(failure: unknown): MessageDescriptor {
  if (failure instanceof PortalError) {
    if (failure.code === 'idempotency_conflict') return { key: 'legal.failure.conflict' };
    if (failure.code === 'hold_not_found') return { key: 'legal.failure.notFound' };
    if (failure.code === 'insufficient_user_authentication' || failure.code === 'grant_expired')
      return { key: 'legal.failure.verification' };
    if (failure.status === 403) return { key: 'legal.failure.denied' };
    if (failure.status === 401 || failure.code === 'session_changed')
      return { key: 'legal.failure.session' };
    if (failure.status === 404) return { key: 'legal.failure.unavailable' };
    if (failure.status === 429)
      return failure.retryAfterSeconds === undefined
        ? { key: 'legal.failure.rateLimited' }
        : { key: 'legal.failure.retryAfter', values: { seconds: failure.retryAfterSeconds } };
    if (failure.code === 'invalid_request' || failure.code === 'unsupported_identifier_type')
      return { key: 'legal.failure.invalidRequest' };
    if (failure.code === 'invalid_response' || failure.code === 'response_too_large')
      return { key: 'legal.failure.invalidResponse' };
    if (failure.status >= 500) return { key: 'legal.failure.service' };
  }
  return { key: 'legal.failure.unknown' };
}

export const legalClearedMessage: MessageDescriptor = { key: 'legal.state.cleared' };

export const legalFieldLabels = {
  client_ip: 'disclosure.client_ip',
  ip_subnet: 'disclosure.ip_subnet',
  user_agent: 'disclosure.user_agent',
  device_fingerprint: 'disclosure.device_fingerprint',
  client_id: 'disclosure.client_id',
  scope: 'disclosure.scope',
} as const;

// Exact server evidence, recognized only after the existing response validation.
// Never normalize notes or guess translations for an unknown server explanation.
export const legalEvidenceNotes = {
  preservation:
    'preservation does not restore purged data; ingestion may still be pending; account and ledger presence are observations, not completeness guarantees; expires_at is advisory only',
  coverage:
    'matching indexed retained records only; ingestion may be pending; unindexed or purged history is not covered; separate account references do not establish one person',
} as const;
