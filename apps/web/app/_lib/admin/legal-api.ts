import type { PortalClient } from '../portal/client';
import type { StepUpGrant } from '../portal/contracts';
import { PortalError } from '../portal/errors';
import { emptyResponse } from '../portal/json-response';
import {
  legalCreateResponse,
  legalHoldsResponse,
  legalLookupResponse,
  type LegalHold,
  type LegalHoldRequest,
  type LegalHoldsQuery,
  type LegalLookupContinuation,
  type LegalLookupQuery,
  type LegalPreservationRequest,
  type LegalPreservationResult,
} from './legal-contracts';
import {
  validateLegalHoldRequest,
  validateLegalHoldsQuery,
  validateLegalJSON,
  validateLegalLookupContinuation,
  validateLegalLookupQuery,
  validateLegalPreservationRequest,
} from './legal-validation';
import { nonzeroUUID } from './validation';

// The shared PortalClient owns authentication, one-use grants and nonce handling.
export class LegalClient {
  constructor(private readonly portal: PortalClient) {}

  async holds(query: LegalHoldsQuery, signal?: AbortSignal) {
    const parameters = validateLegalHoldsQuery(query);
    return this.portal.request(
      '/api/v1/admin/legal-holds',
      (value, status) => {
        if (status !== 200) throw new PortalError('invalid_response');
        return legalHoldsResponse(value, parameters);
      },
      {
        query: {
          ...(parameters.accountRef === undefined ? {} : { account_ref: parameters.accountRef }),
          status: parameters.status,
          limit: parameters.limit,
          offset: parameters.offset,
        },
        signal,
      }
    );
  }

  async applyHold(
    request: LegalHoldRequest,
    grant: StepUpGrant,
    signal?: AbortSignal,
    onSend?: () => void
  ): Promise<LegalHold> {
    const parameters = validateLegalHoldRequest(request);
    const body = {
      account_ref: parameters.accountRef,
      reason: parameters.reason,
      requesting_authority: parameters.requestingAuthority,
      legal_basis: parameters.legalBasis,
      ...(parameters.reviewAt === undefined ? {} : { review_at: parameters.reviewAt }),
    };
    validateLegalJSON(body);
    return this.portal.request(
      '/api/v1/admin/legal-holds',
      (value, status) => legalCreateResponse(value, status, parameters, 'legal_hold') as LegalHold,
      { method: 'POST', body, idempotencyKey: parameters.requestId, grant, signal, onSend }
    );
  }

  async preserve(
    request: LegalPreservationRequest,
    grant: StepUpGrant,
    signal?: AbortSignal,
    onSend?: () => void
  ): Promise<LegalPreservationResult> {
    const parameters = validateLegalPreservationRequest(request);
    const body = {
      account_ref: parameters.accountRef,
      reason: parameters.reason,
      requesting_authority: parameters.requestingAuthority,
      ...(parameters.expiresAt === undefined ? {} : { expires_at: parameters.expiresAt }),
    };
    validateLegalJSON(body);
    return this.portal.request(
      '/api/v1/admin/preservation-requests',
      (value, status) =>
        legalCreateResponse(value, status, parameters, 'preservation') as LegalPreservationResult,
      { method: 'POST', body, idempotencyKey: parameters.requestId, grant, signal, onSend }
    );
  }

  async releaseHold(holdId: string, grant: StepUpGrant, signal?: AbortSignal, onSend?: () => void) {
    let target: string;
    try {
      target = nonzeroUUID(holdId);
    } catch {
      throw new PortalError('invalid_request');
    }
    return this.portal.request(
      `/api/v1/admin/legal-holds/${target}`,
      (value, status) => {
        if (status !== 204) throw new PortalError('invalid_response');
        return emptyResponse(value);
      },
      { method: 'DELETE', grant, signal, onSend }
    );
  }

  async lookup(
    query: LegalLookupQuery,
    grant: StepUpGrant,
    signal?: AbortSignal,
    onSend?: () => void,
    continuation?: LegalLookupContinuation
  ) {
    const parameters = validateLegalLookupQuery(query);
    const scope =
      continuation === undefined
        ? undefined
        : validateLegalLookupContinuation(parameters, continuation);
    const body = {
      identifier_type: 'email',
      identifier: parameters.identifier,
      requesting_authority: parameters.requestingAuthority,
      case_reference: parameters.caseReference,
      purpose: parameters.purpose,
      start_time: parameters.startTime,
      end_time: parameters.endTime,
      limit: parameters.limit,
      fields: parameters.fields,
      ...(scope === undefined ? {} : { cursor: scope.cursor }),
    };
    validateLegalJSON(body);
    return this.portal.request(
      '/api/v1/admin/legal-inquiry/lookup',
      (value, status) => {
        if (status !== 200) throw new PortalError('invalid_response');
        return legalLookupResponse(value, parameters, scope);
      },
      { method: 'POST', body, grant, signal, onSend }
    );
  }
}
