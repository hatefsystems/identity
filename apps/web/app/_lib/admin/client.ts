import { PortalClient } from '../portal/client';
import type { StepUpGrant } from '../portal/contracts';
import { PortalError } from '../portal/errors';
import { emptyResponse } from '../portal/json-response';
import {
  auditPageResponse,
  capabilitiesResponse,
  userResponse,
  usersResponse,
  type AdminAuditQuery,
  type AdminChain,
  type AdminStatusUpdate,
  type AdminUsersQuery,
  type AdminVerifyQuery,
} from './contracts';
import {
  compareDecimal,
  decimalString,
  moderationStatus,
  normalizeModerationReason,
  requestFields,
  timestampNanoseconds,
  uuid,
  validateAuditQuery,
  validateUsersQuery,
  validateVerifyQuery,
} from './validation';
import { verificationPageResponse } from './verification';

export type * from './contracts';

// This wrapper owns no session, credentials, capability cache, or retry loop.
export class AdminClient {
  constructor(private readonly portal: PortalClient) {}

  capabilities(signal?: AbortSignal) {
    return this.portal.request('/api/v1/admin/capabilities', capabilitiesResponse, { signal });
  }

  async users(query: AdminUsersQuery = {}, signal?: AbortSignal) {
    const parameters = validateUsersQuery(query);
    return this.portal.request(
      '/api/v1/admin/users',
      (value) => {
        const page = usersResponse(value);
        if (
          page.offset !== (parameters.offset ?? 0) ||
          (parameters.limit !== undefined && page.limit > parameters.limit) ||
          (parameters.status !== undefined &&
            page.items.some((user) => user.status !== parameters.status))
        )
          throw new PortalError('invalid_response');
        return page;
      },
      { query: parameters, signal }
    );
  }

  async lookup(email: string, signal?: AbortSignal) {
    if (typeof email !== 'string') throw new PortalError('invalid_request');
    const normalized = email.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '').toLowerCase();
    if (
      !normalized.includes('@') ||
      /[\p{Cc}\p{Cs}]/u.test(normalized) ||
      new TextEncoder().encode(normalized).length > 254
    )
      throw new PortalError('invalid_request');
    return this.portal.request(
      '/api/v1/admin/users/lookup',
      (value) => {
        const page = usersResponse(value);
        if (
          page.limit !== 1 ||
          page.offset !== 0 ||
          page.total > 1 ||
          page.items.some((user) => user.email?.toLowerCase() !== normalized)
        )
          throw new PortalError('invalid_response');
        return page;
      },
      { method: 'POST', body: { email: normalized }, signal }
    );
  }

  async user(id: string, signal?: AbortSignal) {
    const target = uuid(id);
    return this.portal.request(
      `/api/v1/admin/users/${target}`,
      (value) => {
        const user = userResponse(value);
        if (user.id !== target) throw new PortalError('invalid_response');
        return user;
      },
      { signal }
    );
  }

  async updateStatus(
    id: string,
    update: AdminStatusUpdate,
    grant: StepUpGrant,
    signal?: AbortSignal,
    onSend?: () => void
  ) {
    const target = uuid(id);
    requestFields(update, ['status', 'reason', 'expected_revision']);
    const body = {
      status: moderationStatus(update.status),
      reason: normalizeModerationReason(update.reason),
      expected_revision: decimalString(update.expected_revision),
    };
    return this.portal.request(`/api/v1/admin/users/${target}/status`, emptyResponse, {
      method: 'PATCH',
      body,
      grant,
      signal,
      onSend,
    });
  }

  async auditLogs(query: AdminAuditQuery, signal?: AbortSignal) {
    const parameters = validateAuditQuery(query);
    const start = timestampNanoseconds(parameters.start_time);
    const end = timestampNanoseconds(parameters.end_time);
    return this.portal.request(
      '/api/v1/admin/audit-logs',
      (value) => {
        const page = auditPageResponse(value);
        if (
          (parameters.limit !== undefined && page.limit > parameters.limit) ||
          page.items.some(
            (row) =>
              (parameters.before_seq !== undefined &&
                parameters.before_seq !== '0' &&
                compareDecimal(row.seq, parameters.before_seq) >= 0) ||
              (parameters.event_type !== undefined && row.event_type !== parameters.event_type) ||
              row.timestamp === null ||
              timestampNanoseconds(row.timestamp) < start ||
              timestampNanoseconds(row.timestamp) > end
          )
        )
          throw new PortalError('invalid_response');
        return page;
      },
      { query: parameters, signal }
    );
  }

  async verify(chain: AdminChain, query: AdminVerifyQuery = {}, signal?: AbortSignal) {
    if (chain !== 'audit' && chain !== 'ledger') throw new PortalError('invalid_request');
    const parameters = validateVerifyQuery(query);
    const path =
      chain === 'audit' ? '/api/v1/admin/audit-logs/verify' : '/api/v1/admin/ledger/verify';
    return this.portal.request(
      path,
      (value) => verificationPageResponse(value, chain, parameters),
      { query: parameters, signal }
    );
  }
}
