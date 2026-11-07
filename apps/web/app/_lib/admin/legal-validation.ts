import { PortalError } from '../portal/errors';
import { integer } from '../portal/validation';
import type { AdminLimits } from './contracts';
import {
  legalCursor,
  legalDisclosureFields,
  legalLookupResponse,
  type LegalHoldRequest,
  type LegalHoldsQuery,
  type LegalLookupContinuation,
  type LegalLookupPage,
  type LegalLookupQuery,
  type LegalPreservationRequest,
} from './legal-contracts';
import {
  adminTimestamp,
  compareDecimal,
  decimalString,
  nonzeroUUID,
  positiveInteger,
  requestFields,
  timestampNanoseconds,
} from './validation';

function input<T>(validate: () => T): T {
  try {
    return validate();
  } catch {
    throw new PortalError('invalid_request');
  }
}

function normalizedText(value: string, max: number): string {
  if (typeof value !== 'string' || /\p{Cs}/u.test(value)) throw new PortalError('invalid_request');
  const result = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
  if (!result || new TextEncoder().encode(result).length > max)
    throw new PortalError('invalid_request');
  return result;
}

function utc(value: string, precision = 9): string {
  const result = adminTimestamp(value);
  if (
    !result.endsWith('Z') ||
    result.startsWith('0000-') ||
    /^0001-01-01T00:00:00(?:\.0+)?Z$/.test(result) ||
    (/\.(\d+)/.exec(result)?.[1].length ?? 0) > precision
  )
    throw new PortalError('invalid_request');
  return result;
}

export function validateLegalJSON(value: unknown): void {
  input(() => {
    const serialized = JSON.stringify(value);
    if (serialized === undefined || new TextEncoder().encode(serialized).length > 32 * 1024)
      throw new PortalError('invalid_request');
  });
}

export function legalPageLimits(limits: AdminLimits): Readonly<{ default: number; max: number }> {
  return input(() => {
    const maximum = positiveInteger(limits.page_size_max, 200);
    const initial = positiveInteger(limits.page_size_default, 200);
    if (initial > maximum) throw new PortalError('invalid_request');
    const max = Math.min(maximum, 50);
    return Object.freeze({ default: Math.min(initial, max), max });
  });
}

export function validateLegalHoldsQuery(
  query: LegalHoldsQuery,
  limits?: AdminLimits
): LegalHoldsQuery {
  return input(() => {
    requestFields(query, ['accountRef', 'status', 'limit', 'offset']);
    if (!['active', 'released', 'all'].includes(query.status))
      throw new PortalError('invalid_request');
    return Object.freeze({
      ...(query.accountRef === undefined ? {} : { accountRef: nonzeroUUID(query.accountRef) }),
      status: query.status,
      limit: positiveInteger(query.limit, limits ? legalPageLimits(limits).max : 50),
      offset: integer(query.offset, 2147483647),
    });
  });
}

export function validateLegalHoldRequest(request: LegalHoldRequest): LegalHoldRequest {
  return input(() => {
    requestFields(request, [
      'accountRef',
      'requestId',
      'reason',
      'requestingAuthority',
      'legalBasis',
      'reviewAt',
    ]);
    const reviewAt =
      request.reviewAt === undefined || request.reviewAt === ''
        ? undefined
        : utc(request.reviewAt, 6);
    return Object.freeze({
      accountRef: nonzeroUUID(request.accountRef),
      requestId: nonzeroUUID(request.requestId),
      reason: normalizedText(request.reason, 4096),
      requestingAuthority: normalizedText(request.requestingAuthority, 255),
      legalBasis: normalizedText(request.legalBasis, 255),
      ...(reviewAt === undefined ? {} : { reviewAt }),
    });
  });
}

export function validateLegalPreservationRequest(
  request: LegalPreservationRequest
): LegalPreservationRequest {
  return input(() => {
    requestFields(request, [
      'accountRef',
      'requestId',
      'reason',
      'requestingAuthority',
      'expiresAt',
    ]);
    const expiresAt =
      request.expiresAt === undefined || request.expiresAt === ''
        ? undefined
        : utc(request.expiresAt, 6);
    return Object.freeze({
      accountRef: nonzeroUUID(request.accountRef),
      requestId: nonzeroUUID(request.requestId),
      reason: normalizedText(request.reason, 4096),
      requestingAuthority: normalizedText(request.requestingAuthority, 255),
      ...(expiresAt === undefined ? {} : { expiresAt }),
    });
  });
}

export function validateLegalLookupQuery(
  query: LegalLookupQuery,
  limits?: AdminLimits
): LegalLookupQuery {
  return input(() => {
    requestFields(query, [
      'identifier',
      'requestingAuthority',
      'caseReference',
      'purpose',
      'startTime',
      'endTime',
      'limit',
      'fields',
    ]);
    if (
      typeof query.identifier !== 'string' ||
      new TextEncoder().encode(query.identifier).length > 1024
    )
      throw new PortalError('invalid_request');
    const identifier = normalizedText(query.identifier, 1024);
    const parts = identifier.split('@');
    // Preserve input for the backend's NFC/IDNA identity authority. Domain
    // literals and invisible exceptions are not supported signup identities.
    const atom = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~\p{L}\p{N}\p{M}]+$/u;
    const dotAtom = (value: string) => value.split('.').every((piece) => atom.test(piece));
    const domain = parts[1] ?? '';
    const domainDots = domain.replace(/[\u3002\uff0e\uff61]/gu, '.');
    if (
      parts.length !== 2 ||
      /[\p{White_Space}\p{Cc}\p{Cs}\p{Default_Ignorable_Code_Point}]/u.test(identifier) ||
      !dotAtom(parts[0]) ||
      !domain ||
      domainDots.startsWith('.') ||
      domainDots.endsWith('.') ||
      domainDots.includes('..') ||
      /[[\]<>"\\]/u.test(domain)
    )
      throw new PortalError('invalid_request');
    const startTime = utc(query.startTime);
    const endTime = utc(query.endTime);
    const window = timestampNanoseconds(endTime) - timestampNanoseconds(startTime);
    const maxWindow = limits?.audit_max_window_seconds ?? 31 * 24 * 3600;
    if (
      !Number.isFinite(maxWindow) ||
      maxWindow <= 0 ||
      maxWindow > 31 * 24 * 3600 ||
      window < 0n ||
      window > BigInt(Math.floor(maxWindow * 1000000000)) ||
      !Array.isArray(query.fields) ||
      query.fields.length > legalDisclosureFields.length ||
      query.fields.some((field) => !legalDisclosureFields.includes(field)) ||
      new Set(query.fields).size !== query.fields.length
    )
      throw new PortalError('invalid_request');
    return Object.freeze({
      identifier,
      requestingAuthority: normalizedText(query.requestingAuthority, 255),
      caseReference: normalizedText(query.caseReference, 255),
      purpose: normalizedText(query.purpose, 4096),
      startTime,
      endTime,
      limit: positiveInteger(query.limit, limits ? legalPageLimits(limits).max : 50),
      fields: Object.freeze([...query.fields].sort()),
    });
  });
}

export function validateLegalLookupContinuation(
  query: LegalLookupQuery,
  continuation: LegalLookupContinuation
): LegalLookupContinuation {
  return input(() => {
    requestFields(continuation, ['query', 'cursor', 'throughSeq', 'observedAt', 'afterSeq']);
    const scope = validateLegalLookupQuery(continuation.query);
    const throughSeq = decimalString(continuation.throughSeq);
    const afterSeq = decimalString(continuation.afterSeq);
    if (
      JSON.stringify(scope) !== JSON.stringify(validateLegalLookupQuery(query)) ||
      afterSeq === '0' ||
      compareDecimal(afterSeq, throughSeq) >= 0
    )
      throw new PortalError('invalid_request');
    return Object.freeze({
      query: scope,
      cursor: legalCursor(continuation.cursor),
      throughSeq,
      observedAt: adminTimestamp(continuation.observedAt),
      afterSeq,
    });
  });
}

export function legalLookupContinuation(
  query: LegalLookupQuery,
  page: LegalLookupPage
): LegalLookupContinuation | undefined {
  const scope = validateLegalLookupQuery(query);
  const result = legalLookupResponse(page, scope);
  if (result.next_cursor === undefined) return undefined;
  return Object.freeze({
    query: scope,
    cursor: result.next_cursor,
    throughSeq: result.coverage.through_seq,
    observedAt: result.coverage.observed_at,
    afterSeq: result.items[result.items.length - 1].seq,
  });
}
