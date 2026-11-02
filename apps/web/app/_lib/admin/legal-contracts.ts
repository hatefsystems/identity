import { PortalError } from '../portal/errors';
import { boolean, integer, list, record, text } from '../portal/validation';
import {
  adminTimestamp,
  compareDecimal,
  decimalString,
  nonzeroUUID,
  positiveInteger,
  timestampNanoseconds,
} from './validation';

export const legalDisclosureFields = Object.freeze([
  'client_ip',
  'ip_subnet',
  'user_agent',
  'device_fingerprint',
  'client_id',
  'scope',
] as const);

export type LegalDisclosureField = (typeof legalDisclosureFields)[number];
export type LegalRequestKind = 'legal_hold' | 'preservation';
export type LegalHoldStatus = 'active' | 'released' | 'all';
export type LegalHoldsQuery = Readonly<{
  accountRef?: string;
  status: LegalHoldStatus;
  limit: number;
  offset: number;
}>;
export type LegalHoldRequest = Readonly<{
  accountRef: string;
  requestId: string;
  reason: string;
  requestingAuthority: string;
  legalBasis: string;
  reviewAt?: string;
}>;
export type LegalPreservationRequest = Readonly<{
  accountRef: string;
  requestId: string;
  reason: string;
  requestingAuthority: string;
  expiresAt?: string;
}>;
export type LegalHold = {
  id: string;
  account_ref: string;
  request_kind: LegalRequestKind;
  reason?: string;
  requesting_authority?: string;
  legal_basis?: string;
  applied_by: string;
  is_active: boolean;
  applied_at: string | null;
  review_at: string | null;
  released_at: string | null;
  released_by: string | null;
  details_purged: boolean;
  replayed: boolean;
};
export type LegalHoldsPage = { items: LegalHold[]; total: number; limit: number; offset: number };
export type LegalPreservationResult = {
  hold: LegalHold;
  replayed: boolean;
  account_present: boolean;
  ledger_evidence_present: boolean;
  observed_at: string;
  note: string;
};
export type LegalLookupQuery = Readonly<{
  identifier: string;
  requestingAuthority: string;
  caseReference: string;
  purpose: string;
  startTime: string;
  endTime: string;
  limit: number;
  fields: readonly LegalDisclosureField[];
}>;
export type LegalLookupItem = {
  id: string;
  account_ref: string;
  event_type: string;
  timestamp: string | null;
  retain_until: string | null;
  seq: string;
} & Partial<Record<LegalDisclosureField, string>>;
export type LegalLookupCoverage = {
  through_seq: string;
  observed_at: string;
  eligibility_checked_at: string;
  note: string;
};
export type LegalLookupPage = {
  items: LegalLookupItem[];
  next_cursor?: string;
  coverage: LegalLookupCoverage;
};
export type LegalLookupContinuation = Readonly<{
  query: LegalLookupQuery;
  cursor: string;
  throughSeq: string;
  observedAt: string;
  afterSeq: string;
}>;

function legalRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const item = record(value);
  if (
    (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null) ||
    Object.keys(item).some((key) => !keys.includes(key))
  )
    throw new PortalError('invalid_response');
  return item;
}

function legalText(value: unknown, max = 4 * 1024 * 1024, nonblank = false): string {
  const result = text(value, max);
  if (
    /\p{Cs}/u.test(result) ||
    new TextEncoder().encode(result).length > max ||
    (nonblank && !result.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, ''))
  )
    throw new PortalError('invalid_response');
  return result;
}

function nullable<T>(value: unknown, decode: (value: unknown) => T): T | null {
  return value === null ? null : decode(value);
}

export function legalHoldResponse(value: unknown): LegalHold {
  const item = legalRecord(value, [
    'id',
    'account_ref',
    'request_kind',
    'reason',
    'requesting_authority',
    'legal_basis',
    'applied_by',
    'is_active',
    'applied_at',
    'review_at',
    'released_at',
    'released_by',
    'details_purged',
    'replayed',
  ]);
  if (item.request_kind !== 'legal_hold' && item.request_kind !== 'preservation')
    throw new PortalError('invalid_response');
  const result: LegalHold = {
    id: nonzeroUUID(item.id),
    account_ref: nonzeroUUID(item.account_ref),
    request_kind: item.request_kind,
    ...(item.reason === undefined ? {} : { reason: legalText(item.reason, 4096, true) }),
    ...(item.requesting_authority === undefined
      ? {}
      : { requesting_authority: legalText(item.requesting_authority, 255, true) }),
    ...(item.legal_basis === undefined
      ? {}
      : { legal_basis: legalText(item.legal_basis, 255, true) }),
    applied_by: nonzeroUUID(item.applied_by),
    is_active: boolean(item.is_active),
    applied_at: nullable(item.applied_at, adminTimestamp),
    review_at: nullable(item.review_at, adminTimestamp),
    released_at: nullable(item.released_at, adminTimestamp),
    released_by: nullable(item.released_by, nonzeroUUID),
    details_purged: boolean(item.details_purged),
    replayed: boolean(item.replayed),
  };
  if (
    (result.is_active && (result.released_at !== null || result.released_by !== null)) ||
    (result.details_purged
      ? result.is_active ||
        result.reason !== undefined ||
        result.requesting_authority !== undefined ||
        result.legal_basis !== undefined
      : result.reason === undefined ||
        result.requesting_authority === undefined ||
        result.legal_basis === undefined ||
        (result.request_kind === 'preservation' && result.legal_basis !== 'preservation_request'))
  )
    throw new PortalError('invalid_response');
  return result;
}

export function legalHoldsResponse(value: unknown, query: LegalHoldsQuery): LegalHoldsPage {
  const item = legalRecord(value, ['items', 'total', 'limit', 'offset']);
  const result = {
    items: list(item.items, legalHoldResponse, 50),
    total: integer(item.total, Number.MAX_SAFE_INTEGER),
    limit: positiveInteger(item.limit, 50),
    offset: integer(item.offset, 2147483647),
  };
  if (
    result.offset !== query.offset ||
    result.limit !== query.limit ||
    result.items.length !== Math.min(result.limit, Math.max(0, result.total - result.offset)) ||
    new Set(result.items.map((hold) => hold.id)).size !== result.items.length ||
    result.items.some(
      (hold) =>
        hold.replayed ||
        (query.accountRef !== undefined && hold.account_ref !== query.accountRef) ||
        (query.status !== 'all' && hold.is_active !== (query.status === 'active'))
    )
  )
    throw new PortalError('invalid_response');
  return result;
}

export function legalCreateResponse(
  value: unknown,
  status: number,
  request: LegalHoldRequest | LegalPreservationRequest,
  kind: LegalRequestKind
): LegalHold | LegalPreservationResult {
  let result: LegalHold | LegalPreservationResult;
  if (kind === 'preservation') {
    const item = legalRecord(value, [
      'hold',
      'replayed',
      'account_present',
      'ledger_evidence_present',
      'observed_at',
      'note',
    ]);
    result = {
      hold: legalHoldResponse(item.hold),
      replayed: boolean(item.replayed),
      account_present: boolean(item.account_present),
      ledger_evidence_present: boolean(item.ledger_evidence_present),
      observed_at: adminTimestamp(item.observed_at),
      note: legalText(item.note, 4096, true),
    };
  } else {
    result = legalHoldResponse(value);
  }
  const hold = 'hold' in result ? result.hold : result;
  const date =
    kind === 'preservation'
      ? (request as LegalPreservationRequest).expiresAt
      : (request as LegalHoldRequest).reviewAt;
  if (
    status !== (result.replayed ? 200 : 201) ||
    (!result.replayed && !hold.is_active) ||
    hold.details_purged ||
    hold.account_ref !== request.accountRef ||
    hold.request_kind !== kind ||
    hold.reason !== request.reason ||
    hold.requesting_authority !== request.requestingAuthority ||
    hold.legal_basis !==
      (kind === 'preservation'
        ? 'preservation_request'
        : (request as LegalHoldRequest).legalBasis) ||
    (date === undefined
      ? hold.review_at !== null
      : hold.review_at === null ||
        timestampNanoseconds(hold.review_at) !== timestampNanoseconds(date))
  )
    throw new PortalError('invalid_response');
  return result;
}

export function legalCursor(value: unknown): string {
  const result = text(value, 4096);
  if (!/^[A-Za-z0-9_-]+$/.test(result) || result.trim() !== result)
    throw new PortalError('invalid_response');
  return result;
}

export function legalLookupResponse(
  value: unknown,
  query: LegalLookupQuery,
  continuation?: LegalLookupContinuation
): LegalLookupPage {
  const item = legalRecord(value, ['items', 'next_cursor', 'coverage']);
  const coverage = legalRecord(item.coverage, [
    'through_seq',
    'observed_at',
    'eligibility_checked_at',
    'note',
  ]);
  const result: LegalLookupPage = {
    items: list(
      item.items,
      (value): LegalLookupItem => {
        const row = legalRecord(value, [
          'id',
          'account_ref',
          'event_type',
          'timestamp',
          'retain_until',
          'seq',
          ...query.fields,
        ]);
        const projected: LegalLookupItem = {
          id: nonzeroUUID(row.id),
          account_ref: nonzeroUUID(row.account_ref),
          event_type: legalText(row.event_type, 100, true),
          timestamp: nullable(row.timestamp, adminTimestamp),
          retain_until: nullable(row.retain_until, adminTimestamp),
          seq: decimalString(row.seq),
        };
        for (const field of query.fields) {
          if (row[field] !== undefined) projected[field] = legalText(row[field]);
        }
        return projected;
      },
      50
    ),
    ...(item.next_cursor === undefined ? {} : { next_cursor: legalCursor(item.next_cursor) }),
    coverage: {
      through_seq: decimalString(coverage.through_seq),
      observed_at: adminTimestamp(coverage.observed_at),
      eligibility_checked_at: adminTimestamp(coverage.eligibility_checked_at),
      note: legalText(coverage.note, 4096, true),
    },
  };
  const start = timestampNanoseconds(query.startTime);
  const end = timestampNanoseconds(query.endTime);
  const last = result.items.at(-1);
  if (
    result.items.length > query.limit ||
    timestampNanoseconds(result.coverage.eligibility_checked_at) <
      timestampNanoseconds(result.coverage.observed_at) ||
    (continuation !== undefined &&
      (result.coverage.through_seq !== continuation.throughSeq ||
        result.coverage.observed_at !== continuation.observedAt)) ||
    (result.next_cursor !== undefined &&
      (result.items.length !== query.limit ||
        !last ||
        compareDecimal(last.seq, result.coverage.through_seq) >= 0 ||
        result.next_cursor === continuation?.cursor)) ||
    new Set(result.items.map((row) => row.id)).size !== result.items.length ||
    result.items.some(
      (row, index) =>
        compareDecimal(
          row.seq,
          index === 0 ? (continuation?.afterSeq ?? '0') : result.items[index - 1].seq
        ) <= 0 ||
        compareDecimal(row.seq, result.coverage.through_seq) > 0 ||
        row.timestamp === null ||
        timestampNanoseconds(row.timestamp) < start ||
        timestampNanoseconds(row.timestamp) > end
    )
  )
    throw new PortalError('invalid_response');
  return result;
}
