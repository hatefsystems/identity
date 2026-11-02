import { PortalError } from '../portal/errors';
import { integer, record, text } from '../portal/validation';
import type {
  AdminAuditQuery,
  AdminLimits,
  AdminModerationStatus,
  AdminUserStatus,
  AdminUsersQuery,
  AdminVerifyQuery,
} from './contracts';

export function decimalString(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !/^(0|[1-9][0-9]{0,18})$/.test(value) ||
    value.trim() !== value ||
    (value.length === 19 && value > '9223372036854775807')
  )
    throw new PortalError('invalid_response');
  return value;
}

export function compareDecimal(left: string, right: string): -1 | 0 | 1 {
  const a = decimalString(left);
  const b = decimalString(right);
  if (a === b) return 0;
  return a.length === b.length ? (a < b ? -1 : 1) : a.length < b.length ? -1 : 1;
}

export function digest(value: unknown): string {
  const result = text(value, 64);
  if (!/^[a-f0-9]{64}$/.test(result)) throw new PortalError('invalid_response');
  return result;
}

export function uuid(value: unknown): string {
  const result = text(value, 36);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(result))
    throw new PortalError('invalid_response');
  return result;
}

export function nonzeroUUID(value: unknown): string {
  const result = uuid(value);
  if (result === '00000000-0000-0000-0000-000000000000')
    throw new PortalError('invalid_response');
  return result;
}

export function adminTimestamp(value: unknown): string {
  const result = text(value, 64);
  if (
    !/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(
      result
    ) ||
    result.trim() !== result ||
    !Number.isFinite(Date.parse(result)) ||
    !Number.isFinite(Date.parse(`${result.slice(0, 10)}T00:00:00Z`)) ||
    new Date(`${result.slice(0, 10)}T00:00:00Z`).toISOString().slice(0, 10) !== result.slice(0, 10)
  )
    throw new PortalError('invalid_response');
  return result;
}

export function timestampNanoseconds(value: string): bigint {
  const timestamp = adminTimestamp(value);
  const fraction = /\.(\d+)/.exec(timestamp)?.[1] ?? '';
  return BigInt(Date.parse(timestamp)) * 1000000n + BigInt(fraction.padEnd(9, '0').slice(3));
}

export function userStatus(value: unknown): AdminUserStatus {
  if (
    !['active', 'suspended', 'banned', 'pending_verification', 'pending_deletion'].includes(
      text(value, 32)
    )
  )
    throw new PortalError('invalid_response');
  return value as AdminUserStatus;
}

export function moderationStatus(value: unknown): AdminModerationStatus {
  if (!['active', 'suspended', 'banned'].includes(text(value, 32)))
    throw new PortalError('invalid_request');
  return value as AdminModerationStatus;
}

export function normalizeModerationReason(value: string): string {
  if (typeof value !== 'string' || /\p{Cs}/u.test(value)) throw new PortalError('invalid_request');
  const reason = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
  if (!reason || new TextEncoder().encode(reason).length > 2000)
    throw new PortalError('invalid_request');
  return reason;
}

export function requestFields(value: unknown, keys: readonly string[]): void {
  const item = record(value);
  if (
    (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null) ||
    Object.keys(item).some((key) => !keys.includes(key))
  )
    throw new PortalError('invalid_request');
}

export function positiveInteger(value: unknown, max: number): number {
  const result = integer(value, max);
  if (result === 0) throw new PortalError('invalid_response');
  return result;
}

export function validateUsersQuery(query: AdminUsersQuery): AdminUsersQuery {
  requestFields(query, ['limit', 'offset', 'status']);
  return {
    ...(query.limit === undefined ? {} : { limit: positiveInteger(query.limit, 200) }),
    ...(query.offset === undefined ? {} : { offset: integer(query.offset, 2147483647) }),
    ...(query.status === undefined ? {} : { status: userStatus(query.status) }),
  };
}

export function validateAuditQuery(query: AdminAuditQuery, limits?: AdminLimits): AdminAuditQuery {
  requestFields(query, ['start_time', 'end_time', 'event_type', 'limit', 'before_seq']);
  const utc = (value: string) => {
    // datetime-local controls in this form are explicitly labelled UTC.
    let source = value;
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(source)) source += ':00Z';
    else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/.test(source)) source += 'Z';
    const timestamp = adminTimestamp(source);
    const fraction = /\.(\d+)/.exec(timestamp)?.[1] ?? '';
    return adminTimestamp(
      new Date(timestamp).toISOString().replace(/\.\d{3}Z$/, `.${fraction.padEnd(3, '0')}Z`)
    );
  };
  const start_time = utc(query.start_time);
  const end_time = utc(query.end_time);
  const window = timestampNanoseconds(end_time) - timestampNanoseconds(start_time);
  const maxWindow = limits?.audit_max_window_seconds ?? 31 * 24 * 3600;
  if (
    !Number.isFinite(maxWindow) ||
    maxWindow <= 0 ||
    maxWindow > 31 * 24 * 3600 ||
    window < 0n ||
    window > BigInt(Math.floor(maxWindow * 1000000000))
  )
    throw new PortalError('invalid_request');
  const event_type =
    query.event_type === undefined ? undefined : text(query.event_type, 100).trim();
  if (event_type !== undefined && !/^[a-z0-9._]{1,100}$/.test(event_type))
    throw new PortalError('invalid_request');
  return {
    start_time,
    end_time,
    ...(event_type === undefined ? {} : { event_type }),
    ...(query.limit === undefined
      ? {}
      : { limit: positiveInteger(query.limit, Math.min(limits?.page_size_max ?? 200, 200)) }),
    ...(query.before_seq === undefined ? {} : { before_seq: decimalString(query.before_seq) }),
  };
}

export function validateVerifyQuery(query: AdminVerifyQuery): AdminVerifyQuery {
  requestFields(query, ['after_seq', 'through_seq', 'predecessor_hash', 'limit']);
  const after_seq = query.after_seq === undefined ? '0' : decimalString(query.after_seq);
  const through_seq =
    query.through_seq === undefined ? undefined : decimalString(query.through_seq);
  if (
    (after_seq !== '0' && through_seq === undefined) ||
    (through_seq !== undefined && compareDecimal(after_seq, through_seq) > 0)
  )
    throw new PortalError('invalid_request');
  return {
    after_seq,
    ...(through_seq === undefined ? {} : { through_seq }),
    ...(query.predecessor_hash === undefined
      ? {}
      : { predecessor_hash: digest(query.predecessor_hash) }),
    ...(query.limit === undefined ? {} : { limit: positiveInteger(query.limit, 5000) }),
  };
}
