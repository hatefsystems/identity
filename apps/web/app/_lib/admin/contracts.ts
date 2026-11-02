import { PortalError } from '../portal/errors';
import { boolean, integer, list, record, text } from '../portal/validation';
import {
  adminTimestamp,
  compareDecimal,
  decimalString,
  digest,
  positiveInteger,
  userStatus,
  uuid,
} from './validation';

export type AdminLimits = {
  page_size_default: number;
  page_size_max: number;
  audit_max_window_seconds: number;
  chain_verify_max_limit: number;
};

export type AdminCapabilities = {
  capabilities: {
    users_read: boolean;
    users_pii: boolean;
    users_lookup: boolean;
    users_status_write: boolean;
    audit_logs_read: boolean;
    audit_chain_verify: boolean;
    ledger_verify: boolean;
    legal_holds_read: boolean;
    legal_holds_apply: boolean;
    legal_holds_release: boolean;
    preservation_requests_create: boolean;
    legal_inquiry_lookup: boolean;
  };
  limits: AdminLimits;
};

export type AdminUserStatus =
  'active' | 'suspended' | 'banned' | 'pending_verification' | 'pending_deletion';
export type AdminModerationStatus = 'active' | 'suspended' | 'banned';
export type AdminUser = {
  id: string;
  email?: string;
  status: AdminUserStatus;
  is_mfa_enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
  deleted_at: string | null;
  lifecycle_revision: string;
};
export type AdminStatusUpdate = {
  status: AdminModerationStatus;
  reason: string;
  expected_revision: string;
};
export type AdminUsersQuery = { limit?: number; offset?: number; status?: AdminUserStatus };
export type AdminUsersPage = { items: AdminUser[]; total: number; limit: number; offset: number };

export type AdminAuditLog = {
  id: string;
  user_id: string | null;
  actor_id: string;
  actor_spiffe_id: string;
  event_type: string;
  action_status: string;
  client_ip: string;
  user_agent: string;
  payload: string;
  timestamp: string | null;
  sha256_leaf_hash: string;
  sha256_chain_hash: string;
  seq: string;
};
export type AdminAuditQuery = {
  start_time: string;
  end_time: string;
  event_type?: string;
  limit?: number;
  before_seq?: string;
};
export type AdminAuditPage = {
  items: AdminAuditLog[];
  limit: number;
  has_more: boolean;
  next_before_seq: string;
};
export type AdminChain = 'audit' | 'ledger';
// GoldenAuditGenesisHex / GoldenLedgerGenesisHex in identity-api/internal/audit/chain.go.
const genesisHashes = {
  audit: '5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb',
  ledger: '6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54',
} as const;
export type AdminVerifyQuery = {
  after_seq?: string;
  through_seq?: string;
  predecessor_hash?: string;
  limit?: number;
};
export type AdminVerificationFailure =
  | 'predecessor_mismatch'
  | 'no_stored_records'
  | 'invalid_leaf_hash'
  | 'invalid_chain_hash'
  | 'chain_mismatch'
  | 'record_not_serializable'
  | 'leaf_mismatch'
  | 'payload_absent_without_erasure_record'
  | 'head_mismatch';
export type AdminVerification = {
  failure_reason?: AdminVerificationFailure;
  after_seq: string;
  through_seq: string;
  seed_hash: string;
  seed_source: 'genesis' | 'database_predecessor' | 'supplied_predecessor';
  scope: string;
  last_hash: string;
  complete: boolean;
  verified: boolean;
  checked: number;
  first_seq: string | null;
  last_seq: string | null;
  broken_at_seq: string | null;
  expected_hash: string | null;
  stored_hash: string | null;
  next_after_seq: string | null;
} & ({ chain: 'audit'; erased_checked?: never } | { chain: 'ledger'; erased_checked: number });

function nullable<T>(value: unknown, decode: (value: unknown) => T): T | null {
  return value === null ? null : decode(value);
}

export function capabilitiesResponse(value: unknown): AdminCapabilities {
  const item = record(value);
  const flags = record(item.capabilities);
  const limits = record(item.limits);
  if (
    typeof limits.audit_max_window_seconds !== 'number' ||
    !Number.isFinite(limits.audit_max_window_seconds) ||
    limits.audit_max_window_seconds <= 0 ||
    limits.audit_max_window_seconds > 31 * 24 * 3600
  )
    throw new PortalError('invalid_response');
  const result: AdminCapabilities = {
    capabilities: {
      users_read: boolean(flags.users_read),
      users_pii: boolean(flags.users_pii),
      users_lookup: boolean(flags.users_lookup),
      users_status_write: boolean(flags.users_status_write),
      audit_logs_read: boolean(flags.audit_logs_read),
      audit_chain_verify: boolean(flags.audit_chain_verify),
      ledger_verify: boolean(flags.ledger_verify),
      legal_holds_read: boolean(flags.legal_holds_read),
      legal_holds_apply: boolean(flags.legal_holds_apply),
      legal_holds_release: boolean(flags.legal_holds_release),
      preservation_requests_create: boolean(flags.preservation_requests_create),
      legal_inquiry_lookup: boolean(flags.legal_inquiry_lookup),
    },
    limits: {
      page_size_default: positiveInteger(limits.page_size_default, 200),
      page_size_max: positiveInteger(limits.page_size_max, 200),
      audit_max_window_seconds: limits.audit_max_window_seconds,
      chain_verify_max_limit: positiveInteger(limits.chain_verify_max_limit, 5000),
    },
  };
  if (
    result.limits.page_size_default > result.limits.page_size_max ||
    (result.capabilities.users_lookup &&
      (!result.capabilities.users_read || !result.capabilities.users_pii))
  )
    throw new PortalError('invalid_response');
  return result;
}

export function userResponse(value: unknown): AdminUser {
  const item = record(value);
  return {
    id: uuid(item.id),
    ...(item.email === undefined ? {} : { email: text(item.email, 320) }),
    status: userStatus(item.status),
    is_mfa_enabled: boolean(item.is_mfa_enabled),
    created_at: nullable(item.created_at, adminTimestamp),
    updated_at: nullable(item.updated_at, adminTimestamp),
    deleted_at: nullable(item.deleted_at, adminTimestamp),
    lifecycle_revision: decimalString(item.lifecycle_revision),
  };
}

export function usersResponse(value: unknown): AdminUsersPage {
  const item = record(value);
  const result = {
    items: list(item.items, userResponse, 200),
    total: integer(item.total, Number.MAX_SAFE_INTEGER),
    limit: positiveInteger(item.limit, 200),
    offset: integer(item.offset, 2147483647),
  };
  if (
    result.items.length !== Math.min(result.limit, Math.max(0, result.total - result.offset)) ||
    new Set(result.items.map((user) => user.id)).size !== result.items.length
  )
    throw new PortalError('invalid_response');
  return result;
}

export function auditLogResponse(value: unknown): AdminAuditLog {
  const item = record(value);
  const seq = decimalString(item.seq);
  if (seq === '0') throw new PortalError('invalid_response');
  return {
    id: uuid(item.id),
    user_id: nullable(item.user_id, uuid),
    actor_id: uuid(item.actor_id),
    actor_spiffe_id: text(item.actor_spiffe_id, 2048),
    event_type: text(item.event_type, 100),
    action_status: text(item.action_status, 32),
    client_ip: text(item.client_ip, 64),
    user_agent: text(item.user_agent, 8192),
    // A bounded string, never parsed as an object, linked, or interpreted as HTML.
    payload: text(item.payload, 4 * 1024 * 1024),
    timestamp: nullable(item.timestamp, adminTimestamp),
    sha256_leaf_hash: digest(item.sha256_leaf_hash),
    sha256_chain_hash: digest(item.sha256_chain_hash),
    seq,
  };
}

export function auditPageResponse(value: unknown): AdminAuditPage {
  const item = record(value);
  const result = {
    items: list(item.items, auditLogResponse, 200),
    limit: positiveInteger(item.limit, 200),
    has_more: boolean(item.has_more),
    next_before_seq: decimalString(item.next_before_seq),
  };
  const last = result.items.at(-1);
  if (
    result.items.length > result.limit ||
    (result.has_more && result.items.length !== result.limit) ||
    result.next_before_seq !== (last?.seq ?? '0') ||
    new Set(result.items.map((row) => row.id)).size !== result.items.length ||
    result.items.some(
      (row, index) => index > 0 && compareDecimal(result.items[index - 1].seq, row.seq) <= 0
    )
  )
    throw new PortalError('invalid_response');
  return result;
}

export function verificationResponse(value: unknown): AdminVerification {
  const item = record(value);
  if (item.chain !== 'audit' && item.chain !== 'ledger') throw new PortalError('invalid_response');
  const scope =
    item.chain === 'audit'
      ? 'stored_segment_relative_to_seed; not complete ingestion, tail-truncation detection, or independent historical authenticity'
      : 'database_relative_chain_and_retained_payloads; erased payloads are authorized by erasure records, not recomputed; not complete ingestion or independent historical authenticity';
  if (item.scope !== scope) throw new PortalError('invalid_response');
  if (
    !['genesis', 'database_predecessor', 'supplied_predecessor'].includes(
      text(item.seed_source, 32)
    )
  )
    throw new PortalError('invalid_response');
  const failures: readonly string[] = [
    'predecessor_mismatch',
    'no_stored_records',
    'invalid_leaf_hash',
    'invalid_chain_hash',
    'chain_mismatch',
    'record_not_serializable',
    'leaf_mismatch',
    'payload_absent_without_erasure_record',
    'head_mismatch',
  ];
  if (item.failure_reason !== undefined && !failures.includes(text(item.failure_reason, 64)))
    throw new PortalError('invalid_response');
  const result: AdminVerification = {
    ...(item.chain === 'ledger'
      ? { chain: 'ledger', erased_checked: integer(item.erased_checked, 5000) }
      : { chain: 'audit' }),
    ...(item.failure_reason === undefined
      ? {}
      : { failure_reason: item.failure_reason as AdminVerificationFailure }),
    after_seq: decimalString(item.after_seq),
    through_seq: decimalString(item.through_seq),
    seed_hash: digest(item.seed_hash),
    seed_source: item.seed_source as AdminVerification['seed_source'],
    scope: text(item.scope, 1024),
    last_hash: digest(item.last_hash),
    complete: boolean(item.complete),
    verified: boolean(item.verified),
    checked: integer(item.checked, 5000),
    first_seq: nullable(item.first_seq, decimalString),
    last_seq: nullable(item.last_seq, decimalString),
    broken_at_seq: nullable(item.broken_at_seq, decimalString),
    expected_hash: nullable(item.expected_hash, digest),
    stored_hash: nullable(item.stored_hash, digest),
    next_after_seq: nullable(item.next_after_seq, decimalString),
  };
  const { after_seq: after, through_seq: through, first_seq: first, last_seq: last } = result;
  if (
    !result.scope ||
    compareDecimal(after, through) > 0 ||
    (result.erased_checked ?? 0) > result.checked ||
    (result.seed_source === 'genesis' &&
      (after !== '0' || result.seed_hash !== genesisHashes[result.chain])) ||
    (result.seed_source === 'database_predecessor' && after === '0')
  )
    throw new PortalError('invalid_response');
  if (result.checked === 0) {
    if (first !== null || last !== null || result.last_hash !== result.seed_hash)
      throw new PortalError('invalid_response');
  } else if (
    first === null ||
    last === null ||
    compareDecimal(first, after) <= 0 ||
    compareDecimal(first, last) > 0 ||
    compareDecimal(last, through) > 0 ||
    (result.checked === 1 && first !== last) ||
    BigInt(last) - BigInt(first) + 1n < BigInt(result.checked)
  ) {
    throw new PortalError('invalid_response');
  }
  if (result.verified) {
    if (
      result.failure_reason !== undefined ||
      result.broken_at_seq !== null ||
      result.expected_hash !== null ||
      result.stored_hash !== null
    )
      throw new PortalError('invalid_response');
    if (result.complete) {
      if ((last ?? after) !== through) throw new PortalError('invalid_response');
      // Canonical-v2 can still return a cursor on a complete page. Do not follow it.
    } else if (
      last === null ||
      compareDecimal(last, through) >= 0 ||
      result.next_after_seq !== last
    ) {
      throw new PortalError('invalid_response');
    }
  } else {
    if (result.complete || result.failure_reason === undefined)
      throw new PortalError('invalid_response');
    const reason = result.failure_reason;
    const broken = result.broken_at_seq;
    if (reason === 'no_stored_records') {
      if (result.checked !== 0 || broken !== null || compareDecimal(after, through) >= 0)
        throw new PortalError('invalid_response');
    } else if (reason === 'predecessor_mismatch') {
      if (result.checked !== 0 || broken !== after || result.seed_source !== 'supplied_predecessor')
        throw new PortalError('invalid_response');
    } else if (
      broken === null ||
      compareDecimal(broken, after) <= 0 ||
      compareDecimal(broken, through) > 0 ||
      (['invalid_leaf_hash', 'invalid_chain_hash'].includes(reason)
        ? compareDecimal(broken, last ?? after) <= 0
        : broken !== last)
    ) {
      throw new PortalError('invalid_response');
    }
    const mismatch = [
      'predecessor_mismatch',
      'chain_mismatch',
      'leaf_mismatch',
      'head_mismatch',
    ].includes(reason);
    if (
      mismatch
        ? result.expected_hash === null || result.stored_hash === null
        : result.expected_hash !== null || result.stored_hash !== null
    )
      throw new PortalError('invalid_response');
    if (
      (reason === 'predecessor_mismatch' && result.expected_hash !== result.seed_hash) ||
      (reason === 'head_mismatch' &&
        (last !== through || result.expected_hash !== result.last_hash)) ||
      (mismatch && reason !== 'head_mismatch' && result.expected_hash === result.stored_hash)
    )
      throw new PortalError('invalid_response');
  }
  return result;
}
