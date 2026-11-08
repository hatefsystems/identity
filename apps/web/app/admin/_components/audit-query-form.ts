import type { MessageDescriptor } from '../../../i18n/messages';
import type { AdminAuditQuery, AdminLimits } from '../../_lib/admin/contracts';
import { adminTimestamp, validateAuditQuery } from '../../_lib/admin/validation';
import { queryPageSize } from './query-view-state';

export type AuditQueryDraft = { start: string; end: string; event: string; size: string };
export type AuditQueryField = keyof AuditQueryDraft;

export function auditQueryDefaults(limits: AdminLimits, now = Date.now()): AuditQueryDraft {
  const end = Math.floor(now / 1000) * 1000;
  const window = Math.floor(Math.min(86400, limits.audit_max_window_seconds) * 1000);
  return {
    start: new Date(end - window).toISOString().slice(0, -1),
    end: new Date(end).toISOString().slice(0, -1),
    event: '',
    size: String(limits.page_size_default),
  };
}

export function auditQueryFromDraft(
  draft: AuditQueryDraft,
  limits: AdminLimits
):
  | { query: AdminAuditQuery; error?: never }
  | { query?: never; error: { field: AuditQueryField; message: MessageDescriptor } } {
  const times: string[] = [];
  for (const field of ['start', 'end'] as const) {
    try {
      const value = draft[field];
      if (
        value.trim() !== value ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?$/.test(value)
      )
        throw new Error('Invalid UTC input');
      times.push(
        new Date(adminTimestamp(`${value}${value.length === 16 ? ':00' : ''}Z`)).toISOString()
      );
    } catch {
      return { error: { field, message: { key: `audit.validation.${field}` } } };
    }
  }
  const [start_time, end_time] = times;
  const duration = Date.parse(end_time) - Date.parse(start_time);
  if (duration < 0) return { error: { field: 'end', message: { key: 'audit.validation.order' } } };
  if (duration > limits.audit_max_window_seconds * 1000)
    return {
      error: {
        field: 'start',
        message: {
          key: 'audit.validation.window',
          values: { seconds: limits.audit_max_window_seconds },
        },
      },
    };
  const event_type = draft.event.trim();
  if (event_type && !/^[a-z0-9._]{1,100}$/.test(event_type))
    return {
      error: {
        field: 'event',
        message: { key: 'audit.validation.event' },
      },
    };
  const limit = queryPageSize(draft.size, limits.page_size_max);
  if (limit === null)
    return {
      error: {
        field: 'size',
        message: { key: 'audit.validation.size', values: { maximum: limits.page_size_max } },
      },
    };
  return {
    query: validateAuditQuery(
      { start_time, end_time, limit, ...(event_type ? { event_type } : {}) },
      limits
    ),
  };
}
