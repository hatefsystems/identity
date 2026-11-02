'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useId, useRef, useState, type FormEvent } from 'react';
import { controlClass, Feedback, inputClass, PageHeading, Panel } from '../../_components/controls';
import { NativeDialog } from '../../_components/native-dialog';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type {
  AdminAuditLog,
  AdminAuditPage,
  AdminAuditQuery,
  AdminLimits,
} from '../../_lib/admin/contracts';
import type { PortalClient } from '../../_lib/portal/client';
import { isAborted, PortalError } from '../../_lib/portal/errors';
import { clearSensitiveViews } from '../../_lib/portal/invalidation';
import {
  auditQueryDefaults,
  auditQueryFromDraft,
  type AuditQueryDraft,
  type AuditQueryField,
} from './audit-query-form';
import {
  queryCellClass,
  queryClearedMessage,
  queryFailureMessage,
  queryHeadClass,
  queryTableFrameClass,
  revealQueryFocus,
  useQueryViewWork,
} from './query-view-state';
import { QueryUtcTime } from './query-view-time';

export const auditCursorHistoryLimit = 20;
type CursorHistory = { cursors: (string | undefined)[]; position: number; dropped: boolean };
const firstPage = (): CursorHistory => ({ cursors: [undefined], position: 0, dropped: false });

export function AuditView() {
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  return (
    <>
      <PageHeading title="Audit logs">
        Search bounded UTC windows. Raw events are sensitive disclosures, not independently verified
        evidence.
      </PageHeading>
      {capabilities?.capabilities.audit_logs_read ? (
        <AuditQuery
          key={profile.session.id}
          client={client}
          limits={capabilities.limits}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error="This workspace does not grant raw audit-log access. No audit records were requested." />
      )}
    </>
  );
}

function AuditQuery({
  client,
  limits,
  reportPermissionLoss,
}: {
  client: PortalClient;
  limits: AdminLimits;
  reportPermissionLoss: () => void;
}) {
  const [draft, setDraft] = useState(() => auditQueryDefaults(limits));
  const [submitted, setSubmitted] = useState<AdminAuditQuery | null>(null);
  const [history, setHistory] = useState<CursorHistory>(firstPage);
  const [page, setPage] = useState<AdminAuditPage | null>(null);
  const [detail, setDetail] = useState<AdminAuditLog | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState(
    'Review the UTC window, then search explicitly. No query has run.'
  );
  const [error, setError] = useState('');
  const [inputError, setInputError] = useState<{ field: AuditQueryField; message: string } | null>(
    null
  );
  const form = useRef<HTMLFormElement>(null);
  const id = useId();
  const { work, cleared } = useQueryViewWork(() => {
    setDraft({ start: '', end: '', event: '', size: '' });
    setSubmitted(null);
    setHistory(firstPage());
    setPage(null);
    setDetail(null);
    setPending(false);
    setStatus('');
    setError('');
    setInputError(null);
  });

  function edit(next: AuditQueryDraft) {
    work.cancel();
    setDraft(next);
    setSubmitted(null);
    setHistory(firstPage());
    setPage(null);
    setDetail(null);
    setPending(false);
    setError('');
    setInputError(null);
    setStatus(
      'Filters changed. Search explicitly to load results; previous cursor history was cleared.'
    );
  }

  async function readPage(query: AdminAuditQuery, navigation: CursorHistory) {
    const controller = work.begin();
    if (!controller) return;
    setPage(null);
    setDetail(null);
    setPending(true);
    setError('');
    setStatus('Loading one audit-log page...');
    try {
      const before_seq = navigation.cursors[navigation.position];
      const result = await new AdminClient(client).auditLogs(
        { ...query, ...(before_seq === undefined ? {} : { before_seq }) },
        controller.signal
      );
      if (!work.current(controller)) return;
      setPage(result);
      setSubmitted(query);
      setHistory(navigation);
      setStatus(
        `${result.items.length} records loaded on this page. ${result.has_more ? 'Older matching records are available.' : 'No older matching records were reported for this request.'}`
      );
    } catch (failure) {
      if (!work.current(controller) || isAborted(failure)) return;
      setPage(null);
      setSubmitted(null);
      setHistory(firstPage());
      setStatus('');
      setError(queryFailureMessage(failure));
      if (failure instanceof PortalError && failure.status === 403) {
        clearSensitiveViews();
        reportPermissionLoss();
      }
    } finally {
      if (work.current(controller)) setPending(false);
      work.finish(controller);
    }
  }

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending || work.blocked) return;
    const result = auditQueryFromDraft(draft, limits);
    if (result.error) {
      setInputError(result.error);
      const field = form.current?.elements.namedItem(result.error.field);
      if (field instanceof HTMLElement) field.focus();
      return;
    }
    setInputError(null);
    setSubmitted(null);
    setHistory(firstPage());
    void readPage(result.query, firstPage());
  }

  function older() {
    if (!submitted || !page?.has_more || pending) return;
    const cursors = [...history.cursors.slice(0, history.position + 1), page.next_before_seq];
    const dropped = history.dropped || cursors.length > auditCursorHistoryLimit;
    if (cursors.length > auditCursorHistoryLimit) cursors.shift();
    void readPage(submitted, { cursors, position: cursors.length - 1, dropped });
  }

  if (cleared) return <Feedback status={queryClearedMessage} />;
  return (
    <>
      <Panel title="Bounded event query" id={`${id}-heading`}>
        <form
          ref={form}
          aria-label="Search audit logs"
          noValidate
          onSubmit={search}
          autoComplete="off"
          className="min-w-0 space-y-4"
        >
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            {(['start', 'end'] as const).map((field) => (
              <div key={field} className="min-w-0 space-y-2">
                <Label htmlFor={`${id}-${field}`}>
                  {field === 'start' ? 'Start time (UTC)' : 'End time (UTC)'}
                </Label>
                <Input
                  id={`${id}-${field}`}
                  name={field}
                  type="datetime-local"
                  step="0.001"
                  value={draft[field]}
                  className={`${inputClass} max-w-full`}
                  aria-invalid={inputError?.field === field}
                  aria-describedby={`${id}-window-help${inputError?.field === field ? ` ${id}-input-error` : ''}`}
                  onChange={(event) => edit({ ...draft, [field]: event.target.value })}
                />
              </div>
            ))}
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-event`}>Event type (exact)</Label>
              <Input
                id={`${id}-event`}
                name="event"
                value={draft.event}
                maxLength={100}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                className={inputClass}
                aria-invalid={inputError?.field === 'event'}
                aria-describedby={`${id}-event-help${inputError?.field === 'event' ? ` ${id}-input-error` : ''}`}
                onChange={(event) => edit({ ...draft, event: event.target.value })}
              />
              <p id={`${id}-event-help`} className="text-sm text-muted-foreground">
                Optional. Up to 100 lowercase letters, digits, periods, or underscores. No patterns
                or partial matching.
              </p>
            </div>
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-size`}>Page size</Label>
              <Input
                id={`${id}-size`}
                name="size"
                type="number"
                min={1}
                max={limits.page_size_max}
                step={1}
                value={draft.size}
                className={inputClass}
                aria-invalid={inputError?.field === 'size'}
                aria-describedby={`${id}-size-help${inputError?.field === 'size' ? ` ${id}-input-error` : ''}`}
                onChange={(event) => edit({ ...draft, size: event.target.value })}
              />
              <p id={`${id}-size-help`} className="text-sm text-muted-foreground">
                1-{limits.page_size_max} records per request.
              </p>
            </div>
          </div>
          <p id={`${id}-window-help`} className="text-sm text-muted-foreground">
            All times are UTC, not your browser&apos;s local timezone. Maximum window:{' '}
            {limits.audit_max_window_seconds} seconds. The last-24-hours default is shortened when
            the configured maximum is smaller.
          </p>
          {inputError && (
            <p
              id={`${id}-input-error`}
              role="alert"
              className="text-sm text-red-700 dark:text-red-400"
            >
              {inputError.message}
            </p>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending}>
              Search audit logs
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => edit(auditQueryDefaults(limits))}
            >
              Use last 24 hours
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => {
                edit({ start: '', end: '', event: '', size: String(limits.page_size_default) });
                setStatus('Audit filters, records, and cursor history cleared.');
              }}
            >
              Clear query
            </Button>
            {pending && (
              <Button
                type="button"
                variant="outline"
                className={controlClass}
                onClick={() => {
                  edit(draft);
                  setStatus('Audit request cancelled. No result was accepted.');
                }}
              >
                Cancel audit request
              </Button>
            )}
          </div>
        </form>
        <Feedback status={status} error={error} />
        {submitted && (
          <p
            className="break-words text-sm text-muted-foreground"
            data-testid="audit-submitted-filters"
          >
            Submitted window: {submitted.start_time} to {submitted.end_time}. Event type:{' '}
            {submitted.event_type ?? 'All'}. Filters stay fixed for page navigation.
          </p>
        )}
        {page && page.items.length > 0 && (
          <div
            role="region"
            aria-label="Audit results, horizontally scrollable"
            tabIndex={0}
            className={queryTableFrameClass}
            onFocus={revealQueryFocus}
          >
            <table className="w-full min-w-[36rem] border-collapse">
              <caption className="sr-only">
                Audit results ordered by descending chain sequence
              </caption>
              <thead className="border-b bg-muted/40">
                <tr>
                  <th scope="col" className={queryHeadClass}>
                    Event time (UTC)
                  </th>
                  <th scope="col" className={queryHeadClass}>
                    Event type
                  </th>
                  <th scope="col" className={queryHeadClass}>
                    Action status
                  </th>
                  <th scope="col" className={queryHeadClass}>
                    Sequence
                  </th>
                  <th scope="col" className={queryHeadClass}>
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {page.items.map((row) => (
                  <tr key={row.id} data-testid="admin-audit-row">
                    <td className={queryCellClass}>
                      <QueryUtcTime value={row.timestamp} />
                    </td>
                    <th scope="row" className={`${queryCellClass} max-w-60 break-all font-medium`}>
                      {row.event_type}
                    </th>
                    <td className={`${queryCellClass} max-w-32 break-words`}>
                      {row.action_status}
                    </td>
                    <td className={`${queryCellClass} break-all font-mono text-xs`}>{row.seq}</td>
                    <td className={queryCellClass}>
                      <Button
                        type="button"
                        variant="outline"
                        className={controlClass}
                        aria-label={`View details for sequence ${row.seq}`}
                        onClick={() => setDetail(row)}
                      >
                        Details
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {page?.items.length === 0 && (
          <p className="text-sm">No audit records matched this page of the submitted query.</p>
        )}
        {page && submitted && (
          <nav aria-label="Audit cursor pagination" className="flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || history.position === 0}
              onClick={() =>
                void readPage(submitted, { ...history, position: history.position - 1 })
              }
            >
              Newer records
            </Button>
            <span className="text-sm text-muted-foreground">
              {page.items.length} records on this page. No total is calculated.
            </span>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || !page.has_more}
              onClick={older}
            >
              Older records
            </Button>
          </nav>
        )}
        {history.dropped && (
          <p className="text-sm">
            Earlier cursor history was discarded. Start a new search to revisit newer pages beyond
            the retained history.
          </p>
        )}
        <p className="text-sm leading-relaxed text-muted-foreground">
          Only the current page and up to {auditCursorHistoryLimit} page cursors are kept in memory.
          Each page is a separate, durably audited read, not a frozen global collection. Late
          ingestion can change later searches. Nothing polls for freshness; search again explicitly
          to refresh.
        </p>
      </Panel>
      {detail && (
        <NativeDialog
          title="Audit record details"
          description={
            <>
              Sequence <span className="break-all font-mono">{detail.seq}</span>. Stored hashes are
              record fields, not proof of chain verification.
            </>
          }
          onCancel={() => setDetail(null)}
          testId="admin-audit-detail"
        >
          <dl className="min-w-0 space-y-3 text-sm">
            {[
              ['Record reference', detail.id],
              ['Actor reference', detail.actor_id],
              ['Actor service reference', detail.actor_spiffe_id || 'Not recorded'],
              ['Subject reference', detail.user_id ?? 'Not recorded'],
              ['Client IP', detail.client_ip || 'Not recorded'],
              ['User agent', detail.user_agent || 'Not recorded'],
              ['Stored leaf hash', detail.sha256_leaf_hash],
              ['Stored chain hash', detail.sha256_chain_hash],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-all font-mono text-xs">{value}</dd>
              </div>
            ))}
          </dl>
          <p className="text-sm text-muted-foreground">
            A missing subject reference does not explain why it is absent. No account lookup or
            integrity conclusion is implied.
          </p>
          <div className="min-w-0 space-y-2">
            <h3 className="text-sm font-semibold">Payload text</h3>
            <pre
              aria-label="Audit payload text"
              tabIndex={0}
              className="max-h-80 min-w-0 max-w-full overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-3 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {detail.payload}
            </pre>
          </div>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            onClick={() => setDetail(null)}
          >
            Close details
          </Button>
        </NativeDialog>
      )}
    </>
  );
}
