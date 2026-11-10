'use client';

import { useTranslations } from 'next-intl';
import type { Message, MessageDescriptor } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';
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
import { AdminResults } from './admin-results';
import {
  auditQueryDefaults,
  auditQueryFromDraft,
  type AuditQueryDraft,
  type AuditQueryField,
} from './audit-query-form';
import {
  queryClearedMessage,
  queryFailureMessage,
  useQueryViewWork,
} from './query-view-state';
import { QueryUtcTime } from './query-view-time';

export const auditCursorHistoryLimit = 20;
type CursorHistory = { cursors: (string | undefined)[]; position: number; dropped: boolean };
const firstPage = (): CursorHistory => ({ cursors: [undefined], position: 0, dropped: false });

export function AuditView() {
  const t = useTranslations('audit');
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  return (
    <>
      <PageHeading title={t('title')}>{t('introduction')}</PageHeading>
      {capabilities?.capabilities.audit_logs_read ? (
        <AuditQuery
          key={profile.session.id}
          client={client}
          limits={capabilities.limits}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error={{ key: 'audit.denied' }} />
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
  const t = useTranslations('audit');
  const message = useMessage();
  const [draft, setDraft] = useState(() => auditQueryDefaults(limits));
  const [submitted, setSubmitted] = useState<AdminAuditQuery | null>(null);
  const [history, setHistory] = useState<CursorHistory>(firstPage);
  const [page, setPage] = useState<AdminAuditPage | null>(null);
  const [detail, setDetail] = useState<AdminAuditLog | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState<Message>({ key: 'audit.initial' });
  const [error, setError] = useState<Message>('');
  const [inputError, setInputError] = useState<{
    field: AuditQueryField;
    message: MessageDescriptor;
  } | null>(null);
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
    setStatus({ key: 'audit.changed' });
  }

  async function readPage(query: AdminAuditQuery, navigation: CursorHistory) {
    const controller = work.begin();
    if (!controller) return;
    setPage(null);
    setDetail(null);
    setPending(true);
    setError('');
    setStatus({ key: 'audit.loading' });
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
      setStatus({
        key: 'audit.loaded',
        values: { count: result.items.length, more: result.has_more ? 'yes' : 'no' },
      });
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

  const preview = auditQueryFromDraft(draft, limits).query;
  if (cleared) return <Feedback status={queryClearedMessage} />;
  return (
    <>
      <Panel title={t('query')} id={`${id}-heading`}>
        <form
          ref={form}
          aria-label={t('search')}
          noValidate
          onSubmit={search}
          autoComplete="off"
          className="min-w-0 space-y-4"
        >
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            {(['start', 'end'] as const).map((field) => (
              <div key={field} className="min-w-0 space-y-2">
                <Label htmlFor={`${id}-${field}`}>{t(field)}</Label>
                <Input
                  dir="ltr"
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
              <Label htmlFor={`${id}-event`}>{t('event')}</Label>
              <Input
                dir="ltr"
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
                {t('eventHelp')}
              </p>
            </div>
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-size`}>{t('size')}</Label>
              <Input
                dir="ltr"
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
                {t('sizeHelp', { maximum: limits.page_size_max })}
              </p>
            </div>
          </div>
          <p id={`${id}-window-help`} className="text-sm text-muted-foreground">
            {t('windowHelp', { seconds: limits.audit_max_window_seconds })}
          </p>
          {inputError && (
            <p
              id={`${id}-input-error`}
              role="alert"
              className="text-sm text-red-700 dark:text-red-400"
            >
              {message(inputError.message)}
            </p>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending}>
              {t('search')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => edit(auditQueryDefaults(limits))}
            >
              {t('lastDay')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => {
                edit({ start: '', end: '', event: '', size: String(limits.page_size_default) });
                setStatus({ key: 'audit.cleared' });
              }}
            >
              {t('clear')}
            </Button>
            {pending && (
              <Button
                type="button"
                variant="outline"
                className={controlClass}
                onClick={() => {
                  edit(draft);
                  setStatus({ key: 'audit.cancelled' });
                }}
              >
                {t('cancel')}
              </Button>
            )}
          </div>
        </form>
        <Feedback status={status} error={error} />
        <div className="grid min-w-0 gap-3 sm:grid-cols-2">
          {preview && (
            <p className="min-w-0 break-words rounded-md border p-3 text-sm text-muted-foreground"
              data-testid="audit-draft-preview">
              {t.rich('draftPreview', {
                start: () => <QueryUtcTime value={preview.start_time} />,
                end: () => <QueryUtcTime value={preview.end_time} />,
                event: preview.event_type ?? t('all'),
                eventValue: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
                size: String(preview.limit),
              })}
            </p>
          )}
          {submitted && (
          <p
            className="min-w-0 break-words rounded-md border p-3 text-sm text-muted-foreground"
            data-testid="audit-submitted-filters"
          >
            {t.rich('submitted', {
              start: submitted.start_time,
              end: submitted.end_time,
              event: submitted.event_type ?? t('all'),
              startValue: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
              endValue: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
              eventValue: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
            })}
          </p>
          )}
        </div>
        {page && page.items.length > 0 && (
          <AdminResults label={t('region')} caption={t('caption')} width={36}
            viewLabel={t('resultView')} compactLabel={t('compactRows')} tableLabel={t('tableView')}
            columns={[
              { id: 'event', label: t('eventType'), rowHeader: true, wide: true },
              { id: 'time', label: t('eventTime') },
              { id: 'status', label: t('actionStatus') },
              { id: 'sequence', label: t('sequence') },
              { id: 'details', label: t('details'), wide: true },
            ]}
            rows={page.items.map((row) => ({
              id: row.id, testId: 'admin-audit-row',
              cells: [
                <bdi key="event" dir="ltr" className="break-all">{row.event_type}</bdi>,
                <QueryUtcTime key="time" value={row.timestamp} />,
                <bdi key="status" dir="ltr" className="break-all">{row.action_status}</bdi>,
                <bdi key="sequence" dir="ltr" className="break-all font-mono text-xs">{row.seq}</bdi>,
                <Button key="details" type="button" variant="outline" className={controlClass}
                  data-focus-return={`audit-details:${row.id}`}
                  aria-label={t('viewDetails', { sequence: row.seq })} onClick={() => setDetail(row)}>
                  {t('details')}
                </Button>,
              ],
            }))}
          />
        )}
        {page?.items.length === 0 && <p className="text-sm">{t('empty')}</p>}
        {page && submitted && (
          <nav aria-label={t('pagination')} className="flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || history.position === 0}
              onClick={() =>
                void readPage(submitted, { ...history, position: history.position - 1 })
              }
            >
              {t('newer')}
            </Button>
            <span className="text-sm text-muted-foreground">
              {t('pageCount', { count: page.items.length })}
            </span>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || !page.has_more}
              onClick={older}
            >
              {t('older')}
            </Button>
          </nav>
        )}
        {history.dropped && <p className="text-sm">{t('historyDropped')}</p>}
        <p className="text-sm leading-relaxed text-muted-foreground">
          {t('retention', { limit: auditCursorHistoryLimit })}
        </p>
      </Panel>
      {detail && (
        <NativeDialog
          title={t('detailTitle')}
          description={t.rich('detailDescription', {
            sequence: detail.seq,
            sequenceValue: (chunks) => (
              <bdi dir="ltr" className="break-all font-mono">
                {chunks}
              </bdi>
            ),
          })}
          onCancel={() => setDetail(null)}
          testId="admin-audit-detail"
        >
          <dl className="min-w-0 space-y-3 text-sm">
            {[
              ['record', detail.id],
              ['actor', detail.actor_id],
              ['service', detail.actor_spiffe_id || t('notRecorded')],
              ['subject', detail.user_id ?? t('notRecorded')],
              ['ip', detail.client_ip || t('notRecorded')],
              ['agent', detail.user_agent || t('notRecorded')],
              ['leaf', detail.sha256_leaf_hash],
              ['chain', detail.sha256_chain_hash],
            ].map(([field, value]) => (
              <div key={field} className="min-w-0">
                <dt className="text-muted-foreground">
                  {t(
                    `fields.${field as keyof typeof import('../../../messages/audit').auditEn.fields}`
                  )}
                </dt>
                <dd dir="ltr" className="mt-1 break-all font-mono text-xs">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          <p className="text-sm text-muted-foreground">{t('missingSubject')}</p>
          <div className="min-w-0 space-y-2">
            <h3 className="text-sm font-semibold">{t('payload')}</h3>
            <pre
              aria-label={t('payloadLabel')}
              dir="ltr"
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
            {t('close')}
          </Button>
        </NativeDialog>
      )}
    </>
  );
}
