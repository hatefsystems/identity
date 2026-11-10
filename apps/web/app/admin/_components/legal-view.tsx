'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useTranslations } from 'next-intl';
import { useEffect, useId, useRef, useState } from 'react';
import type { Message } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';
import { controlClass, Feedback, inputClass, PageHeading, Panel } from '../../_components/controls';
import { NativeDialog } from '../../_components/native-dialog';
import { usePortal } from '../../_components/portal-provider';
import type { AdminCapabilities, AdminLimits } from '../../_lib/admin/contracts';
import { LegalClient } from '../../_lib/admin/legal-api';
import type {
  LegalHold,
  LegalHoldsPage,
  LegalHoldsQuery,
  LegalLookupPage,
  LegalLookupQuery,
} from '../../_lib/admin/legal-contracts';
import {
  legalLookupContinuation,
  legalPageLimits,
  validateLegalHoldsQuery,
} from '../../_lib/admin/legal-validation';
import type { LegalOperation } from '../../_lib/portal/action-intent';
import { isAborted, PortalError } from '../../_lib/portal/errors';
import { AdminResults } from './admin-results';
import { LegalActionDialog, type LegalAction, type LegalOutcome } from './legal-action-dialog';
import {
  clearLegalRegion,
  legalClearedMessage,
  legalEvidenceNotes,
  legalFailureMessage,
  legalFieldLabels,
} from './legal-view-state';
import {
  querySelectClass,
  useQueryViewWork,
} from './query-view-state';
import { QueryUtcTime } from './query-view-time';

type Section = 'holds' | 'preservation' | 'attribution';

export function LegalView() {
  const t = useTranslations('legal');
  const { profile, capabilities, resumedAction } = usePortal();
  const access = capabilities?.capabilities;
  const resume = resumedAction?.kind === 'legal' ? resumedAction.operation : undefined;
  const flags = access
    ? [
        access.legal_holds_read,
        access.legal_holds_apply,
        access.legal_holds_release,
        access.preservation_requests_create,
        access.legal_inquiry_lookup,
      ]
        .map(Number)
        .join('')
    : '';
  return (
    <>
      <PageHeading title={t('title')}>{t('introduction')}</PageHeading>
      {capabilities && access && flags.includes('1') ? (
        <LegalWorkspace
          key={`${profile.session.id}:${flags}`}
          capabilities={capabilities}
          resume={resume}
        />
      ) : (
        <Feedback error={{ key: 'legal.denied' }} />
      )}
    </>
  );
}

function LegalWorkspace({
  capabilities,
  resume,
}: {
  capabilities: AdminCapabilities;
  resume?: LegalOperation;
}) {
  const t = useTranslations('legal');
  const access = capabilities.capabilities;
  const sections: Section[] = [
    ...(access.legal_holds_read || access.legal_holds_apply || access.legal_holds_release
      ? ['holds' as const]
      : []),
    ...(access.preservation_requests_create ? ['preservation' as const] : []),
    ...(access.legal_inquiry_lookup ? ['attribution' as const] : []),
  ];
  const desired: Section =
    resume === 'lookup' ? 'attribution' : resume === 'preservation' ? 'preservation' : 'holds';
  const [selected, setSelected] = useState<Section>(
    sections.includes(desired) ? desired : sections[0]
  );
  const [resumeOperation, setResumeOperation] = useState(resume);
  const region = useRef<HTMLDivElement>(null);
  return (
    <>
      <nav aria-label={t('sectionsLabel')} className="flex flex-wrap gap-2">
        {sections.map((section) => (
          <Button
            key={section}
            type="button"
            variant={section === selected ? 'default' : 'outline'}
            className={controlClass}
            aria-pressed={section === selected}
            onClick={() => {
              if (section === selected) return;
              clearLegalRegion(region.current);
              setResumeOperation(undefined);
              setSelected(section);
            }}
          >
            {t(`sections.${section}`)}
          </Button>
        ))}
      </nav>
      <div key={selected} ref={region} className="min-w-0 space-y-6">
        <LegalSection section={selected} capabilities={capabilities} resume={resumeOperation} />
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">{t('workspaceNotice')}</p>
    </>
  );
}

function LegalSection({
  section,
  capabilities,
  resume,
}: {
  section: Section;
  capabilities: AdminCapabilities;
  resume?: LegalOperation;
}) {
  const t = useTranslations('legal');
  const { reportLegalInterruption } = usePortal();
  const access = capabilities.capabilities;
  const initial: LegalAction | null =
    resume === 'hold' && access.legal_holds_apply && section === 'holds'
      ? { kind: 'hold' }
      : resume === 'preservation' &&
          access.preservation_requests_create &&
          section === 'preservation'
        ? { kind: 'preservation' }
        : resume === 'lookup' && access.legal_inquiry_lookup && section === 'attribution'
          ? { kind: 'lookup' }
          : null;
  const [action, setAction] = useState<LegalAction | null>(initial);
  const [resumeTotp, setResumeTotp] = useState(Boolean(initial));
  const [outcome, setOutcome] = useState<LegalOutcome | null>(null);
  const [page, setPage] = useState<LegalLookupPage | null>(null);
  const [query, setQuery] = useState<LegalLookupQuery | null>(null);
  const [selectedRef, setSelectedRef] = useState<string | null>(null);
  const [detail, setDetail] = useState<LegalHold | null>(null);
  const [readGeneration, setReadGeneration] = useState(0);
  const [error, setError] = useState<Message>('');
  const [status, setStatus] = useState<Message>(
    resume === 'release' ? { key: 'legal.state.releaseResume' } : ''
  );
  const region = useRef<HTMLDivElement>(null);
  const id = useId();
  const { cleared } = useQueryViewWork(() => {
    clearLegalRegion(region.current);
    setAction(null);
    setOutcome(null);
    setPage(null);
    setQuery(null);
    setSelectedRef(null);
    setDetail(null);
    setError('');
    setStatus('');
    setResumeTotp(false);
  });
  useEffect(() => {
    const element = region.current;
    return () => clearLegalRegion(element);
  }, []);

  function open(value: LegalAction) {
    setOutcome(null);
    setError('');
    setStatus('');
    setDetail(null);
    setResumeTotp(false);
    if (value.kind === 'lookup' && !value.continuation) {
      setPage(null);
      setQuery(null);
      setSelectedRef(null);
    }
    setAction(value);
  }

  function receive(value: LegalOutcome) {
    setAction(null);
    setResumeTotp(false);
    setError('');
    if (value.kind === 'lookup') {
      setPage(value.page);
      setQuery(value.query);
      setSelectedRef(null);
      setOutcome(null);
      setStatus({ key: 'legal.state.lookupAccepted', values: { count: value.page.items.length } });
    } else if (value.kind === 'created' || value.kind === 'released') {
      setOutcome(value);
      if (section === 'holds') setReadGeneration((current) => current + 1);
      setStatus({ key: 'legal.state.confirmed' });
    } else {
      setPage(null);
      setQuery(null);
      setSelectedRef(null);
      setDetail(null);
      setOutcome(value);
      setReadGeneration((current) => current + 1);
      if (value.kind === 'failed') setError(legalFailureMessage(value.error));
      else if (value.kind === 'expired') setError({ key: 'legal.state.expired' });
      else if (value.kind === 'cancelled') setStatus({ key: 'legal.state.cancelled' });
      else {
        reportLegalInterruption(value.operation);
        setStatus(
          value.operation === 'lookup'
            ? { key: 'legal.state.lookupUnconfirmed' }
            : { key: 'legal.state.writeUnconfirmed' }
        );
      }
    }
  }

  if (cleared) return <Feedback status={legalClearedMessage} />;
  const observation = outcome?.kind === 'created' ? outcome.observation : undefined;
  const replayed =
    outcome?.kind === 'created' && (observation ? observation.replayed : outcome.hold.replayed);
  return (
    <div ref={region} className="min-w-0 space-y-6">
      <Panel title={t(`sections.${section}`)} id={`${id}-heading`}>
        <p className="text-sm leading-relaxed">{t(`sectionNotice.${section}`)}</p>
        <div className="flex flex-wrap gap-3">
          {section === 'holds' && access.legal_holds_apply && (
            <Button type="button" className={controlClass} onClick={() => open({ kind: 'hold' })}>
              {t('buttons.hold')}
            </Button>
          )}
          {section === 'preservation' && (
            <Button
              type="button"
              className={controlClass}
              onClick={() => open({ kind: 'preservation' })}
            >
              {t('buttons.preservation')}
            </Button>
          )}
          {section === 'attribution' && (
            <>
              <Button
                type="button"
                className={controlClass}
                onClick={() => open({ kind: 'lookup' })}
              >
                {t('buttons.lookup')}
              </Button>
              {(page || query) && (
                <Button
                  type="button"
                  variant="outline"
                  className={controlClass}
                  onClick={() => {
                    setPage(null);
                    setQuery(null);
                    setSelectedRef(null);
                    setOutcome(null);
                    setStatus({ key: 'legal.state.inquiryCleared' });
                  }}
                >
                  {t('buttons.clearInquiry')}
                </Button>
              )}
            </>
          )}
        </div>
        <Feedback error={error} status={status} />
        {outcome?.kind === 'unconfirmed' && (
          <p data-testid="legal-outcome" data-outcome="unconfirmed" className="text-sm">
            {t('outcome.noRetry')}
          </p>
        )}
        {(outcome?.kind === 'created' || outcome?.kind === 'released') && (
          <div
            data-testid="legal-outcome"
            data-outcome={replayed ? 'replayed' : 'confirmed'}
            data-legal-private
            className="min-w-0 space-y-4 rounded-md border p-4"
          >
            {outcome.kind === 'released' ? (
              <p className="break-all text-sm">
                {t.rich('outcome.released', {
                  id: outcome.holdId,
                  value: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
                })}
              </p>
            ) : (
              <>
                <p className="text-sm font-semibold">
                  {t(replayed ? 'outcome.replayed' : 'outcome.created')}
                  {!outcome.hold.is_active && <> {t('outcome.alreadyReleased')}</>}
                </p>
                <HoldCore hold={outcome.hold} />
                <Button
                  type="button"
                  variant="outline"
                  className={controlClass}
                  onClick={() => setDetail(outcome.hold)}
                >
                  {t('buttons.details')}
                </Button>
                {observation && (
                  <div className="min-w-0 space-y-2 text-sm">
                    <p>
                      {t.rich('outcome.observedAt', {
                        time: () => <QueryUtcTime value={observation.observed_at} />,
                      })}
                    </p>
                    <p>
                      {t('outcome.presence', {
                        account: t(observation.account_present ? 'values.yes' : 'values.no'),
                        ledger: t(observation.ledger_evidence_present ? 'values.yes' : 'values.no'),
                      })}
                    </p>
                    <LegalEvidenceNote kind="preservation" note={observation.note} />
                    <p className="text-muted-foreground">{t('outcome.presenceNotice')}</p>
                  </div>
                )}
                <p className="text-sm text-muted-foreground">{t('outcome.transactionNotice')}</p>
              </>
            )}
          </div>
        )}
      </Panel>
      {section === 'holds' &&
        (access.legal_holds_read ? (
          <LegalHoldsRead
            key={readGeneration}
            limits={capabilities.limits}
            canRelease={access.legal_holds_release}
            onRelease={(hold) => open({ kind: 'release', hold })}
            onDetails={setDetail}
          />
        ) : (
          <Feedback status={{ key: 'legal.outcome.listingUnavailable' }} />
        ))}
      {section === 'attribution' && page && query && (
        <Panel title={t('attribution.title')} id={`${id}-results`}>
          <div
            data-testid="legal-coverage"
            data-legal-private
            className="min-w-0 space-y-3 text-sm"
          >
            <p className="break-all">
              {t.rich('attribution.scope', {
                start: () => <QueryUtcTime value={query.startTime} />,
                end: () => <QueryUtcTime value={query.endTime} />,
                size: String(query.limit),
              })}
            </p>
            <p className="break-all">
              {t.rich('attribution.highWater', {
                sequence: page.coverage.through_seq,
                value: (chunks) => (
                  <bdi dir="ltr" className="font-mono">
                    {chunks}
                  </bdi>
                ),
              })}
            </p>
            <p>
              {t.rich('attribution.observedAt', {
                time: () => <QueryUtcTime value={page.coverage.observed_at} />,
              })}
            </p>
            <p>
              {t.rich('attribution.checkedAt', {
                time: () => <QueryUtcTime value={page.coverage.eligibility_checked_at} />,
              })}
            </p>
            <LegalEvidenceNote kind="coverage" note={page.coverage.note} />
          </div>
          {page.items.length === 0 ? (
            <p className="text-sm">{t('attribution.empty')}</p>
          ) : (
            <AdminResults label={t('attribution.region')} caption={t('attribution.caption')}
              viewLabel={t('resultView')} compactLabel={t('compactRows')} tableLabel={t('tableView')}
              width={48} privateRegion
              columns={[
                { id: 'reference', label: t('fields.accountRef'), rowHeader: true, wide: true },
                { id: 'event', label: t('fields.eventType') },
                { id: 'time', label: t('fields.eventTime') },
                { id: 'sequence', label: t('fields.sequence') },
                { id: 'record', label: t('fields.eventRef'), secondary: true },
                { id: 'retention', label: t('fields.retainUntil'), secondary: true },
                ...query.fields.map((key) => ({ id: key, label: t(legalFieldLabels[key]), secondary: true })),
                { id: 'selection', label: t('fields.selection'), wide: true },
              ]}
              rows={page.items.map((row) => ({
                id: row.id, testId: 'legal-result-row',
                cells: [
                  <bdi key="reference" dir="ltr" className="break-all font-mono text-xs">{row.account_ref}</bdi>,
                  <bdi key="event" dir="ltr" className="break-all">{row.event_type}</bdi>,
                  <QueryUtcTime key="time" value={row.timestamp} />,
                  <bdi key="sequence" dir="ltr" className="break-all font-mono text-xs">{row.seq}</bdi>,
                  <bdi key="record" dir="ltr" className="break-all font-mono text-xs">{row.id}</bdi>,
                  <QueryUtcTime key="retention" value={row.retain_until} />,
                  ...query.fields.map((key) => row[key] === undefined ? t('attribution.missingField') :
                    <bdi key={key} dir="ltr" className="whitespace-pre-wrap break-all">{row[key]}</bdi>),
                  (access.legal_holds_apply || access.preservation_requests_create) && (
                    <Button key="selection" type="button" variant="outline" className={controlClass}
                      data-focus-return={`legal-select:${row.id}`}
                      aria-pressed={selectedRef === row.account_ref}
                      onClick={() => { setSelectedRef(row.account_ref); setOutcome(null); }}>
                      {t('buttons.select')}
                    </Button>
                  ),
                ],
              }))}
            />
          )}
          {selectedRef && (
            <div
              className="min-w-0 space-y-3 rounded-md border p-4"
              data-legal-private
              data-testid="legal-selected-reference"
            >
              <p className="break-all text-sm">
                {t.rich('attribution.selected', {
                  id: selectedRef,
                  value: (chunks) => (
                    <bdi dir="ltr" className="font-mono">
                      {chunks}
                    </bdi>
                  ),
                })}
              </p>
              <p className="text-sm text-muted-foreground">{t('attribution.selectionNotice')}</p>
              <div className="flex flex-wrap gap-3">
                {access.legal_holds_apply && (
                  <Button
                    type="button"
                    className={controlClass}
                    onClick={() => open({ kind: 'hold', accountRef: selectedRef })}
                  >
                    {t('buttons.hold')}
                  </Button>
                )}
                {access.preservation_requests_create && (
                  <Button
                    type="button"
                    variant="outline"
                    className={controlClass}
                    onClick={() => open({ kind: 'preservation', accountRef: selectedRef })}
                  >
                    {t('buttons.preservation')}
                  </Button>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  className={controlClass}
                  onClick={() => setSelectedRef(null)}
                >
                  {t('buttons.clearSelection')}
                </Button>
              </div>
            </div>
          )}
          {page.next_cursor ? (
            <Button
              type="button"
              className={controlClass}
              onClick={() => {
                try {
                  const continuation = legalLookupContinuation(query, page);
                  if (!continuation) throw new PortalError('invalid_response');
                  setSelectedRef(null);
                  open({ kind: 'lookup', continuation });
                } catch (failure) {
                  setPage(null);
                  setQuery(null);
                  setSelectedRef(null);
                  setStatus('');
                  setError(legalFailureMessage(failure));
                }
              }}
            >
              {t('buttons.nextLookup')}
            </Button>
          ) : (
            <p className="text-sm">{t('attribution.final')}</p>
          )}
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t('attribution.coverageNotice')}
          </p>
        </Panel>
      )}
      {action && <LegalActionDialog action={action} resumeTotp={resumeTotp} onOutcome={receive} />}
      {detail && (
        <NativeDialog
          title={t('details.title')}
          testId="legal-hold-details"
          description={t('details.description')}
          onCancel={() => setDetail(null)}
        >
          <div data-legal-private className="min-w-0 space-y-4">
            <HoldCore hold={detail} />
            {detail.details_purged ? (
              <p className="text-sm">{t('details.purged')}</p>
            ) : (
              <dl className="min-w-0 space-y-3 text-sm">
                {(
                  [
                    ['reason', detail.reason],
                    ['requestingAuthority', detail.requesting_authority],
                    ['legalBasis', detail.legal_basis],
                  ] as const
                ).map(([label, value]) => (
                  <div key={label} className="min-w-0">
                    <dt className="text-muted-foreground">{t(`fields.${label}`)}</dt>
                    <dd className="mt-1 whitespace-pre-wrap break-all">
                      {value === undefined ? (
                        t('values.notReturned')
                      ) : (
                        <bdi dir="auto">{value}</bdi>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            onClick={() => setDetail(null)}
          >
            {t('buttons.closeDetails')}
          </Button>
        </NativeDialog>
      )}
    </div>
  );
}

function HoldCore({ hold }: { hold: LegalHold }) {
  const t = useTranslations('legal');
  return (
    <dl className="min-w-0 space-y-2 text-sm">
      {(
        [
          [
            'requestKind',
            t(hold.request_kind === 'preservation' ? 'values.preservation' : 'values.hold'),
            false,
          ],
          ['holdId', hold.id, true],
          ['accountRef', hold.account_ref, true],
          ['status', t(hold.is_active ? 'values.active' : 'values.released'), false],
          ['appliedBy', hold.applied_by, true],
          ['releasedBy', hold.released_by ?? t('values.notRecorded'), hold.released_by !== null],
        ] as const
      ).map(([label, value, technical]) => (
        <div key={label} className="min-w-0">
          <dt className="text-muted-foreground">{t(`fields.${label}`)}</dt>
          <dd className="break-all">{technical ? <bdi dir="ltr">{value}</bdi> : value}</dd>
        </div>
      ))}
      <div>
        <dt className="text-muted-foreground">{t('fields.appliedAt')}</dt>
        <dd>
          <QueryUtcTime value={hold.applied_at} />
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">{t('fields.advisoryReviewAt')}</dt>
        <dd>
          <QueryUtcTime value={hold.review_at} />
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">{t('fields.releasedAt')}</dt>
        <dd>
          <QueryUtcTime value={hold.released_at} />
        </dd>
      </div>
    </dl>
  );
}

function LegalEvidenceNote({
  kind,
  note,
}: {
  kind: keyof typeof legalEvidenceNotes;
  note: string;
}) {
  const t = useTranslations('legal');
  const recognized = note === legalEvidenceNotes[kind];
  return (
    <div className="min-w-0 space-y-2">
      <p>
        {t.rich(recognized ? `evidence.${kind}` : 'evidence.unknown', {
          field: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
        })}
      </p>
      {recognized ? (
        <details className="min-w-0">
          <summary className="min-h-11 cursor-pointer py-2">{t('evidence.original')}</summary>
          <p className="whitespace-pre-wrap break-words">
            <bdi dir="auto">{note}</bdi>
          </p>
        </details>
      ) : (
        <p className="whitespace-pre-wrap break-words">
          <bdi dir="auto">{note}</bdi>
        </p>
      )}
    </div>
  );
}

function LegalHoldsRead({
  limits,
  canRelease,
  onRelease,
  onDetails,
}: {
  limits: AdminLimits;
  canRelease: boolean;
  onRelease: (hold: LegalHold) => void;
  onDetails: (hold: LegalHold) => void;
}) {
  const t = useTranslations('legal');
  const message = useMessage();
  const { client, reportPermissionLoss } = usePortal();
  const sizes = legalPageLimits(limits);
  const [draft, setDraft] = useState({
    accountRef: '',
    all: false,
    status: 'active',
    size: String(sizes.default),
  });
  const [submitted, setSubmitted] = useState<LegalHoldsQuery | null>(null);
  const [page, setPage] = useState<LegalHoldsPage | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<Message>('');
  const [inputError, setInputError] = useState<Message>('');
  const [status, setStatus] = useState<Message>({ key: 'legal.read.initial' });
  const busy = useRef(false);
  const region = useRef<HTMLDivElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const id = useId();
  const { work, cleared } = useQueryViewWork(() => {
    clearLegalRegion(region.current);
    setDraft({ accountRef: '', all: false, status: 'active', size: '' });
    setSubmitted(null);
    setPage(null);
    setPending(false);
    setError('');
    setInputError('');
    setStatus('');
    busy.current = false;
  });
  useEffect(() => {
    const element = region.current;
    return () => clearLegalRegion(element);
  }, []);
  function edit(next: typeof draft) {
    work.cancel();
    busy.current = false;
    setDraft(next);
    setSubmitted(null);
    setPage(null);
    setPending(false);
    setInputError('');
    setError('');
    setStatus({ key: 'legal.read.changed' });
  }
  async function load(query: LegalHoldsQuery) {
    if (busy.current) return;
    const controller = work.begin();
    if (!controller) return;
    busy.current = true;
    setPage(null);
    setSubmitted(null);
    setPending(true);
    setError('');
    setStatus({ key: 'legal.read.loading' });
    try {
      const result = await new LegalClient(client).holds(query, controller.signal);
      if (!work.current(controller)) return;
      setPage(result);
      setSubmitted(query);
      setStatus({
        key: 'legal.read.accepted',
        values: { count: result.items.length, total: result.total },
      });
    } catch (failure) {
      if (!work.current(controller) || isAborted(failure)) return;
      setStatus('');
      setError(legalFailureMessage(failure));
      if (failure instanceof PortalError && failure.status === 403) reportPermissionLoss();
    } finally {
      if (work.current(controller)) {
        busy.current = false;
        setPending(false);
      }
      work.finish(controller);
    }
  }
  function search() {
    if (busy.current || work.blocked) return;
    try {
      const query = validateLegalHoldsQuery(
        {
          ...(draft.all ? {} : { accountRef: draft.accountRef }),
          status: draft.status as LegalHoldsQuery['status'],
          limit: /^[1-9][0-9]*$/.test(draft.size) ? Number(draft.size) : 0,
          offset: 0,
        },
        limits
      );
      setInputError('');
      void load(query);
    } catch {
      setInputError({ key: 'legal.read.invalid', values: { max: sizes.max } });
      form.current?.querySelector<HTMLElement>('input:not(:disabled)')?.focus();
    }
  }
  if (cleared) return <Feedback status={legalClearedMessage} />;
  return (
    <div ref={region}>
      <Panel title={t('read.title')} id={`${id}-heading`}>
        <form
          ref={form}
          aria-label={t('buttons.read')}
          method="post"
          noValidate
          autoComplete="off"
          className="min-w-0 space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            search();
          }}
        >
          <div className="min-w-0 space-y-2">
            <Label htmlFor={`${id}-ref`}>{t('fields.accountRef')}</Label>
            <Input
              id={`${id}-ref`}
              name="accountRef"
              dir="ltr"
              type="text"
              value={draft.accountRef}
              disabled={draft.all}
              className={inputClass}
              spellCheck={false}
              autoCapitalize="none"
              autoComplete="off"
              aria-invalid={Boolean(inputError)}
              aria-describedby={`${id}-filter-help${inputError ? ` ${id}-error` : ''}`}
              onChange={(event) => edit({ ...draft, accountRef: event.target.value })}
            />
          </div>
          <label className="flex min-h-11 items-center gap-3 py-2 text-sm">
            <input
              type="checkbox"
              checked={draft.all}
              onChange={(event) => edit({ ...draft, all: event.target.checked, accountRef: '' })}
              className="size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            {t('read.allReferences')}
          </label>
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-status`}>{t('fields.holdStatus')}</Label>
              <select
                id={`${id}-status`}
                name="status"
                value={draft.status}
                className={querySelectClass}
                onChange={(event) => edit({ ...draft, status: event.target.value })}
              >
                <option value="active">{t('values.active')}</option>
                <option value="released">{t('values.released')}</option>
                <option value="all">{t('values.all')}</option>
              </select>
            </div>
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-size`}>{t('fields.size')}</Label>
              <Input
                id={`${id}-size`}
                name="size"
                dir="ltr"
                type="number"
                min={1}
                max={sizes.max}
                step={1}
                value={draft.size}
                className={inputClass}
                aria-invalid={Boolean(inputError)}
                aria-describedby={inputError ? `${id}-error` : undefined}
                onChange={(event) => edit({ ...draft, size: event.target.value })}
              />
            </div>
          </div>
          <p id={`${id}-filter-help`} className="text-sm text-muted-foreground">
            {t.rich('read.filterHelp', {
              max: String(sizes.max),
              id: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
            })}
          </p>
          {inputError && (
            <p id={`${id}-error`} role="alert" className="text-sm text-destructive">
              {message(inputError)}
            </p>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending}>
              {t('buttons.read')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() =>
                edit({ accountRef: '', all: false, status: 'active', size: String(sizes.default) })
              }
            >
              {t('buttons.clearRead')}
            </Button>
            {pending && (
              <Button
                type="button"
                variant="outline"
                className={controlClass}
                onClick={() =>
                  edit({
                    accountRef: '',
                    all: false,
                    status: 'active',
                    size: String(sizes.default),
                  })
                }
              >
                {t('buttons.cancelRead')}
              </Button>
            )}
          </div>
        </form>
        <Feedback error={error} status={status} />
        {page?.items.length === 0 && <p className="text-sm">{t('read.empty')}</p>}
        {page && page.items.length > 0 && (
          <AdminResults label={t('read.region')} caption={t('read.caption')} width={54} privateRegion
            viewLabel={t('resultView')} compactLabel={t('compactRows')} tableLabel={t('tableView')}
            columns={[
              { id: 'kind', label: t('fields.requestKind') },
              { id: 'id', label: t('fields.holdId'), rowHeader: true, wide: true },
              { id: 'reference', label: t('fields.accountRef'), wide: true },
              { id: 'status', label: t('fields.status') },
              { id: 'applied', label: t('fields.applied'), secondary: true },
              { id: 'review', label: t('fields.review'), secondary: true },
              { id: 'released', label: t('fields.released'), secondary: true },
              { id: 'actors', label: t('fields.actors'), secondary: true },
              { id: 'actions', label: t('fields.actions'), wide: true },
            ]}
            rows={page.items.map((row) => ({
              id: row.id, testId: 'legal-hold-row',
              cells: [
                t(row.request_kind === 'preservation' ? 'values.preservation' : 'values.hold'),
                <bdi key="id" dir="ltr" className="break-all font-mono text-xs">{row.id}</bdi>,
                <bdi key="reference" dir="ltr" className="break-all font-mono text-xs">{row.account_ref}</bdi>,
                t(row.is_active ? 'values.active' : 'values.released'),
                <QueryUtcTime key="applied" value={row.applied_at} />,
                <QueryUtcTime key="review" value={row.review_at} />,
                <QueryUtcTime key="released" value={row.released_at} />,
                <div key="actors" className="space-y-1 break-all text-xs">
                  <p>{t.rich('read.appliedBy', { id: row.applied_by, value: (chunks) => <bdi dir="ltr">{chunks}</bdi> })}</p>
                  <p>{t.rich('read.releasedBy', { id: row.released_by ?? t('values.notRecorded'),
                    value: (chunks) => <bdi dir={row.released_by ? 'ltr' : 'auto'}>{chunks}</bdi> })}</p>
                </div>,
                <div key="actions" className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" className={controlClass}
                    data-focus-return={`legal-details:${row.id}`} onClick={() => onDetails(row)}>
                    {t('buttons.details')}
                  </Button>
                  {canRelease && row.is_active && (
                    <Button type="button" variant="outline" className={controlClass}
                      data-focus-return={`legal-release:${row.id}`} onClick={() => onRelease(row)}>
                      {t('buttons.release')}
                    </Button>
                  )}
                </div>,
              ],
            }))}
          />
        )}
        {page && submitted && (
          <nav aria-label={t('read.pagination')} className="flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || submitted.offset === 0}
              onClick={() =>
                void load({ ...submitted, offset: Math.max(0, submitted.offset - submitted.limit) })
              }
            >
              {t('buttons.previous')}
            </Button>
            <span className="text-sm text-muted-foreground">
              {t('read.snapshot', {
                offset: String(page.offset),
                count: String(page.items.length),
                total: String(page.total),
              })}
            </span>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={
                pending ||
                page.offset + page.items.length >= page.total ||
                submitted.offset + submitted.limit > 2147483647
              }
              onClick={() =>
                void load({ ...submitted, offset: submitted.offset + submitted.limit })
              }
            >
              {t('buttons.next')}
            </Button>
          </nav>
        )}
      </Panel>
    </div>
  );
}
