'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState } from 'react';
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
import { LegalActionDialog, type LegalAction, type LegalOutcome } from './legal-action-dialog';
import {
  clearLegalRegion,
  legalClearedMessage,
  legalFailureMessage,
  legalFieldLabels,
} from './legal-view-state';
import {
  queryCellClass,
  queryHeadClass,
  querySelectClass,
  queryTableFrameClass,
  revealQueryFocus,
  useQueryViewWork,
} from './query-view-state';
import { QueryUtcTime } from './query-view-time';

type Section = 'holds' | 'preservation' | 'attribution';
const sectionLabels: Record<Section, string> = {
  holds: 'Legal Holds',
  preservation: 'Preservation',
  attribution: 'Attribution',
};

export function LegalView() {
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
      <PageHeading title="DPO and Legal">
        Purpose-limited legal operations. Class B records are pseudonymized personal data, not
        anonymous. Investigative access is not permission to disclose externally.
      </PageHeading>
      {capabilities && access && flags.includes('1') ? (
        <LegalWorkspace
          key={`${profile.session.id}:${flags}`}
          capabilities={capabilities}
          resume={resume}
        />
      ) : (
        <Feedback error="No legal operation is available to this session. A false capability does not distinguish missing permission from deployment prerequisites. No legal records were requested." />
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
      <nav aria-label="Legal workspace sections" className="flex flex-wrap gap-2">
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
            {sectionLabels[section]}
          </Button>
        ))}
      </nav>
      <div key={selected} ref={region} className="min-w-0 space-y-6">
        <LegalSection section={selected} capabilities={capabilities} resume={resumeOperation} />
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">
        Only the selected authorized section is mounted. No legal operation runs on load or while
        typing. Leaving a section, hiding this page, or losing authority clears its private state.
        There are no browser-saved drafts, exports, uploads, or external transfers.
      </p>
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
  const [error, setError] = useState('');
  const [status, setStatus] = useState(
    resume === 'release'
      ? 'The prior target was cleared. Read Legal Holds and select an authorized request row again before fresh release verification.'
      : ''
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
      setStatus(
        `${value.page.items.length} indexed records accepted on this page. Each further page requires fresh verification.`
      );
    } else if (value.kind === 'created' || value.kind === 'released') {
      setOutcome(value);
      if (section === 'holds') setReadGeneration((current) => current + 1);
      setStatus(
        'The legal response is confirmed. No list refresh was made automatically. Read Legal Holds explicitly for a current snapshot.'
      );
    } else {
      setPage(null);
      setQuery(null);
      setSelectedRef(null);
      setDetail(null);
      setOutcome(value);
      setReadGeneration((current) => current + 1);
      if (value.kind === 'failed') setError(legalFailureMessage(value.error));
      else if (value.kind === 'expired')
        setError(
          'Verification expired. Private form data was cleared. Start fresh verification and reenter the original request.'
        );
      else if (value.kind === 'cancelled')
        setStatus(
          'The legal workflow was cancelled before transmission. Its private state was cleared.'
        );
      else {
        reportLegalInterruption(value.operation);
        setStatus(
          value.operation === 'lookup'
            ? 'No attribution result was accepted. This is not a no-match result. Start a new inquiry explicitly with fresh verification.'
            : 'Legal write outcome unconfirmed. Nothing was retried and rollback is not implied. Reconcile the original external intake operation before a fresh, explicit attempt.'
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
      <Panel title={sectionLabels[section]} id={`${id}-heading`}>
        <p className="text-sm leading-relaxed">
          {section === 'attribution'
            ? 'Search one explicit email and UTC window against currently eligible indexed ledger records. An email may match distinct historical account references; do not merge them or infer verified real-world identity. An empty or final page is not proof of no historical activity.'
            : section === 'preservation'
              ? 'Record a freeze-before-order preservation request independently of a case workflow or full disclosure order. Its advisory expiry never releases the hold automatically. Preservation history is available in Legal Holds by request kind.'
              : 'Each Legal Hold or preservation request is independent and overrides retention until explicit release. Release resumes original clocks and may allow immediate purge eligibility. A hold cannot restore erased data, extend recovery, or establish an immutable evidence snapshot.'}
        </p>
        <div className="flex flex-wrap gap-3">
          {section === 'holds' && access.legal_holds_apply && (
            <Button type="button" className={controlClass} onClick={() => open({ kind: 'hold' })}>
              Apply Legal Hold
            </Button>
          )}
          {section === 'preservation' && (
            <Button
              type="button"
              className={controlClass}
              onClick={() => open({ kind: 'preservation' })}
            >
              Record preservation
            </Button>
          )}
          {section === 'attribution' && (
            <>
              <Button
                type="button"
                className={controlClass}
                onClick={() => open({ kind: 'lookup' })}
              >
                Start attribution inquiry
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
                    setStatus(
                      'Inquiry and current page cleared. Reenter all inputs for a new run.'
                    );
                  }}
                >
                  Clear inquiry
                </Button>
              )}
            </>
          )}
        </div>
        <Feedback error={error} status={status} />
        {outcome?.kind === 'unconfirmed' && (
          <p data-testid="legal-outcome" data-outcome="unconfirmed" className="text-sm">
            No automatic retransmission was made. No durable recovery draft is kept in this browser.
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
                Request {outcome.holdId} is released, including if already released. This does not
                prove this caller changed it. Other independent holds may remain.
              </p>
            ) : (
              <>
                <p className="text-sm font-semibold">
                  {replayed
                    ? 'Existing request replayed; current state returned.'
                    : 'New legal request created.'}
                  {!outcome.hold.is_active &&
                    ' This request is already released; replay did not reactivate it.'}
                </p>
                <HoldCore hold={outcome.hold} />
                <Button
                  type="button"
                  variant="outline"
                  className={controlClass}
                  onClick={() => setDetail(outcome.hold)}
                >
                  View restricted details
                </Button>
                {observation && (
                  <div className="min-w-0 space-y-2 text-sm">
                    <p>
                      Observed at: <QueryUtcTime value={observation.observed_at} />
                    </p>
                    <p>
                      Account record present: {observation.account_present ? 'Yes' : 'No'}. Ledger
                      payload present: {observation.ledger_evidence_present ? 'Yes' : 'No'}.
                    </p>
                    <p className="whitespace-pre-wrap break-words">{observation.note}</p>
                    <p className="text-muted-foreground">
                      Account presence includes soft-deleted records. Payload presence can include
                      unindexed or expired records and says nothing about completeness. The hold is
                      valid even if both observations are false.
                    </p>
                  </div>
                )}
                <p className="text-sm text-muted-foreground">
                  Lookup and hold creation are separate transactions. This response does not promise
                  that all previously displayed evidence survived until this hold committed.
                </p>
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
          <Feedback status="Listing is not available to this session. Release requires an authorized list row; no account-profile resolver or inferred target is used." />
        ))}
      {section === 'attribution' && page && query && (
        <Panel title="Current attribution page" id={`${id}-results`}>
          <div
            data-testid="legal-coverage"
            data-legal-private
            className="min-w-0 space-y-3 text-sm"
          >
            <p className="break-all">
              Fixed UTC scope: {query.startTime} to {query.endTime}. Page size: {query.limit}.
            </p>
            <p className="break-all">
              High-water sequence: <span className="font-mono">{page.coverage.through_seq}</span>.
            </p>
            <p>
              Original observation: <QueryUtcTime value={page.coverage.observed_at} />.
            </p>
            <p>
              Eligibility checked: <QueryUtcTime value={page.coverage.eligibility_checked_at} />.
            </p>
            <p className="whitespace-pre-wrap break-words">{page.coverage.note}</p>
          </div>
          {page.items.length === 0 ? (
            <p className="text-sm">
              No matching indexed, currently eligible records were returned on this page in this
              scope. This is not proof of no activity, no account, or a complete history.
            </p>
          ) : (
            <div
              role="region"
              aria-label="Attribution results, horizontally scrollable"
              tabIndex={0}
              className={queryTableFrameClass}
              onFocus={revealQueryFocus}
              data-legal-private
            >
              <table className="w-full min-w-[48rem] border-collapse">
                <caption className="sr-only">
                  Pseudonymized personal data ordered by ascending sequence, not verified inclusion
                  evidence
                </caption>
                <thead className="border-b bg-muted/40">
                  <tr>
                    {[
                      'Event reference',
                      'Original account reference',
                      'Event type',
                      'Event time (UTC)',
                      'Retain until (UTC)',
                      'Sequence',
                      ...query.fields.map((key) => legalFieldLabels[key]),
                      'Reference selection',
                    ].map((label) => (
                      <th key={label} scope="col" className={queryHeadClass}>
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {page.items.map((row) => (
                    <tr key={row.id} data-testid="legal-result-row">
                      <td className={`${queryCellClass} max-w-52 break-all font-mono text-xs`}>
                        {row.id}
                      </td>
                      <th
                        scope="row"
                        className={`${queryCellClass} max-w-52 break-all font-mono text-xs`}
                      >
                        {row.account_ref}
                      </th>
                      <td className={`${queryCellClass} max-w-48 break-all`}>{row.event_type}</td>
                      <td className={queryCellClass}>
                        <QueryUtcTime value={row.timestamp} />
                      </td>
                      <td className={queryCellClass}>
                        <QueryUtcTime value={row.retain_until} />
                      </td>
                      <td className={`${queryCellClass} break-all font-mono text-xs`}>{row.seq}</td>
                      {query.fields.map((key) => (
                        <td
                          key={key}
                          className={`${queryCellClass} max-w-56 whitespace-pre-wrap break-all`}
                        >
                          {row[key] ?? 'Not present in this returned projection'}
                        </td>
                      ))}
                      <td className={queryCellClass}>
                        {(access.legal_holds_apply || access.preservation_requests_create) && (
                          <Button
                            type="button"
                            variant="outline"
                            className={controlClass}
                            aria-pressed={selectedRef === row.account_ref}
                            onClick={() => {
                              setSelectedRef(row.account_ref);
                              setOutcome(null);
                            }}
                          >
                            Select reference
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {selectedRef && (
            <div
              className="min-w-0 space-y-3 rounded-md border p-4"
              data-legal-private
              data-testid="legal-selected-reference"
            >
              <p className="break-all text-sm">
                Selected original reference: <span className="font-mono">{selectedRef}</span>.
              </p>
              <p className="text-sm text-muted-foreground">
                This selection conveys only a reference, not proof that the account still exists or
                who owned it. Confirm each independent operation with fresh verification.
              </p>
              <div className="flex flex-wrap gap-3">
                {access.legal_holds_apply && (
                  <Button
                    type="button"
                    className={controlClass}
                    onClick={() => open({ kind: 'hold', accountRef: selectedRef })}
                  >
                    Apply Legal Hold
                  </Button>
                )}
                {access.preservation_requests_create && (
                  <Button
                    type="button"
                    variant="outline"
                    className={controlClass}
                    onClick={() => open({ kind: 'preservation', accountRef: selectedRef })}
                  >
                    Record preservation
                  </Button>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  className={controlClass}
                  onClick={() => setSelectedRef(null)}
                >
                  Clear selection
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
              Next attribution page
            </Button>
          ) : (
            <p className="text-sm">
              No continuation was returned. This is not a complete-history finding.
            </p>
          )}
          <p className="text-sm leading-relaxed text-muted-foreground">
            Only this page is retained; no previous-page cache or fetch-all exists. Current
            retention and holds are rechecked on every page; release may remove expired matches.
            Later ingestion above the bound is outside this run. The cursor has no advertised age
            expiry, and no countdown is inferred. Coverage does not promise every historical pepper
            generation is searchable. Missing selected metadata does not prove it never existed.
          </p>
        </Panel>
      )}
      {action && <LegalActionDialog action={action} resumeTotp={resumeTotp} onOutcome={receive} />}
      {detail && (
        <NativeDialog
          title="Restricted legal request details"
          testId="legal-hold-details"
          description="Restricted narrative data, rendered as inert text. Missing purged details are not empty original values."
          onCancel={() => setDetail(null)}
        >
          <div data-legal-private className="min-w-0 space-y-4">
            <HoldCore hold={detail} />
            {detail.details_purged ? (
              <p className="text-sm">
                Restricted details were purged. The original values are not available.
              </p>
            ) : (
              <dl className="min-w-0 space-y-3 text-sm">
                {[
                  ['Reason', detail.reason],
                  ['Requesting authority', detail.requesting_authority],
                  ['Legal basis', detail.legal_basis],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0">
                    <dt className="text-muted-foreground">{label}</dt>
                    <dd className="mt-1 whitespace-pre-wrap break-all">
                      {value ?? 'Not returned'}
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
            Close details
          </Button>
        </NativeDialog>
      )}
    </div>
  );
}

function HoldCore({ hold }: { hold: LegalHold }) {
  return (
    <dl className="min-w-0 space-y-2 text-sm">
      {[
        ['Request kind', hold.request_kind === 'preservation' ? 'Preservation' : 'Legal Hold'],
        ['Hold request UUID', hold.id],
        ['Original account reference', hold.account_ref],
        ['Status', hold.is_active ? 'Active' : 'Released'],
        ['Applied by (opaque reference)', hold.applied_by],
        ['Released by (opaque reference)', hold.released_by ?? 'Not recorded'],
      ].map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="break-all">{value}</dd>
        </div>
      ))}
      <div>
        <dt className="text-muted-foreground">Applied at (UTC)</dt>
        <dd>
          <QueryUtcTime value={hold.applied_at} />
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Advisory review at (UTC)</dt>
        <dd>
          <QueryUtcTime value={hold.review_at} />
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Released at (UTC)</dt>
        <dd>
          <QueryUtcTime value={hold.released_at} />
        </dd>
      </div>
    </dl>
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
  const [error, setError] = useState('');
  const [inputError, setInputError] = useState('');
  const [status, setStatus] = useState(
    'Choose a reference or explicitly select all original references, then read. No request has run.'
  );
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
    setStatus('Filters changed. Read explicitly for a new snapshot.');
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
    setStatus('Loading one bounded Legal Holds page...');
    try {
      const result = await new LegalClient(client).holds(query, controller.signal);
      if (!work.current(controller)) return;
      setPage(result);
      setSubmitted(query);
      setStatus(
        `${result.items.length} requests on this page. Total ${result.total} in this response snapshot, not a stable multi-page inventory.`
      );
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
      setInputError(
        `Enter a canonical nonzero account reference or explicitly select all original references, and a page size from 1 to ${sizes.max}. Invalid input never becomes an all-subject query.`
      );
      form.current?.querySelector<HTMLElement>('input:not(:disabled)')?.focus();
    }
  }
  if (cleared) return <Feedback status={legalClearedMessage} />;
  return (
    <div ref={region}>
      <Panel title="Read independent requests" id={`${id}-heading`}>
        <form
          ref={form}
          aria-label="Read Legal Holds"
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
            <Label htmlFor={`${id}-ref`}>Original account reference</Label>
            <Input
              id={`${id}-ref`}
              name="accountRef"
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
            All original references
          </label>
          <div className="grid min-w-0 gap-4 sm:grid-cols-2">
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-status`}>Hold status</Label>
              <select
                id={`${id}-status`}
                name="status"
                value={draft.status}
                className={querySelectClass}
                onChange={(event) => edit({ ...draft, status: event.target.value })}
              >
                <option value="active">Active</option>
                <option value="released">Released</option>
                <option value="all">All</option>
              </select>
            </div>
            <div className="min-w-0 space-y-2">
              <Label htmlFor={`${id}-size`}>Page size</Label>
              <Input
                id={`${id}-size`}
                name="size"
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
            The reference is the original users.id, retained independently after deletion. An
            all-subject read is explicit and bounded to at most {sizes.max}
            requests per page. No account-profile browsing is granted.
          </p>
          {inputError && (
            <p id={`${id}-error`} role="alert" className="text-sm text-destructive">
              {inputError}
            </p>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending}>
              Read Legal Holds
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() =>
                edit({ accountRef: '', all: false, status: 'active', size: String(sizes.default) })
              }
            >
              Clear hold query
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
                Cancel hold read
              </Button>
            )}
          </div>
        </form>
        <Feedback error={error} status={status} />
        {page?.items.length === 0 && (
          <p className="text-sm">
            No requests were returned on this page of the submitted filters. This is not a
            missing-request API response or proof of no historical hold.
          </p>
        )}
        {page && page.items.length > 0 && (
          <div
            role="region"
            aria-label="Legal Holds, horizontally scrollable"
            tabIndex={0}
            className={queryTableFrameClass}
            onFocus={revealQueryFocus}
            data-legal-private
          >
            <table className="w-full min-w-[54rem] border-collapse">
              <caption className="sr-only">
                Independent Legal Hold and preservation requests
              </caption>
              <thead className="border-b bg-muted/40">
                <tr>
                  {[
                    'Request kind',
                    'Hold request UUID',
                    'Original account reference',
                    'Status',
                    'Applied (UTC)',
                    'Advisory review (UTC)',
                    'Released (UTC)',
                    'Actor references',
                    'Actions',
                  ].map((label) => (
                    <th key={label} scope="col" className={queryHeadClass}>
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y">
                {page.items.map((row) => (
                  <tr key={row.id} data-testid="legal-hold-row">
                    <td className={queryCellClass}>
                      {row.request_kind === 'preservation' ? 'Preservation' : 'Legal Hold'}
                    </td>
                    <th
                      scope="row"
                      className={`${queryCellClass} max-w-52 break-all font-mono text-xs`}
                    >
                      {row.id}
                    </th>
                    <td className={`${queryCellClass} max-w-52 break-all font-mono text-xs`}>
                      {row.account_ref}
                    </td>
                    <td className={queryCellClass}>{row.is_active ? 'Active' : 'Released'}</td>
                    <td className={queryCellClass}>
                      <QueryUtcTime value={row.applied_at} />
                    </td>
                    <td className={queryCellClass}>
                      <QueryUtcTime value={row.review_at} />
                    </td>
                    <td className={queryCellClass}>
                      <QueryUtcTime value={row.released_at} />
                    </td>
                    <td className={`${queryCellClass} max-w-52 break-all text-xs`}>
                      Applied by: {row.applied_by}
                      <br />
                      Released by: {row.released_by ?? 'Not recorded'}
                    </td>
                    <td className={`${queryCellClass} space-y-2`}>
                      <Button
                        type="button"
                        variant="outline"
                        className={controlClass}
                        onClick={() => onDetails(row)}
                      >
                        View restricted details
                      </Button>
                      {canRelease && row.is_active && (
                        <Button
                          type="button"
                          variant="outline"
                          className={controlClass}
                          onClick={() => onRelease(row)}
                        >
                          Release request
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {page && submitted && (
          <nav
            aria-label="Legal Holds offset pagination"
            className="flex flex-wrap items-center gap-3"
          >
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={pending || submitted.offset === 0}
              onClick={() =>
                void load({ ...submitted, offset: Math.max(0, submitted.offset - submitted.limit) })
              }
            >
              Previous hold page
            </Button>
            <span className="text-sm text-muted-foreground">
              Offset {page.offset}; {page.items.length} of {page.total} in this response snapshot.
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
              Next hold page
            </Button>
          </nav>
        )}
      </Panel>
    </div>
  );
}
