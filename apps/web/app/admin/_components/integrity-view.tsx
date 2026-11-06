'use client';

import { Button, Label } from '@hatef/ui';
import { useId, useState } from 'react';
import { controlClass, Feedback, PageHeading, Panel } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type {
  AdminCapabilities,
  AdminChain,
  AdminVerificationFailure,
} from '../../_lib/admin/contracts';
import {
  advanceVerificationRun,
  beginVerificationRun,
  type VerificationRun,
} from '../../_lib/admin/verification';
import type { PortalClient } from '../../_lib/portal/client';
import { isAborted, PortalError } from '../../_lib/portal/errors';
import { clearSensitiveViews } from '../../_lib/portal/invalidation';
import {
  queryClearedMessage,
  queryFailureMessage,
  querySelectClass,
  useQueryViewWork,
} from './query-view-state';

const integrityFailureDescriptions: Record<AdminVerificationFailure, string> = {
  chain_mismatch: 'The stored chain link differs from the recomputed link.',
  leaf_mismatch: 'A retained payload does not reproduce its stored leaf hash.',
  predecessor_mismatch:
    'The stored predecessor changed from the prior page hash supplied for this run.',
  invalid_leaf_hash: 'A stored leaf digest has an invalid format.',
  invalid_chain_hash: 'A stored chain digest has an invalid format.',
  record_not_serializable: 'A retained record could not be serialized in canonical format.',
  head_mismatch: 'The checked end does not agree with the stored logical head.',
  payload_absent_without_erasure_record:
    'A payload is absent without a recorded erasure annotation.',
  no_stored_records:
    'No stored records were available in the reported range. This is no verification evidence, not proof of no activity.',
};

export function IntegrityView() {
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  const allowed =
    capabilities?.capabilities.audit_chain_verify || capabilities?.capabilities.ledger_verify;
  return (
    <>
      <PageHeading title="Integrity verification">
        Run the canonical-v2 verifier independently of audit-search filters, one explicit bounded
        page at a time.
      </PageHeading>
      {allowed && capabilities ? (
        <IntegrityQuery
          key={`${profile.session.id}:${capabilities.capabilities.audit_chain_verify}:${capabilities.capabilities.ledger_verify}`}
          client={client}
          capabilities={capabilities}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error="This workspace does not grant chain-verification access. No verification was requested." />
      )}
    </>
  );
}

function IntegrityQuery({
  client,
  capabilities,
  reportPermissionLoss,
}: {
  client: PortalClient;
  capabilities: AdminCapabilities;
  reportPermissionLoss: () => void;
}) {
  const [chain, setChain] = useState<AdminChain>(
    capabilities.capabilities.audit_chain_verify ? 'audit' : 'ledger'
  );
  const [run, setRun] = useState<VerificationRun | null>(null);
  const [pending, setPending] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [notice, setNotice] = useState(
    'No verification has run. Start at genesis to capture a sequence bound.'
  );
  const [error, setError] = useState('');
  const id = useId();
  const { work, cleared } = useQueryViewWork(() => {
    setRun(null);
    setPending(false);
    setStopped(false);
    setNotice('');
    setError('');
  });

  async function verifyPage(current: VerificationRun) {
    if (!current.next) return;
    const controller = work.begin();
    if (!controller) return;
    setPending(true);
    setStopped(false);
    setError('');
    setNotice('Checking one bounded verification page...');
    try {
      const page = await new AdminClient(client).verify(
        current.chain,
        current.next,
        controller.signal
      );
      if (!work.current(controller)) return;
      const next = advanceVerificationRun(current, page);
      setRun(next);
      setNotice(
        page.verified
          ? page.complete
            ? next.checked === 0
              ? 'No records checked.'
              : 'Verification complete for the captured database-relative range.'
            : 'Clean partial segment. Verification is not complete.'
          : page.failure_reason === 'no_stored_records'
            ? 'No verification evidence.'
            : 'Verification stopped at the first integrity failure.'
      );
    } catch (failure) {
      if (!work.current(controller) || isAborted(failure)) return;
      setRun({ ...current, next: null });
      setStopped(true);
      setNotice(
        'Run incomplete. The requested page supplied no accepted verification evidence. Start a new run to try again.'
      );
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

  function start() {
    if (pending || work.blocked) return;
    const initial = beginVerificationRun(chain, capabilities.limits.chain_verify_max_limit);
    setRun(initial);
    void verifyPage(initial);
  }

  function stop() {
    work.cancel();
    setRun((current) => (current ? { ...current, next: null } : null));
    setPending(false);
    setStopped(true);
    setNotice(
      'Verification stopped. No complete-run conclusion was reached. Start a new run to continue from genesis.'
    );
  }

  if (cleared) return <Feedback status={queryClearedMessage} />;
  const page = run?.result;
  const failure = page?.failure_reason;
  const integrityFailure = failure && failure !== 'no_stored_records';
  return (
    <>
      <Panel title="Verify a chain" id={`${id}-heading`}>
        <div className="max-w-sm space-y-2">
          <Label htmlFor={`${id}-chain`}>Chain</Label>
          <select
            id={`${id}-chain`}
            value={chain}
            className={querySelectClass}
            onChange={(event) => {
              work.cancel();
              setChain(event.target.value as AdminChain);
              setRun(null);
              setPending(false);
              setStopped(false);
              setError('');
              setNotice('Chain selection changed. Start a new run; no prior progress is reused.');
            }}
          >
            {capabilities.capabilities.audit_chain_verify && (
              <option value="audit">Audit chain</option>
            )}
            {capabilities.capabilities.ledger_verify && (
              <option value="ledger">Security ledger</option>
            )}
          </select>
        </div>
        <p className="text-sm text-muted-foreground">
          Start at genesis, with at most{' '}
          {Math.min(1000, capabilities.limits.chain_verify_max_limit)} chain nodes per page. The
          first response captures the upper sequence bound; later pages keep that exact bound and
          the previous page&apos;s hash. New records are not chased.
        </p>
        <div className="flex flex-wrap gap-3">
          <Button type="button" className={controlClass} disabled={pending} onClick={start}>
            Start new run
          </Button>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={pending || stopped || !run?.result || !run.next}
            onClick={() => {
              if (run) void verifyPage(run);
            }}
          >
            Continue verification
          </Button>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={!pending && (!run?.next || !run.result)}
            onClick={stop}
          >
            Stop verification
          </Button>
        </div>
        <Feedback
          status={notice}
          error={
            error ||
            (integrityFailure
              ? `${integrityFailureDescriptions[failure]} No continuation is allowed for this run.`
              : '')
          }
        />
        {run && (
          <dl
            aria-label="Verification progress"
            className="grid min-w-0 gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3"
          >
            {[
              ['Chain', run.chain === 'audit' ? 'Audit chain' : 'Security ledger'],
              ['Captured through sequence', run.through_seq ?? 'Not captured yet'],
              ['Accepted pages', String(run.pages)],
              ['Chain nodes checked, cumulative', String(run.checked)],
              ['Chain nodes checked, last page', String(page?.checked ?? 0)],
              ['Work limit per page', String(run.limit)],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-muted-foreground">{label}</dt>
                <dd
                  className="mt-1 break-all font-mono"
                  data-testid={
                    label === 'Captured through sequence' ? 'verification-bound' : undefined
                  }
                >
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        )}
        {page && (
          <div className="min-w-0 space-y-4 border-t pt-4" data-testid="verification-page">
            <h3 className="font-semibold">Last accepted verification page</h3>
            {page.verified && page.complete && run?.checked === 0 && (
              <p className="text-sm">
                The reported chain is empty at the captured bound. No payload or record content was
                verified; this is not proof that no activity occurred.
              </p>
            )}
            {failure === 'no_stored_records' && (
              <p className="text-sm">{integrityFailureDescriptions.no_stored_records}</p>
            )}
            {!page.verified && failure !== 'no_stored_records' && (
              <p className="text-sm">
                Failure-page counts describe visited nodes, not successfully verified payloads.
                Earlier clean pages do not make this a complete proof.
              </p>
            )}
            <dl className="grid min-w-0 gap-4 text-sm sm:grid-cols-2">
              {[
                ['Page after sequence', page.after_seq],
                ['First checked sequence', page.first_seq ?? 'None'],
                ['Last checked sequence', page.last_seq ?? 'None'],
                [
                  'Seed source',
                  page.seed_source === 'genesis'
                    ? 'Genesis'
                    : page.seed_source === 'supplied_predecessor'
                      ? 'Prior page hash (supplied predecessor)'
                      : 'Stored database predecessor',
                ],
                ['Seed hash', page.seed_hash],
                ['Last hash', page.last_hash],
                ...(failure
                  ? [
                      ['Failure code', failure],
                      ['First failure sequence', page.broken_at_seq ?? 'Not provided'],
                    ]
                  : []),
                ...(page.expected_hash !== null ? [['Expected hash', page.expected_hash]] : []),
                ...(page.stored_hash !== null ? [['Stored hash', page.stored_hash]] : []),
              ].map(([label, value]) => (
                <div key={label} className="min-w-0">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="mt-1 break-all font-mono text-xs">{value}</dd>
                </div>
              ))}
            </dl>
            {page.chain === 'ledger' && run && (
              <div className="space-y-2 text-sm">
                <p>
                  Erasure annotations checked: {page.erased_checked} on the last page;{' '}
                  {run.erased_checked} cumulative. These are a subset of {run.checked} checked chain
                  nodes, not extra work.
                </p>
                {page.verified && (
                  <p>
                    Retained payloads recomputed: {page.checked - page.erased_checked} on the last
                    clean page; {run.checked - run.erased_checked} cumulative.
                  </p>
                )}
                <p className="text-muted-foreground">
                  Erased payloads retain chain links and erasure annotations, but their original
                  bodies cannot be recomputed. A fully erased ledger can have clean surviving links
                  without verifying its erased content. An annotation does not establish legal
                  authorization or that the purge operator honored retention and holds.
                </p>
              </div>
            )}
            {page.chain === 'audit' && page.verified && page.checked > 0 && (
              <p className="text-sm">
                Retained audit payloads were recomputed for the {page.checked} checked nodes on this
                clean page.
              </p>
            )}
            <div className="space-y-2">
              <h3 className="text-sm font-semibold">Backend scope</h3>
              <p className="break-words font-mono text-xs leading-relaxed">{page.scope}</p>
            </div>
          </div>
        )}
      </Panel>
      <Panel title="Verification limits" id={`${id}-limits`}>
        <p className="text-sm leading-relaxed">
          Verification is database-relative to the reported seed and bound. It does not prove
          complete event ingestion, independent historical authenticity, or protection from a
          coherent privileged rewrite or rollback.
        </p>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Each page uses its own database snapshot, not one multi-page global snapshot or an
          independently authenticated head. A continued run does not authenticate new tail records.
          A durable-head check does not independently detect a coherent privileged rollback; preserve the
          backend&apos;s reported scope when interpreting any result.
        </p>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Sequence gaps are valid; counts are not percentages. Stop and failures end continuation.
          Backgrounding, session changes, and navigation discard progress rather than silently
          restoring a proof. No audit payloads or other accounts are fetched by this view.
        </p>
      </Panel>
    </>
  );
}
