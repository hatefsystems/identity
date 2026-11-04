'use client';

import { useTranslations } from 'next-intl';
import type { Message } from '../../../i18n/messages';
import { Button, Label } from '@hatef/ui';
import { useId, useState } from 'react';
import { controlClass, Feedback, PageHeading, Panel } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type { AdminCapabilities, AdminChain } from '../../_lib/admin/contracts';
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

export function IntegrityView() {
  const t = useTranslations('integrity');
  const { client, profile, capabilities, reportPermissionLoss } = usePortal();
  const allowed =
    capabilities?.capabilities.audit_chain_verify || capabilities?.capabilities.ledger_verify;
  return (
    <>
      <PageHeading title={t('title')}>{t('introduction')}</PageHeading>
      {allowed && capabilities ? (
        <IntegrityQuery
          key={`${profile.session.id}:${capabilities.capabilities.audit_chain_verify}:${capabilities.capabilities.ledger_verify}`}
          client={client}
          capabilities={capabilities}
          reportPermissionLoss={reportPermissionLoss}
        />
      ) : (
        <Feedback error={{ key: 'integrity.denied' }} />
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
  const t = useTranslations('integrity');
  const [chain, setChain] = useState<AdminChain>(
    capabilities.capabilities.audit_chain_verify ? 'audit' : 'ledger'
  );
  const [run, setRun] = useState<VerificationRun | null>(null);
  const [pending, setPending] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [notice, setNotice] = useState<Message>({ key: 'integrity.initial' });
  const [error, setError] = useState<Message>('');
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
    setNotice({ key: 'integrity.checking' });
    try {
      const page = await new AdminClient(client).verify(
        current.chain,
        current.next,
        controller.signal
      );
      if (!work.current(controller)) return;
      const next = advanceVerificationRun(current, page);
      setRun(next);
      setNotice({
        key: page.verified
          ? page.complete
            ? next.checked === 0
              ? 'integrity.noRecords'
              : 'integrity.complete'
            : 'integrity.partial'
          : page.failure_reason === 'no_stored_records'
            ? 'integrity.noEvidence'
            : 'integrity.failed',
      });
    } catch (failure) {
      if (!work.current(controller) || isAborted(failure)) return;
      setRun({ ...current, next: null });
      setStopped(true);
      setNotice({ key: 'integrity.incomplete' });
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
    setNotice({ key: 'integrity.stopped' });
  }

  if (cleared) return <Feedback status={queryClearedMessage} />;
  const page = run?.result;
  const failure = page?.failure_reason;
  const integrityFailure = failure && failure !== 'no_stored_records';
  return (
    <>
      <Panel title={t('verify')} id={`${id}-heading`}>
        <div className="max-w-sm space-y-2">
          <Label htmlFor={`${id}-chain`}>{t('chain')}</Label>
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
              setNotice({ key: 'integrity.changed' });
            }}
          >
            {capabilities.capabilities.audit_chain_verify && (
              <option value="audit">{t('audit')}</option>
            )}
            {capabilities.capabilities.ledger_verify && (
              <option value="ledger">{t('ledger')}</option>
            )}
          </select>
        </div>
        <p className="text-sm text-muted-foreground">
          {t('instructions', { limit: Math.min(1000, capabilities.limits.chain_verify_max_limit) })}
        </p>
        <div className="flex flex-wrap gap-3">
          <Button type="button" className={controlClass} disabled={pending} onClick={start}>
            {t('start')}
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
            {t('continue')}
          </Button>
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={!pending && (!run?.next || !run.result)}
            onClick={stop}
          >
            {t('stop')}
          </Button>
        </div>
        <Feedback
          status={notice}
          error={
            error ||
            (integrityFailure ? t('failureEnd', { description: t(`failures.${failure}`) }) : '')
          }
        />
        {run && (
          <dl
            aria-label={t('progress')}
            className="grid min-w-0 gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3"
          >
            {[
              ['chain', t(run.chain)],
              ['bound', run.through_seq ?? t('notCaptured')],
              ['pages', String(run.pages)],
              ['checked', String(run.checked)],
              ['pageChecked', String(page?.checked ?? 0)],
              ['limit', String(run.limit)],
            ].map(([field, value]) => (
              <div key={field} className="min-w-0">
                <dt className="text-muted-foreground">
                  {t(
                    `fields.${field as keyof typeof import('../../../messages/integrity').integrityEn.fields}`
                  )}
                </dt>
                <dd
                  dir="ltr"
                  className="mt-1 break-all font-mono"
                  data-testid={field === 'bound' ? 'verification-bound' : undefined}
                >
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        )}
        {page && (
          <div className="min-w-0 space-y-4 border-t pt-4" data-testid="verification-page">
            <h3 className="font-semibold">{t('page')}</h3>
            {page.verified && page.complete && run?.checked === 0 && (
              <p className="text-sm">{t('empty')}</p>
            )}
            {failure === 'no_stored_records' && (
              <p className="text-sm">{t('failures.no_stored_records')}</p>
            )}
            {!page.verified && failure !== 'no_stored_records' && (
              <p className="text-sm">{t('failureCounts')}</p>
            )}
            <dl className="grid min-w-0 gap-4 text-sm sm:grid-cols-2">
              {[
                ['after', page.after_seq],
                ['first', page.first_seq ?? t('none')],
                ['last', page.last_seq ?? t('none')],
                ['seedSource', t(`seed.${page.seed_source}`)],
                ['seedHash', page.seed_hash],
                ['lastHash', page.last_hash],
                ...(failure
                  ? [
                      ['failure', failure],
                      ['broken', page.broken_at_seq ?? t('notProvided')],
                    ]
                  : []),
                ...(page.expected_hash !== null ? [['expected', page.expected_hash]] : []),
                ...(page.stored_hash !== null ? [['stored', page.stored_hash]] : []),
              ].map(([field, value]) => (
                <div key={field} className="min-w-0">
                  <dt className="text-muted-foreground">
                    {t(
                      `fields.${field as keyof typeof import('../../../messages/integrity').integrityEn.fields}`
                    )}
                  </dt>
                  <dd dir="ltr" className="mt-1 break-all font-mono text-xs">
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
            {page.chain === 'ledger' && run && (
              <div className="space-y-2 text-sm">
                <p>
                  {t('erasedCounts', {
                    page: page.erased_checked ?? 0,
                    total: run.erased_checked,
                    checked: run.checked,
                  })}
                </p>
                {page.verified && (
                  <p>
                    {t('retainedCounts', {
                      page: page.checked - (page.erased_checked ?? 0),
                      total: run.checked - run.erased_checked,
                    })}
                  </p>
                )}
                <p className="text-muted-foreground">{t('erasureLimits')}</p>
              </div>
            )}
            {page.chain === 'audit' && page.verified && page.checked > 0 && (
              <p className="text-sm">{t('auditCounts', { count: page.checked })}</p>
            )}
            <div className="space-y-2">
              <h3 className="text-sm font-semibold">{t('scope')}</h3>
              <p className="text-sm leading-relaxed">{t(`scopes.${page.chain}`)}</p>
              <details className="min-w-0 rounded-md border px-3">
                <summary className="min-h-11 cursor-pointer py-3 text-sm">{t('original')}</summary>
                <p dir="ltr" className="break-words pb-3 font-mono text-xs leading-relaxed">
                  {page.scope}
                </p>
              </details>
            </div>
          </div>
        )}
      </Panel>
      <Panel title={t('limits')} id={`${id}-limits`}>
        <p className="text-sm leading-relaxed">{t('relativeLimits')}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{t('snapshotLimits')}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{t('sequenceLimits')}</p>
      </Panel>
    </>
  );
}
