'use client';

import type { Message, MessageDescriptor } from '../../../i18n/messages';

import { useTranslations } from 'next-intl';

import { Button } from '@hatef/ui';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { RecoveryStatus, StepUpGrant } from '../../_lib/portal/contracts';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { sensitiveClearEvent } from '../../_lib/portal/invalidation';
import { controlClass, Feedback, Panel } from './controls';
import { usePortal } from './portal-provider';
import { StepUpDialog } from './step-up-dialog';

type VisibleBatch = {
  codes: string[];
  sessionID: string;
  deadline: number;
  monotonicDeadline: number;
};
const uncertainGeneration: MessageDescriptor = { key: 'security.recovery.uncertain' };

function generationError(failure: unknown): MessageDescriptor {
  if (failure instanceof PortalError && failure.uncertain) return uncertainGeneration;
  if (failure instanceof PortalError && failure.code === 'viewer_expired')
    return { key: 'security.recovery.expiredBeforeDisplay' };
  return errorMessage(failure);
}

export function RecoveryPanel() {
  const t = useTranslations();
  const { client, resumedAction } = usePortal();
  const [remaining, setRemaining] = useState<RecoveryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<Message>('');
  const [error, setError] = useState<Message>('');
  const [status, setStatus] = useState<Message>('');
  const [attempt, setAttempt] = useState(0);
  const [confirm, setConfirm] = useState(resumedAction?.kind === 'recovery');
  const [resumeTotp, setResumeTotp] = useState(resumedAction?.kind === 'recovery');
  const [batch, setBatch] = useState<VisibleBatch | null>(null);
  const [exportBusy, setExportBusy] = useState(false);
  const current = useRef<VisibleBatch | null>(null);
  const exporting = useRef<VisibleBatch | null>(null);
  const activeAction = useRef(confirm);
  const generationPending = useRef(false);
  const alive = useRef(false);
  const viewer = useRef<HTMLDivElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const downloads = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const revokeDownloads = useCallback(() => {
    for (const [url, timer] of downloads.current) {
      clearTimeout(timer);
      URL.revokeObjectURL(url);
    }
    downloads.current.clear();
  }, []);

  const clearBatch = useCallback(
    (message: Message = '') => {
      // Hide synchronously before a pagehide/bfcache snapshot; React then removes
      // the nodes. This is an HTML attribute, not an inline style or CSP exception.
      if (viewer.current) viewer.current.hidden = true;
      current.current = null;
      exporting.current = null;
      revokeDownloads();
      setBatch(null);
      setExportBusy(false);
      if (message) {
        setStatus(message);
        setError('');
      }
    },
    [revokeDownloads]
  );

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError('');
    client
      .recoveryStatus(controller.signal)
      .then((value) => {
        throwIfAborted(controller.signal);
        setRemaining(value);
        setLoading(false);
      })
      .catch((failure) => {
        if (!controller.signal.aborted && !isAborted(failure)) {
          setLoadError(errorMessage(failure));
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, attempt]);

  useEffect(() => {
    alive.current = true;
    function clearView() {
      clearBatch({ key: 'security.recovery.closed' });
      activeAction.current = false;
      setConfirm(false);
    }
    function visibility() {
      if (document.visibilityState === 'hidden') clearView();
    }
    function pageshow(event: PageTransitionEvent) {
      if (event.persisted) clearView();
    }
    window.addEventListener(sensitiveClearEvent, clearView);
    window.addEventListener('pagehide', clearView);
    window.addEventListener('pageshow', pageshow);
    window.addEventListener('popstate', clearView);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      alive.current = false;
      activeAction.current = false;
      current.current = null;
      exporting.current = null;
      revokeDownloads();
      window.removeEventListener(sensitiveClearEvent, clearView);
      window.removeEventListener('pagehide', clearView);
      window.removeEventListener('pageshow', pageshow);
      window.removeEventListener('popstate', clearView);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [clearBatch, revokeDownloads]);

  useEffect(() => {
    if (!batch) return;
    if (!confirm) heading.current?.focus();
    const wait = Math.min(batch.deadline - Date.now(), batch.monotonicDeadline - performance.now());
    const timer = setTimeout(
      () => clearBatch({ key: 'security.recovery.expired' }),
      Math.max(0, wait)
    );
    return () => clearTimeout(timer);
  }, [batch, clearBatch, confirm]);

  function closeConfirmation() {
    activeAction.current = false;
    setConfirm(false);
    setResumeTotp(false);
    if (generationPending.current) {
      setError(uncertainGeneration);
      setStatus('');
    }
  }

  async function generate(grant: StepUpGrant, signal: AbortSignal) {
    const session = client.assertSession().session;
    const start = Date.now();
    const monotonicStart = performance.now();
    const lifetime = Math.min(300000, Date.parse(session.expires_at) - start);
    generationPending.current = true;
    try {
      const result = await client.generateRecovery(grant, signal);
      throwIfAborted(signal);
      if (!alive.current || !activeAction.current)
        throw new DOMException('Cancelled', 'AbortError');
      if (client.assertSession().session.id !== session.id)
        throw new PortalError('session_changed', 409);
      if (
        document.visibilityState === 'hidden' ||
        Date.now() >= start + lifetime ||
        performance.now() >= monotonicStart + lifetime
      )
        throw new PortalError('viewer_expired');
      const visible = {
        codes: result.codes,
        sessionID: session.id,
        deadline: start + lifetime,
        monotonicDeadline: monotonicStart + lifetime,
      };
      current.current = visible;
      setBatch(visible);
      setError('');
      setStatus({ key: 'security.recovery.generated' });
      setRemaining(null);
      setAttempt((value) => value + 1);
    } catch (failure) {
      if (alive.current && !signal.aborted && !isAborted(failure)) {
        setError(generationError(failure));
        setStatus('');
      }
      throw failure;
    } finally {
      generationPending.current = false;
    }
  }

  function validBatch(): VisibleBatch | null {
    const value = current.current;
    if (!value) return null;
    try {
      if (client.assertSession().session.id !== value.sessionID)
        throw new PortalError('session_changed', 409);
    } catch (failure) {
      clearBatch();
      setError(errorMessage(failure));
      return null;
    }
    if (
      Date.now() >= value.deadline ||
      performance.now() >= value.monotonicDeadline ||
      document.visibilityState === 'hidden'
    ) {
      clearBatch({ key: 'security.recovery.expired' });
      return null;
    }
    return value;
  }

  async function copy() {
    const value = validBatch();
    if (!value || exporting.current) return;
    exporting.current = value;
    setExportBusy(true);
    setError('');
    setStatus({ key: 'security.recovery.copying' });
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(`${value.codes.join('\n')}\n`);
      if (alive.current && current.current === value && validBatch())
        setStatus({ key: 'security.recovery.copied' });
    } catch {
      if (alive.current && current.current === value) {
        setError({ key: 'security.recovery.copyFailed' });
        setStatus('');
      }
    } finally {
      if (exporting.current === value) {
        exporting.current = null;
        setExportBusy(false);
      }
    }
  }

  function download() {
    const value = validBatch();
    if (!value || exporting.current) return;
    let url: string | undefined;
    const anchor = document.createElement('a');
    setError('');
    try {
      const blob = new Blob([`${value.codes.join('\n')}\n`], { type: 'text/plain;charset=utf-8' });
      url = URL.createObjectURL(blob);
      anchor.href = url;
      anchor.download = 'recovery-codes.txt';
      anchor.hidden = true;
      document.body.append(anchor);
      anchor.click();
      const createdURL = url;
      // Allow the browser to start the download, then promptly release the URL.
      // Done, navigation and pagehide revoke sooner through revokeDownloads().
      const timer = setTimeout(() => {
        URL.revokeObjectURL(createdURL);
        downloads.current.delete(createdURL);
      }, 1000);
      downloads.current.set(createdURL, timer);
      setStatus({ key: 'security.recovery.downloaded' });
    } catch {
      if (url) URL.revokeObjectURL(url);
      setError({ key: 'security.recovery.downloadFailed' });
      setStatus('');
    } finally {
      anchor.remove();
    }
  }

  return (
    <Panel title={t('security.recovery.title')} id="recovery-heading">
      <p className="text-sm leading-relaxed text-muted-foreground">
        {t('security.recovery.description')}
      </p>
      {remaining && (
        <p className="text-sm" data-testid="recovery-status">
          {t.rich('security.recovery.remaining', {
            count: remaining.remaining,
            amount: (chunks) => <strong className="text-lg tabular-nums">{chunks}</strong>,
          })}
          {remaining.low ? ` ${t('security.recovery.low')}` : ''}
        </p>
      )}
      <Feedback error={loadError} status={loading ? t('security.recovery.loading') : ''} />
      <Feedback error={error} status={status} />
      <div className="flex flex-wrap gap-3">
        <Button
          type="button"
          className={controlClass}
          onClick={() => {
            if (activeAction.current) return;
            clearBatch();
            setError('');
            setStatus('');
            activeAction.current = true;
            setConfirm(true);
            setResumeTotp(false);
          }}
        >
          {t('security.recovery.generate')}
        </Button>
        <Button
          type="button"
          variant="outline"
          className={controlClass}
          disabled={loading}
          onClick={() => setAttempt((value) => value + 1)}
        >
          {t('security.recovery.refresh')}
        </Button>
      </div>
      {batch && (
        <div
          ref={viewer}
          data-testid="recovery-viewer"
          className="space-y-4 rounded-lg border-2 border-foreground bg-background p-4 sm:p-5"
        >
          <h3 ref={heading} tabIndex={-1} className="font-semibold focus:outline-none">
            {t('security.recovery.save')}
          </h3>
          <p className="text-sm leading-relaxed">{t('security.recovery.viewerWarning')}</p>
          <ol
            aria-label={t('security.recovery.list')}
            className="grid min-w-0 gap-2 sm:grid-cols-2"
          >
            {batch.codes.map((code, index) => (
              <li key={index} className="min-w-0 rounded-md border bg-muted/40 p-3">
                <code
                  data-testid="recovery-code"
                  dir="ltr"
                  className="break-all font-mono text-sm leading-relaxed"
                >
                  {code}
                </code>
              </li>
            ))}
          </ol>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t('security.recovery.storageWarning')}
          </p>
          <div className="flex flex-wrap gap-3">
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={exportBusy}
              onClick={copy}
            >
              {t('security.recovery.copy')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={exportBusy}
              onClick={download}
            >
              {t('security.recovery.download')}
            </Button>
            <Button
              type="button"
              className={controlClass}
              onClick={() => clearBatch({ key: 'security.recovery.cleared' })}
            >
              {t('security.recovery.done')}
            </Button>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            {t('security.recovery.clearWarning')}
          </p>
        </div>
      )}
      {confirm && (
        <StepUpDialog
          title={t('security.recovery.replace')}
          description={t('security.recovery.replaceDescription')}
          onCancel={closeConfirmation}
          onAuthorized={generate}
          actionError={generationError}
          intent={{ kind: 'recovery' }}
          resumeMethod={resumeTotp ? 'totp' : undefined}
        />
      )}
    </Panel>
  );
}
