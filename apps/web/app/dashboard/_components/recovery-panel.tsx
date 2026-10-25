'use client';

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
const uncertainGeneration =
  'The generation response was lost. Previous recovery codes may already be invalid. No codes were recovered or automatically regenerated. Start a new generation explicitly with fresh verification when you are ready.';

function generationError(failure: unknown): string {
  if (failure instanceof PortalError && failure.uncertain) return uncertainGeneration;
  if (failure instanceof PortalError && failure.code === 'viewer_expired')
    return 'New codes were generated, but this one-time view expired before they could be displayed. Previous codes are invalid. Start a new generation with fresh verification when you are ready.';
  return errorMessage(failure);
}

export function RecoveryPanel() {
  const { client, resumedAction } = usePortal();
  const [remaining, setRemaining] = useState<RecoveryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
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
    (message = '') => {
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
      clearBatch('The one-time view has closed. Saved codes remain valid until used or replaced.');
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
      () =>
        clearBatch(
          'The one-time view has expired. Saved codes remain valid until used or replaced.'
        ),
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
      setStatus(
        'New recovery codes generated. Save them privately now; they cannot be retrieved later.'
      );
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
      clearBatch('The one-time view has expired. Saved codes remain valid until used or replaced.');
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
    setStatus('Copying codes...');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(`${value.codes.join('\n')}\n`);
      if (alive.current && current.current === value && validBatch())
        setStatus('Codes copied. Store them privately and clear your clipboard when finished.');
    } catch {
      if (alive.current && current.current === value) {
        setError(
          'Copy failed. This browser did not allow clipboard access. Try Download codes or copy the displayed codes manually.'
        );
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
      setStatus(
        'Download requested. Check your browser downloads; this page cannot confirm that the file was saved.'
      );
    } catch {
      if (url) URL.revokeObjectURL(url);
      setError(
        'The download could not be started. Try Copy codes or save the displayed codes manually.'
      );
      setStatus('');
    } finally {
      anchor.remove();
    }
  }

  return (
    <Panel title="Recovery codes" id="recovery-heading">
      <p className="text-sm leading-relaxed text-muted-foreground">
        Recovery codes provide account recovery when your normal factors are unavailable. Old
        plaintext codes cannot be retrieved.
      </p>
      {remaining && (
        <p className="text-sm" data-testid="recovery-status">
          <strong className="text-lg tabular-nums">{remaining.remaining}</strong> unused codes
          remaining.{remaining.low ? ' Your supply is running low.' : ''}
        </p>
      )}
      <Feedback error={loadError} status={loading ? 'Checking remaining recovery codes...' : ''} />
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
          Generate new recovery codes
        </Button>
        <Button
          type="button"
          variant="outline"
          className={controlClass}
          disabled={loading}
          onClick={() => setAttempt((value) => value + 1)}
        >
          Refresh recovery status
        </Button>
      </div>
      {batch && (
        <div
          ref={viewer}
          data-testid="recovery-viewer"
          className="space-y-4 rounded-lg border-2 border-foreground bg-background p-4 sm:p-5"
        >
          <h3 ref={heading} tabIndex={-1} className="font-semibold focus:outline-none">
            Save your new recovery codes
          </h3>
          <p className="text-sm leading-relaxed">
            Every previous code is now invalid. These codes are shown once and clear within five
            minutes, at session expiry, or when you leave or hide this page.
          </p>
          <ol aria-label="New recovery codes" className="grid min-w-0 gap-2 sm:grid-cols-2">
            {batch.codes.map((code, index) => (
              <li key={index} className="min-w-0 rounded-md border bg-muted/40 p-3">
                <code
                  data-testid="recovery-code"
                  className="break-all font-mono text-sm leading-relaxed"
                >
                  {code}
                </code>
              </li>
            ))}
          </ol>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Keep the codes in private storage, such as a password manager. Anyone who obtains a code
            may recover your account. Do not share or email them.
          </p>
          <div className="flex flex-wrap gap-3">
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={exportBusy}
              onClick={copy}
            >
              Copy codes
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              disabled={exportBusy}
              onClick={download}
            >
              Download codes
            </Button>
            <Button
              type="button"
              className={controlClass}
              onClick={() =>
                clearBatch(
                  'Codes cleared from this view. Saved codes remain valid until used or replaced.'
                )
              }
            >
              Done
            </Button>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Clearing this view does not erase your clipboard or downloaded files and cannot
            guarantee browser-memory zeroization.
          </p>
        </div>
      )}
      {confirm && (
        <StepUpDialog
          title="Replace recovery codes"
          description="Generating a new batch immediately invalidates every previous recovery code. The new codes will be displayed once. Continue only when you are ready to save them privately."
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
