'use client';

import { Button } from '@hatef/ui';
import { useEffect, useRef, useState } from 'react';
import type { BrowserSession } from '../../_lib/portal/contracts';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { sensitiveClearEvent } from '../../_lib/portal/invalidation';
import { controlClass, DateLabel, Feedback, PageHeading, Panel } from './controls';
import { NativeDialog } from './native-dialog';
import { usePortal } from './portal-provider';

export function SessionsView() {
  const { client, signOut } = usePortal();
  const [sessions, setSessions] = useState<BrowserSession[] | null>(null);
  const [target, setTarget] = useState<BrowserSession | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const operation = useRef<AbortController | null>(null);
  const read = useRef<AbortController | null>(null);
  const readGeneration = useRef(0);

  function invalidateRead() {
    readGeneration.current++;
    read.current?.abort();
    read.current = null;
  }

  useEffect(() => {
    const controller = new AbortController();
    const generation = ++readGeneration.current;
    read.current = controller;
    setStatus('Loading sessions...');
    setError('');
    client
      .sessions(controller.signal)
      .then((items) => {
        throwIfAborted(controller.signal);
        if (generation !== readGeneration.current) return;
        setSessions(items);
        setStatus('');
      })
      .catch((failure) => {
        if (
          generation === readGeneration.current &&
          !controller.signal.aborted &&
          !isAborted(failure)
        ) {
          setError(errorMessage(failure));
          setStatus('');
        }
      });
    return () => controller.abort();
  }, [client, attempt]);
  useEffect(() => {
    const clear = () => {
      operation.current?.abort();
      operation.current = null;
      setTarget(null);
      setPending(false);
    };
    window.addEventListener(sensitiveClearEvent, clear);
    return () => {
      operation.current?.abort();
      window.removeEventListener(sensitiveClearEvent, clear);
    };
  }, []);

  function close() {
    if (operation.current) {
      operation.current.abort();
      operation.current = null;
      setStatus(
        'Revocation was cancelled locally. It may already have completed. Refresh the list before trying again.'
      );
    }
    setTarget(null);
    setPending(false);
  }

  async function revoke() {
    if (!target || operation.current) return;
    invalidateRead();
    if (target.current) {
      await signOut(target.id);
      return;
    }
    const controller = new AbortController();
    operation.current = controller;
    setPending(true);
    setError('');
    setStatus('');
    try {
      await client.revokeSession(target.id, controller.signal);
      throwIfAborted(controller.signal);
      invalidateRead();
      setSessions((items) => items?.filter((item) => item.id !== target.id) ?? null);
      setTarget(null);
      setStatus('Session revoked. Its linked access and refresh authority is no longer available.');
    } catch (failure) {
      if (!controller.signal.aborted && !isAborted(failure)) {
        setTarget(null);
        if (failure instanceof PortalError && failure.status === 404) {
          invalidateRead();
          setSessions((items) => items?.filter((item) => item.id !== target.id) ?? null);
          setStatus('This session is no longer in the list. Refresh to review current sessions.');
        } else setError(errorMessage(failure));
      }
    } finally {
      if (operation.current === controller) operation.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }

  return (
    <>
      <PageHeading title="Sessions">
        A session is server-side browser authority, not a verified physical device or a separate
        OAuth grant. Revoke individual sessions you no longer need.
      </PageHeading>
      <Panel title="Active browser sessions" id="sessions-heading">
        <Feedback error={error} status={status} />
        {sessions && (
          <ul className="divide-y rounded-lg border" aria-label="Active sessions">
            {sessions.map((session) => (
              <li
                key={session.id}
                data-testid="session-row"
                data-session-id={session.id}
                className="space-y-3 p-4"
              >
                <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                  <div className="min-w-0 space-y-1">
                    <h3 className="font-medium">
                      {session.current ? 'This browser session' : 'Other browser session'}
                    </h3>
                    <p className="break-all font-mono text-xs text-muted-foreground">
                      {session.id}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className={controlClass}
                    onClick={() => {
                      setTarget({ ...session });
                      setError('');
                    }}
                  >
                    {session.current ? 'Sign out this session' : 'Revoke session'}
                  </Button>
                </div>
                <dl className="grid gap-3 text-sm sm:grid-cols-2">
                  <div className="min-w-0">
                    <dt className="text-muted-foreground">Reported browser details</dt>
                    <dd className="mt-1 break-words">{session.user_agent || 'Not provided'}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">IP at session creation</dt>
                    <dd className="mt-1 break-all">{session.ip || 'Not provided'}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Created</dt>
                    <dd className="mt-1">
                      <DateLabel value={session.created_at} />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">Last activity</dt>
                    <dd className="mt-1">
                      <DateLabel value={session.last_seen_at} />
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        )}
        {sessions?.length === 0 && (
          <p className="text-sm">
            No active sessions are listed. Refresh to verify the current state.
          </p>
        )}
        <Button
          type="button"
          variant="outline"
          className={controlClass}
          disabled={Boolean(target) || pending}
          onClick={() => {
            invalidateRead();
            setAttempt((value) => value + 1);
          }}
        >
          Refresh sessions
        </Button>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Revocation blocks subsequent authorization. A request already admitted may finish, and
          another browser clears its rendered data when it detects session loss. Browser details and
          IP addresses do not establish location or device ownership.
        </p>
      </Panel>
      {target && (
        <NativeDialog
          title={target.current ? 'Sign out this session?' : 'Revoke this session?'}
          description={
            <>
              {target.current
                ? 'This will end the current browser session and clear private portal data.'
                : 'This will revoke the selected browser session and its linked access and refresh authority.'}
              <span className="mt-2 block break-all font-mono text-xs">{target.id}</span>
            </>
          }
          onCancel={close}
          testId="session-dialog"
        >
          <Feedback status={pending ? 'Revoking the selected session...' : ''} />
          <div className="flex flex-wrap gap-3">
            <Button type="button" className={controlClass} onClick={revoke} disabled={pending}>
              {target.current ? 'Confirm sign out' : 'Confirm revocation'}
            </Button>
            <Button type="button" variant="outline" className={controlClass} onClick={close}>
              Cancel
            </Button>
          </div>
        </NativeDialog>
      )}
    </>
  );
}
