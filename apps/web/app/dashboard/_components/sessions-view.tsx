'use client';

import type { Message } from '../../../i18n/messages';

import { useTranslations } from 'next-intl';

import { Button } from '@hatef/ui';
import { useEffect, useRef, useState } from 'react';
import type { BrowserSession } from '../../_lib/portal/contracts';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { sensitiveClearEvent } from '../../_lib/portal/invalidation';
import { controlClass, DateLabel, Feedback, PageHeading, Panel } from './controls';
import { NativeDialog } from './native-dialog';
import { usePortal } from './portal-provider';

export function SessionsView() {
  const t = useTranslations();
  const { client, signOut } = usePortal();
  const [sessions, setSessions] = useState<BrowserSession[] | null>(null);
  const [target, setTarget] = useState<BrowserSession | null>(null);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState<Message>('');
  const [error, setError] = useState<Message>('');
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
    setStatus({ key: 'portal.sessions.loading' });
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
      setStatus({ key: 'portal.sessions.cancelled' });
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
      setStatus({ key: 'portal.sessions.revoked' });
    } catch (failure) {
      if (!controller.signal.aborted && !isAborted(failure)) {
        setTarget(null);
        if (failure instanceof PortalError && failure.status === 404) {
          invalidateRead();
          setSessions((items) => items?.filter((item) => item.id !== target.id) ?? null);
          setStatus({ key: 'portal.sessions.missing' });
        } else setError(errorMessage(failure));
      }
    } finally {
      if (operation.current === controller) operation.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }

  return (
    <>
      <PageHeading title={t('portal.sessions.title')}>
        {t('portal.sessions.description')}
      </PageHeading>
      <Panel title={t('portal.sessions.panel')} id="sessions-heading">
        <Feedback error={error} status={status} />
        {sessions && (
          <ul className="divide-y rounded-lg border" aria-label={t('portal.sessions.list')}>
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
                      {session.current ? t('portal.sessions.current') : t('portal.sessions.other')}
                    </h3>
                    <p
                      dir="ltr"
                      className="break-all font-mono text-xs text-muted-foreground isolate"
                    >
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
                    {session.current ? t('portal.sessions.signOut') : t('portal.sessions.revoke')}
                  </Button>
                </div>
                <dl className="grid gap-3 text-sm sm:grid-cols-2">
                  <div className="min-w-0">
                    <dt className="text-muted-foreground">{t('portal.sessions.browser')}</dt>
                    <dd dir="auto" className="mt-1 break-words isolate">
                      {session.user_agent || t('portal.sessions.notProvided')}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t('portal.sessions.ip')}</dt>
                    <dd dir="ltr" className="mt-1 break-all isolate">
                      {session.ip || t('portal.sessions.notProvided')}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t('portal.sessions.created')}</dt>
                    <dd className="mt-1">
                      <DateLabel value={session.created_at} />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t('portal.sessions.lastActivity')}</dt>
                    <dd className="mt-1">
                      <DateLabel value={session.last_seen_at} />
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ul>
        )}
        {sessions?.length === 0 && <p className="text-sm">{t('portal.sessions.empty')}</p>}
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
          {t('portal.sessions.refresh')}
        </Button>
        <p className="text-sm leading-relaxed text-muted-foreground">
          {t('portal.sessions.policy')}
        </p>
      </Panel>
      {target && (
        <NativeDialog
          title={
            target.current ? t('portal.sessions.signOutTitle') : t('portal.sessions.revokeTitle')
          }
          description={
            <>
              {target.current
                ? t('portal.sessions.signOutDescription')
                : t('portal.sessions.revokeDescription')}
              <span dir="ltr" className="mt-2 block break-all font-mono text-xs isolate">
                {target.id}
              </span>
            </>
          }
          onCancel={close}
          testId="session-dialog"
        >
          <Feedback status={pending ? t('portal.sessions.revoking') : ''} />
          <div className="flex flex-wrap gap-3">
            <Button type="button" className={controlClass} onClick={revoke} disabled={pending}>
              {target.current
                ? t('portal.sessions.confirmSignOut')
                : t('portal.sessions.confirmRevoke')}
            </Button>
            <Button type="button" variant="outline" className={controlClass} onClick={close}>
              {t('portal.sessions.cancel')}
            </Button>
          </div>
        </NativeDialog>
      )}
    </>
  );
}
