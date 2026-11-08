'use client';

import { Button } from '@hatef/ui';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useTranslations } from 'next-intl';
import { useEffect, useRef, useState } from 'react';
import type { Message } from '../../../i18n/messages';
import { controlClass, Feedback, linkClass, PageHeading } from '../../_components/controls';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type { AdminUser } from '../../_lib/admin/contracts';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import {
  clearSensitiveViews,
  sensitiveClearEvent,
  sensitiveSuspendEvent,
} from '../../_lib/portal/invalidation';
import {
  canModerate,
  ModerationDialog,
  type ModerationOutcome,
  type ModerationStatus,
} from './moderation-dialog';
import { QueryUtcTime } from './query-view-time';

export function UserDetailView() {
  const t = useTranslations('admin');
  const params = useParams<{ id: string }>();
  const id =
    typeof params.id === 'string' &&
    /^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/.test(params.id)
      ? params.id
      : '';
  const {
    client,
    profile,
    capabilities,
    resumedAction,
    reportPermissionLoss,
    moderationInterrupted,
  } = usePortal();
  const access = capabilities?.capabilities;
  const [user, setUser] = useState<AdminUser | null>(null);
  const [error, setError] = useState<Message>('');
  const [status, setStatus] = useState<Message>('');
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [action, setAction] = useState<{
    target: AdminUser;
    desired: ModerationStatus;
    resume: boolean;
  } | null>(null);
  const resume = useRef(resumedAction?.kind === 'moderation' ? resumedAction.status : null);
  const request = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const selecting = useRef(false);
  const confirmed = useRef(false);
  const interruptedOnMount = useRef(Boolean(moderationInterrupted));
  const actionOpener = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (action || busy) return;
    const opener = actionOpener.current;
    actionOpener.current = null;
    if (opener?.isConnected && !opener.disabled) opener.focus();
    else if (opener) document.getElementById('portal-content')?.focus();
  }, [action, busy]);

  useEffect(() => {
    function clear() {
      generation.current++;
      request.current?.abort();
      actionOpener.current = null;
      resume.current = null;
      setUser(null);
      setAction(null);
      setStatus('');
      setError('');
    }
    window.addEventListener(sensitiveClearEvent, clear);
    window.addEventListener(sensitiveSuspendEvent, clear);
    return () => {
      request.current?.abort();
      window.removeEventListener(sensitiveClearEvent, clear);
      window.removeEventListener(sensitiveSuspendEvent, clear);
    };
  }, []);

  useEffect(() => {
    if (!access?.users_read || !id || (interruptedOnMount.current && attempt === 0)) return;
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setUser(null);
    setError('');
    setBusy(true);
    setStatus({
      key: confirmed.current ? 'admin.detail.confirmedLoading' : 'admin.detail.loading',
    });
    new AdminClient(client)
      .user(id, controller.signal)
      .then((value) => {
        throwIfAborted(controller.signal);
        if (current !== generation.current) return;
        setUser(value);
        setStatus({
          key: confirmed.current ? 'admin.detail.confirmedLoaded' : 'admin.detail.loaded',
        });
        const desired = resume.current;
        resume.current = null;
        if (desired && access.users_status_write) {
          if (canModerate(value, profile.id) && value.status !== desired)
            setAction({ target: value, desired, resume: true });
          else setError({ key: 'admin.detail.pendingUnavailable' });
        }
      })
      .catch((failure) => {
        if (controller.signal.aborted || current !== generation.current || isAborted(failure))
          return;
        setUser(null);
        setStatus(confirmed.current ? { key: 'admin.detail.confirmedRefreshFailed' } : '');
        setError(errorMessage(failure));
        if (failure instanceof PortalError && failure.status === 403) reportPermissionLoss();
      })
      .finally(() => {
        if (!controller.signal.aborted && current === generation.current) setBusy(false);
      });
    return () => controller.abort();
  }, [
    client,
    id,
    access?.users_read,
    access?.users_status_write,
    profile.id,
    attempt,
    reportPermissionLoss,
  ]);

  async function select(desired: ModerationStatus, opener: HTMLButtonElement) {
    if (
      !user ||
      !access?.users_status_write ||
      !canModerate(user, profile.id) ||
      user.status === desired ||
      selecting.current ||
      action
    )
      return;
    selecting.current = true;
    // Disabling the trigger during the fresh read blurs it in Chromium. Keep
    // the explicit opener so closing the eventual modal restores focus to it.
    actionOpener.current = opener;
    request.current?.abort();
    const controller = new AbortController();
    const current = ++generation.current;
    request.current = controller;
    setBusy(true);
    setError('');
    setStatus({ key: 'admin.detail.checking' });
    try {
      const value = await new AdminClient(client).user(user.id, controller.signal);
      throwIfAborted(controller.signal);
      if (current !== generation.current) return;
      setUser(value);
      setStatus('');
      if (
        value.lifecycle_revision !== user.lifecycle_revision ||
        value.status !== user.status ||
        !canModerate(value, profile.id)
      ) {
        setError({ key: 'admin.detail.changed' });
        return;
      }
      confirmed.current = false;
      setAction({ target: value, desired, resume: false });
    } catch (failure) {
      if (!controller.signal.aborted && current === generation.current && !isAborted(failure)) {
        setUser(null);
        setStatus('');
        setError(errorMessage(failure));
        if (failure instanceof PortalError && failure.status === 403) reportPermissionLoss();
      }
    } finally {
      selecting.current = false;
      if (!controller.signal.aborted && current === generation.current) setBusy(false);
    }
  }

  function outcome(result: ModerationOutcome) {
    setAction(null);
    setError('');
    setStatus('');
    if (result.kind === 'confirmed') {
      confirmed.current = true;
      setUser(null);
      setAttempt((value) => value + 1);
    } else if (result.kind === 'conflict' || result.kind === 'unconfirmed') {
      generation.current++;
      request.current?.abort();
      setUser(null);
      if (result.kind === 'conflict') setError({ key: 'admin.detail.conflict' });
    } else if (result.kind === 'expired') {
      setError({ key: 'admin.detail.expired' });
    } else if (result.kind === 'failed') {
      setError(
        result.error instanceof PortalError && result.error.status === 403
          ? { key: 'admin.detail.denied' }
          : errorMessage(result.error)
      );
    }
  }

  return (
    <>
      <PageHeading title={t('detail.title')}>{t('detail.description')}</PageHeading>
      <Link
        href="/admin/users"
        prefetch={false}
        onClick={clearSensitiveViews}
        className={linkClass}
      >
        {t('detail.back')}
      </Link>
      {!access?.users_read ? (
        <p role="status">{t('detail.unavailable')}</p>
      ) : !id ? (
        <p role="alert">{t('detail.invalidReference')}</p>
      ) : (
        <>
          <Feedback error={error} status={status} />
          {user && (
            <section
              aria-labelledby="account-reference"
              className="min-w-0 space-y-5 rounded-xl border bg-card p-5"
            >
              <h2 id="account-reference" className="break-all font-mono text-sm font-semibold">
                <bdi dir="ltr">{user.id}</bdi>
              </h2>
              <dl className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3 text-sm sm:grid-cols-[10rem_minmax(0,1fr)]">
                <dt className="text-muted-foreground">{t('detail.status')}</dt>
                <dd className="font-medium">{t(`statuses.${user.status}`)}</dd>
                <dt className="text-muted-foreground">{t('detail.revision')}</dt>
                <dd className="break-all font-mono">
                  <bdi dir="ltr">{user.lifecycle_revision}</bdi>
                </dd>
                {access.users_pii && user.email !== undefined && (
                  <>
                    <dt className="text-muted-foreground">{t('detail.email')}</dt>
                    <dd className="break-all">
                      <bdi dir="ltr">{user.email}</bdi>
                    </dd>
                  </>
                )}
                <dt className="text-muted-foreground">{t('detail.mfa')}</dt>
                <dd>{t(user.is_mfa_enabled ? 'detail.yes' : 'detail.no')}</dd>
                {(
                  [
                    ['created', user.created_at],
                    ['updated', user.updated_at],
                    ['deleted', user.deleted_at],
                  ] as const
                ).map(([label, value]) => (
                  <div key={label} className="contents">
                    <dt className="text-muted-foreground">{t(`detail.${label}`)}</dt>
                    <dd className="break-words">
                      <QueryUtcTime value={value} />
                    </dd>
                  </div>
                ))}
              </dl>
              {access.users_status_write && (
                <div className="space-y-3 border-t pt-4">
                  <h3 className="font-semibold">{t('detail.actions')}</h3>
                  {!canModerate(user, profile.id) && (
                    <p className="text-sm text-muted-foreground">{t('detail.ineligible')}</p>
                  )}
                  <div className="flex flex-wrap gap-2">
                    {(['suspended', 'banned', 'active'] as const)
                      .filter((desired) => desired !== user.status)
                      .map((desired) => (
                        <Button
                          key={desired}
                          type="button"
                          variant="outline"
                          className={controlClass}
                          disabled={busy || Boolean(action) || !canModerate(user, profile.id)}
                          onClick={(event) => void select(desired, event.currentTarget)}
                        >
                          {t(`moderation.actions.${desired}`)}
                        </Button>
                      ))}
                  </div>
                  <p className="text-sm text-muted-foreground">{t('detail.requirements')}</p>
                </div>
              )}
            </section>
          )}
          <Button
            type="button"
            variant="outline"
            className={controlClass}
            disabled={busy || Boolean(action)}
            onClick={() => {
              request.current?.abort();
              setAttempt((value) => value + 1);
            }}
          >
            {t('detail.read')}
          </Button>
          {action && (
            <ModerationDialog
              target={action.target}
              desiredStatus={action.desired}
              resumeTotp={action.resume}
              onOutcome={outcome}
            />
          )}
        </>
      )}
    </>
  );
}
