'use client';

import type { Message } from '../../../i18n/messages';

import { useFormatter, useTranslations } from 'next-intl';

import { Button } from '@hatef/ui';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { errorMessage, isAborted, throwIfAborted } from '../../_lib/portal/errors';
import { controlClass, DateLabel, Feedback, linkClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';

export function Overview() {
  const t = useTranslations();
  const format = useFormatter();
  const { client, profile } = usePortal();
  const [summary, setSummary] = useState<{
    keys: number;
    sessions: number;
    remaining: number;
    low: boolean;
  } | null>(null);
  const [username, setUsername] = useState<{ display: string } | null>();
  const [error, setError] = useState<Message>('');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setError('');
    setSummary(null);
    setUsername(undefined);
    Promise.all([
      client.keys(controller.signal),
      client.sessions(controller.signal),
      client.recoveryStatus(controller.signal),
    ])
      .then(([keys, sessions, recovery]) => {
        throwIfAborted(controller.signal);
        setSummary({
          keys: keys.length,
          sessions: sessions.length,
          remaining: recovery.remaining,
          low: recovery.low,
        });
      })
      .catch((failure) => {
        if (!controller.signal.aborted && !isAborted(failure)) setError(errorMessage(failure));
      });
    client.username(controller.signal)
      .then((result) => {
        throwIfAborted(controller.signal);
        setUsername(result);
      })
      .catch((failure) => {
        if (!controller.signal.aborted && !isAborted(failure)) setError(errorMessage(failure));
      });
    return () => controller.abort();
  }, [client, attempt]);
  return (
    <>
      <PageHeading title={t('portal.overview.title')}>
        {t('portal.overview.description')}
      </PageHeading>
      <Panel title={profile.display_name || t('portal.overview.profile')} id="overview-profile">
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">{t('portal.overview.email')}</dt>
            <dd dir="ltr" className="mt-1 break-all font-medium isolate">
              {profile.email}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t('portal.overview.status')}</dt>
            <dd className="mt-1 font-medium">
              {(['active', 'disabled', 'suspended', 'pending_deletion'] as const)
                .map((value) => (value === profile.status ? t(`portal.status.${value}`) : ''))
                .join('') || profile.status}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t('portal.overview.username')}</dt>
            <dd className="mt-1 break-words font-medium" data-username-private>
              {username === undefined
                ? t('portal.overview.usernameUnknown')
                : username
                  ? <bdi dir="auto">{username.display}</bdi>
                  : t('portal.overview.usernameAbsent')}
            </dd>
          </div>
        </dl>
        <Link href="/dashboard/profile" className={linkClass}>
          {t('portal.overview.edit')}
        </Link>
      </Panel>
      <Feedback error={error} status={!summary && !error ? t('portal.overview.loading') : ''} />
      {error && (
        <Button
          type="button"
          className={controlClass}
          variant="outline"
          onClick={() => setAttempt((value) => value + 1)}
        >
          {t('portal.overview.refresh')}
        </Button>
      )}
      {summary && (
        <div className="grid gap-5 sm:grid-cols-3">
          <Panel title={t('portal.overview.passkeys')} id="overview-passkeys">
            <p className="text-3xl font-semibold tabular-nums">{format.number(summary.keys)}</p>
            <p className="text-sm text-muted-foreground">
              {t('portal.overview.passkeysDescription')}
            </p>
            <Link href="/dashboard/security" className={linkClass}>
              {t('portal.overview.managePasskeys')}
            </Link>
          </Panel>
          <Panel title={t('portal.overview.sessions')} id="overview-sessions">
            <p className="text-3xl font-semibold tabular-nums">{format.number(summary.sessions)}</p>
            <p className="text-sm text-muted-foreground">
              {t('portal.overview.sessionsDescription')}
            </p>
            <Link href="/dashboard/sessions" className={linkClass}>
              {t('portal.overview.manageSessions')}
            </Link>
          </Panel>
          <Panel title={t('portal.overview.recovery')} id="overview-recovery">
            <p className="text-3xl font-semibold tabular-nums">
              {format.number(summary.remaining)}
            </p>
            <p className="text-sm text-muted-foreground">
              {summary.low ? t('portal.overview.low') : t('portal.overview.remaining')}
            </p>
            <Link href="/dashboard/security" className={linkClass}>
              {t('portal.overview.manageRecovery')}
            </Link>
          </Panel>
        </div>
      )}
      <p className="text-sm leading-relaxed text-muted-foreground">
        {t.rich('portal.overview.expiry', {
          date: () => <DateLabel value={profile.session.expires_at} />,
        })}
      </p>
    </>
  );
}
