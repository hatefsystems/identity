'use client';

import { Button } from '@hatef/ui';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { errorMessage, isAborted, throwIfAborted } from '../../_lib/portal/errors';
import { controlClass, DateLabel, Feedback, linkClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';

export function Overview() {
  const { client, profile } = usePortal();
  const [summary, setSummary] = useState<{
    keys: number;
    sessions: number;
    remaining: number;
    low: boolean;
  } | null>(null);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setError('');
    setSummary(null);
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
    return () => controller.abort();
  }, [client, attempt]);
  return (
    <>
      <PageHeading title="Account overview">
        Manage your shared identity, sign-in methods, and active browser sessions.
      </PageHeading>
      <Panel title={profile.display_name || 'Your profile'} id="overview-profile">
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">Primary email</dt>
            <dd className="mt-1 break-all font-medium">{profile.email}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Account status</dt>
            <dd className="mt-1 font-medium">{profile.status}</dd>
          </div>
        </dl>
        <Link href="/dashboard/profile" className={linkClass}>
          Edit display name
        </Link>
      </Panel>
      <Feedback
        error={error}
        status={!summary && !error ? 'Loading current account summaries...' : ''}
      />
      {error && (
        <Button
          type="button"
          className={controlClass}
          variant="outline"
          onClick={() => setAttempt((value) => value + 1)}
        >
          Refresh overview
        </Button>
      )}
      {summary && (
        <div className="grid gap-5 sm:grid-cols-3">
          <Panel title="Passkeys" id="overview-passkeys">
            <p className="text-3xl font-semibold tabular-nums">{summary.keys}</p>
            <p className="text-sm text-muted-foreground">Registered sign-in credentials.</p>
            <Link href="/dashboard/security" className={linkClass}>
              Manage passkeys
            </Link>
          </Panel>
          <Panel title="Sessions" id="overview-sessions">
            <p className="text-3xl font-semibold tabular-nums">{summary.sessions}</p>
            <p className="text-sm text-muted-foreground">Active server-side browser sessions.</p>
            <Link href="/dashboard/sessions" className={linkClass}>
              Review sessions
            </Link>
          </Panel>
          <Panel title="Recovery codes" id="overview-recovery">
            <p className="text-3xl font-semibold tabular-nums">{summary.remaining}</p>
            <p className="text-sm text-muted-foreground">
              {summary.low
                ? 'Running low on unused recovery codes.'
                : 'Unused recovery codes remaining.'}
            </p>
            <Link href="/dashboard/security" className={linkClass}>
              Manage recovery codes
            </Link>
          </Panel>
        </div>
      )}
      <p className="text-sm leading-relaxed text-muted-foreground">
        This browser uses a cryptographically bound session, with an absolute expiry of{' '}
        <DateLabel value={profile.session.expires_at} />. Inactivity or revocation can end it
        earlier.
      </p>
    </>
  );
}
