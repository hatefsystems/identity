'use client';

import { Button, cn } from '@hatef/ui';
import { ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { PortalClient } from '../../_lib/portal/client';
import type { Profile, StepUpGrant } from '../../_lib/portal/contracts';
import type { StepUpIntent } from '../../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import {
  clearSensitiveViews,
  invalidateOtherTabs,
  onOtherTabInvalidation,
  sensitiveClearEvent,
  suspendSensitiveViews,
} from '../../_lib/portal/invalidation';
import { controlClass, Feedback, linkClass } from './controls';

type PortalState = {
  client: PortalClient;
  profile: Profile;
  resumedAction?: StepUpIntent;
  revalidated?: boolean;
};
type PortalContextValue = PortalState & {
  updateProfile: (profile: Profile) => void;
  signOut: (currentID?: string) => Promise<void>;
  deleteAccount: (grant: StepUpGrant, signal: AbortSignal) => Promise<void>;
  rememberStepUp: (intent: StepUpIntent) => void;
};
type DeletionOutcome = 'confirmed' | 'unconfirmed';
const PortalContext = createContext<PortalContextValue | null>(null);

export function usePortal(): PortalContextValue {
  const value = useContext(PortalContext);
  if (!value) throw new Error('Portal content requires an authenticated bootstrap.');
  return value;
}

export function PortalProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<PortalState | null>(null);
  const [phase, setPhase] = useState<'checking' | 'ready' | 'failed' | 'signing-out'>('checking');
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [deletionOutcome, setDeletionOutcome] = useState<DeletionOutcome | null>(null);
  const terminal = useRef<DeletionOutcome | null>(null);
  const deleting = useRef<{ sent: boolean; interrupt: () => void } | null>(null);
  const alive = useRef(false);
  const outcomeHeading = useRef<HTMLHeadingElement>(null);
  const active = useRef<PortalClient | null>(null);
  const signingOut = useRef(false);
  const requireReconciliation = useRef(false);
  const wasHidden = useRef(false);
  const suspended = useRef<{ sessionID: string; action: StepUpIntent | null } | null>(null);
  const pathname = usePathname();
  const router = useRouter();

  function clear() {
    suspended.current = null;
    wasHidden.current = false;
    clearSensitiveViews();
    active.current?.dispose();
    active.current = null;
    if (alive.current) setState(null);
  }

  function checkSession() {
    if (terminal.current) return;
    requireReconciliation.current = false;
    clear();
    setError('');
    setPhase('checking');
    if (document.visibilityState !== 'hidden') setAttempt((value) => value + 1);
  }

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      deleting.current?.interrupt();
    };
  }, []);

  useEffect(() => {
    if (deletionOutcome) outcomeHeading.current?.focus();
  }, [deletionOutcome]);

  useEffect(() => {
    if (document.visibilityState === 'hidden' || requireReconciliation.current) return;
    const client = new PortalClient();
    active.current = client;
    let expiry: ReturnType<typeof setTimeout> | undefined;
    function lost(failure: PortalError) {
      if (active.current !== client) return;
      if (deleting.current?.sent) {
        deleting.current.interrupt();
        return;
      }
      const hadSession = Boolean(client.profile);
      suspended.current = null;
      clearSensitiveViews();
      active.current = null;
      client.dispose();
      setState(null);
      setPhase('failed');
      setError(errorMessage(failure));
      // Do not echo received broadcasts; only detected authority changes notify.
      if (hadSession && (failure.code === 'session_changed' || failure.code === 'session_required'))
        invalidateOtherTabs();
    }
    client.onSessionLoss = lost;
    client
      .bootstrap()
      .then((profile) => {
        if (active.current !== client) return;
        const prior = suspended.current;
        const resumedAction =
          prior?.sessionID === profile.session.id ? (prior.action ?? undefined) : undefined;
        suspended.current = null;
        setState({ client, profile, resumedAction, revalidated: Boolean(prior) });
        setPhase('ready');
        setError('');
        // Long sessions may exceed the browser timer range. Checking on resume
        // still uses the absolute deadline; never fabricate a sliding expiry.
        const deadline = Date.parse(profile.session.expires_at);
        function checkExpiry() {
          if (Date.now() >= deadline) lost(new PortalError('session_expired', 401));
          else expiry = setTimeout(checkExpiry, Math.min(deadline - Date.now(), 2147483647));
        }
        checkExpiry();
      })
      .catch((failure) => {
        if (active.current !== client || isAborted(failure)) return;
        lost(failure instanceof PortalError ? failure : new PortalError('request_failed'));
      });
    return () => {
      if (expiry) clearTimeout(expiry);
      client.dispose();
      if (active.current === client) active.current = null;
    };
  }, [attempt]);

  useEffect(() => {
    function discardIntent() {
      suspended.current = null;
      setState((value) => (value?.resumedAction ? { ...value, resumedAction: undefined } : value));
    }
    function invalidate() {
      if (terminal.current) return;
      if (deleting.current?.sent) {
        deleting.current.interrupt();
        return;
      }
      discardIntent();
      clearSensitiveViews();
      active.current?.dispose();
      active.current = null;
      setState(null);
      if (requireReconciliation.current) return;
      setPhase('checking');
    }
    function changedSession() {
      invalidate();
      if (signingOut.current || requireReconciliation.current) return;
      wasHidden.current = document.visibilityState === 'hidden';
      if (!wasHidden.current) setAttempt((value) => value + 1);
    }
    function visibility() {
      if (requireReconciliation.current || signingOut.current) return;
      if (document.visibilityState === 'hidden') {
        if (deleting.current?.sent) {
          deleting.current.interrupt();
          return;
        }
        if (wasHidden.current) return;
        wasHidden.current = true;
        // Capture only a non-authoritative session marker before children clear
        // their secrets. A waiting TOTP dialog may add its narrow action intent.
        suspended.current = { sessionID: active.current?.profile?.session.id ?? '', action: null };
        suspendSensitiveViews();
        active.current?.dispose();
        active.current = null;
        setState(null);
        setPhase('checking');
      } else if (wasHidden.current) {
        wasHidden.current = false;
        setAttempt((value) => value + 1);
      }
    }
    function pagehide() {
      invalidate();
      wasHidden.current = true;
    }
    function pageshow(event: PageTransitionEvent) {
      if (event.persisted) changedSession();
    }
    const unsubscribe = onOtherTabInvalidation(changedSession);
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener(sensitiveClearEvent, discardIntent);
    window.addEventListener('popstate', discardIntent);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('pageshow', pageshow);
    return () => {
      unsubscribe();
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener(sensitiveClearEvent, discardIntent);
      window.removeEventListener('popstate', discardIntent);
      window.removeEventListener('pagehide', pagehide);
      window.removeEventListener('pageshow', pageshow);
    };
  }, []);

  async function signOut(currentID?: string) {
    const client = active.current;
    if (!client || signingOut.current || deleting.current || terminal.current) return;
    signingOut.current = true;
    requireReconciliation.current = true;
    suspended.current = null;
    clearSensitiveViews();
    setState(null);
    setPhase('signing-out');
    setError('');
    try {
      if (currentID) await client.revokeSession(currentID);
      else await client.logout();
      invalidateOtherTabs();
      client.dispose();
      active.current = null;
      router.replace('/login');
    } catch (failure) {
      client.dispose();
      active.current = null;
      setPhase('failed');
      setError(
        `Sign-out could not be confirmed. The server session may still be active. ${errorMessage(failure)}`
      );
      invalidateOtherTabs();
    } finally {
      signingOut.current = false;
    }
  }

  async function deleteAccount(grant: StepUpGrant, signal: AbortSignal) {
    const client = active.current;
    if (!client || signingOut.current || deleting.current || terminal.current) {
      grant.clear();
      throw new PortalError('session_changed', 409);
    }
    const operation = { sent: false, interrupt: () => settle('unconfirmed') };
    function settle(outcome: DeletionOutcome) {
      if (terminal.current || (outcome === 'unconfirmed' && !operation.sent)) return;
      terminal.current = outcome;
      requireReconciliation.current = true;
      deleting.current = null;
      grant.clear();
      clear();
      if (alive.current) {
        setError('');
        setDeletionOutcome(outcome);
      }
      // This outcome has no account identifiers or authority. Keep it outside
      // authenticated children, and never issue logout or delete the shared key.
      invalidateOtherTabs();
    }
    try {
      throwIfAborted(signal);
      if (!client.assertSession().deletion_enabled) throw new PortalError('deletion_disabled');
      deleting.current = operation;
      signal.addEventListener('abort', operation.interrupt, { once: true });
      await client.deleteAccount(grant, signal, () => {
        throwIfAborted(signal);
        operation.sent = true;
      });
      if (signal.aborted || active.current !== client) settle('unconfirmed');
      else settle('confirmed');
    } catch (failure) {
      if (terminal.current) return;
      if (
        operation.sent &&
        (signal.aborted ||
          isAborted(failure) ||
          !(failure instanceof PortalError) ||
          failure.uncertain ||
          failure.status >= 500)
      ) {
        settle('unconfirmed');
        return;
      }
      throw failure;
    } finally {
      grant.clear();
      signal.removeEventListener('abort', operation.interrupt);
      if (deleting.current === operation) deleting.current = null;
    }
  }

  function updateProfile(profile: Profile) {
    const client = active.current;
    if (
      !client ||
      !state ||
      profile.session.id !== state.profile.session.id ||
      profile.id !== state.profile.id
    )
      return;
    setState({ client, profile });
  }

  function rememberStepUp(intent: StepUpIntent) {
    const pending = suspended.current;
    if (!pending || pending.sessionID !== active.current?.profile?.session.id) return;
    if (intent.kind === 'recovery') pending.action = { kind: 'recovery' };
    else {
      const target = intent.action;
      pending.action = {
        kind: 'passkey',
        action:
          target.kind === 'add'
            ? { kind: 'add', name: target.name }
            : {
                kind: target.kind,
                id: target.id,
                name: target.kind === 'rename' ? target.name : '',
              },
      };
    }
  }

  const navigation = [
    ['/dashboard', 'Overview'],
    ['/dashboard/profile', 'Profile'],
    ['/dashboard/security', 'Security'],
    ['/dashboard/sessions', 'Sessions'],
    ['/dashboard/privacy', 'Privacy'],
  ];
  return (
    <div className="min-h-svh bg-muted/20">
      <a
        href="#portal-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-background focus:p-3 focus:ring-2 focus:ring-ring"
      >
        Skip to account content
      </a>
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <Link
            href="/"
            onClick={clearSensitiveViews}
            className="flex min-h-11 items-center gap-3 rounded-md px-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Hatef Identity home"
          >
            <span className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldCheck aria-hidden="true" className="size-5" />
            </span>
            <span className="font-semibold tracking-tight">
              Hatef <span className="font-normal text-muted-foreground">Identity</span>
            </span>
          </Link>
          {phase === 'ready' && !deletionOutcome && (
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => signOut()}
            >
              Sign out
            </Button>
          )}
        </div>
      </header>
      <div
        className={cn(
          'mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:gap-10 lg:py-10',
          !deletionOutcome && 'lg:grid-cols-[12rem_minmax(0,1fr)]'
        )}
      >
        <nav aria-label="Account navigation" className="min-w-0" hidden={Boolean(deletionOutcome)}>
          <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Your account
          </p>
          <ul className="grid grid-cols-2 gap-1 sm:grid-cols-5 lg:grid-cols-1">
            {navigation.map(([href, label]) => (
              <li key={href}>
                <Link
                  href={href}
                  prefetch={false}
                  onClick={clearSensitiveViews}
                  aria-current={pathname === href ? 'page' : undefined}
                  className={cn(
                    'flex min-h-11 items-center rounded-md px-3 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
                    pathname === href
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  {label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <main id="portal-content" tabIndex={-1} className="min-w-0 space-y-6 focus:outline-none">
          {deletionOutcome ? (
            <section
              data-testid="deletion-outcome"
              data-outcome={deletionOutcome}
              className="mx-auto max-w-2xl space-y-5 rounded-xl border bg-card p-6 sm:p-8"
            >
              <h1
                ref={outcomeHeading}
                tabIndex={-1}
                className="text-2xl font-semibold tracking-tight focus:outline-none"
              >
                {deletionOutcome === 'confirmed'
                  ? 'Account deletion requested'
                  : 'Deletion outcome unconfirmed'}
              </h1>
              <Feedback
                status={
                  deletionOutcome === 'confirmed'
                    ? 'Your identity account has been deactivated and deletion is scheduled. Your identity sessions have been revoked.'
                    : 'The request was sent, but its outcome could not be confirmed. Your account may already be deactivated. The request has not been retried.'
                }
              />
              {deletionOutcome === 'confirmed' ? (
                <p className="text-sm leading-relaxed">
                  A recovery notification is queued for your primary email and any configured backup
                  email. Queued mail does not confirm inbox delivery. To cancel deletion, open the
                  recovery link in that email and complete verification within the original 30-day
                  recovery window. The email contains the exact deadline.
                </p>
              ) : (
                <p className="text-sm leading-relaxed">
                  Private data has been cleared from this view. Check your primary and configured
                  backup mailboxes for a recovery message. If it arrives, use its recovery link
                  before the deadline in the email. This page cannot confirm an account change or
                  email delivery; a missing message or a failed sign-in is not proof of the outcome.
                </p>
              )}
              <p className="text-sm leading-relaxed text-muted-foreground">
                Recovery requires the emailed link and strong verification, not a current session.
                Recovery does not restore old sessions. Data subject to lawful preservation,
                separately retained security records, backups, and downstream services may follow
                different retention schedules.
              </p>
              <Link href="/" className={linkClass}>
                Return home
              </Link>
            </section>
          ) : phase === 'ready' && state ? (
            <PortalContext
              value={{ ...state, updateProfile, signOut, deleteAccount, rememberStepUp }}
            >
              <div data-testid="portal-ready" className="space-y-6">
                {state.revalidated && (
                  <p role="status" className="text-sm text-muted-foreground">
                    Your session was checked again. If a change was interrupted, it may have
                    completed; review the saved state before trying again.
                  </p>
                )}
                {children}
              </div>
            </PortalContext>
          ) : (
            <section className="space-y-5 rounded-xl border bg-card p-6 sm:p-8">
              <h1 className="text-2xl font-semibold tracking-tight">Your account</h1>
              <Feedback
                status={
                  phase === 'checking'
                    ? 'Checking your secure browser session...'
                    : phase === 'signing-out'
                      ? 'Signing out. Private data has been cleared.'
                      : ''
                }
                error={error}
              />
              {phase === 'failed' && (
                <div className="flex flex-wrap gap-3">
                  <Button type="button" className={controlClass} onClick={checkSession}>
                    Check current session
                  </Button>
                  <Link
                    href={`/login?returnTo=${encodeURIComponent(pathname)}`}
                    className={linkClass}
                  >
                    Sign in with a passkey
                  </Link>
                </div>
              )}
              <noscript>
                <p className="text-sm">
                  JavaScript is required to verify your browser-bound session. No private account
                  data is included in this page.
                </p>
              </noscript>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
