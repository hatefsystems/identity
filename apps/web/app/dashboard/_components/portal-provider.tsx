'use client';

import { Button, cn } from '@hatef/ui';
import { ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { PortalClient } from '../../_lib/portal/client';
import type { Profile } from '../../_lib/portal/contracts';
import type { StepUpIntent } from '../../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError } from '../../_lib/portal/errors';
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
  rememberStepUp: (intent: StepUpIntent) => void;
};
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
    setState(null);
  }

  function checkSession() {
    requireReconciliation.current = false;
    clear();
    setError('');
    setPhase('checking');
    if (document.visibilityState !== 'hidden') setAttempt((value) => value + 1);
  }

  useEffect(() => {
    if (document.visibilityState === 'hidden') return;
    const client = new PortalClient();
    active.current = client;
    let expiry: ReturnType<typeof setTimeout> | undefined;
    function lost(failure: PortalError) {
      if (active.current !== client) return;
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
    if (!client || signingOut.current) return;
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
          {phase === 'ready' && (
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
      <div className="mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[12rem_minmax(0,1fr)] lg:gap-10 lg:py-10">
        <nav aria-label="Account navigation" className="min-w-0">
          <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Your account
          </p>
          <ul className="grid grid-cols-2 gap-1 sm:grid-cols-4 lg:grid-cols-1">
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
          {phase === 'ready' && state ? (
            <PortalContext value={{ ...state, updateProfile, signOut, rememberStepUp }}>
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
