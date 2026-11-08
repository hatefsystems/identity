'use client';

import type { Message } from '../../i18n/messages';
import { useMessage } from '../../i18n/use-message';

import { useTranslations } from 'next-intl';
import { PreferenceControls } from '../../i18n/preferences';
import { useDisplayPreferences } from '../../i18n/provider';
import type { Locale } from '../../i18n/config';

import { Button, cn } from '@hatef/ui';
import { ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { PortalClient } from '../_lib/portal/client';
import { AdminClient } from '../_lib/admin/client';
import type { AdminCapabilities } from '../_lib/admin/contracts';
import type { Profile, StepUpGrant } from '../_lib/portal/contracts';
import type { LegalOperation, StepUpIntent } from '../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../_lib/portal/errors';
import { safeReturnPath } from '../_lib/portal/validation';
import {
  clearSensitiveViews,
  invalidateOtherTabs,
  onOtherTabInvalidation,
  sensitiveClearEvent,
  suspendSensitiveViews,
} from '../_lib/portal/invalidation';
import { controlClass, Feedback, linkClass } from './controls';

type PortalState = {
  client: PortalClient;
  profile: Profile;
  capabilities?: AdminCapabilities;
  route: string;
  resumedAction?: StepUpIntent;
  revalidated?: boolean;
};
type PortalContextValue = Omit<PortalState, 'route'> & {
  moderationInterrupted?: boolean;
  updateProfile: (profile: Profile) => void;
  signOut: (currentID?: string) => Promise<void>;
  deleteAccount: (grant: StepUpGrant, signal: AbortSignal, locale?: Locale) => Promise<void>;
  rememberStepUp: (intent: StepUpIntent) => void;
  reportPermissionLoss: () => void;
  reportModerationInterruption: () => void;
  reportLegalInterruption: (operation: LegalOperation) => void;
};
type DeletionOutcome = 'confirmed' | 'unconfirmed';
const PortalContext = createContext<PortalContextValue | null>(null);

export function usePortal(): PortalContextValue {
  const value = useContext(PortalContext);
  if (!value) throw new Error('Portal content requires an authenticated bootstrap.');
  return value;
}

export function PortalProvider({
  children,
  surface = 'account',
}: {
  children: ReactNode;
  surface?: 'account' | 'admin';
}) {
  const t = useTranslations();
  const message = useMessage();
  const preferences = useDisplayPreferences();
  const [state, setState] = useState<PortalState | null>(null);
  const [phase, setPhase] = useState<
    'checking' | 'ready' | 'failed' | 'signing-out' | 'no-access' | 'disabled'
  >('checking');
  const [error, setError] = useState<Message>('');
  const [attempt, setAttempt] = useState(0);
  const [deletionOutcome, setDeletionOutcome] = useState<DeletionOutcome | null>(null);
  const [moderationInterrupted, setModerationInterrupted] = useState(false);
  const [legalInterrupted, setLegalInterrupted] = useState<LegalOperation | null>(null);
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
  const admin = surface === 'admin';
  const sessionRoute = admin ? pathname : 'account';
  const ready = phase === 'ready' && state?.route === sessionRoute;

  const clear = useCallback(() => {
    suspended.current = null;
    wasHidden.current = false;
    active.current?.dispose();
    active.current = null;
    clearSensitiveViews();
    if (alive.current) setState(null);
  }, []);

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
    // A waiting TOTP marker is only meaningful on the route where it started.
    // No target identifier or account snapshot is retained in the marker.
    suspended.current = null;
    if (admin) {
      active.current?.dispose();
      active.current = null;
      setState(null);
      if (!requireReconciliation.current) setPhase('checking');
    }
    clearSensitiveViews();
  }, [pathname, admin]);

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
      active.current = null;
      client.dispose();
      clearSensitiveViews();
      setState(null);
      const denied = admin && failure.status === 403;
      const disabled = admin && failure.status === 404;
      setPhase(denied ? 'no-access' : disabled ? 'disabled' : 'failed');
      setError(
        denied
          ? { key: 'portal.shell.noAccess' }
          : disabled
            ? { key: 'portal.shell.disabled' }
            : errorMessage(failure)
      );
      // Do not echo received broadcasts; only detected authority changes notify.
      if (hadSession && (failure.code === 'session_changed' || failure.code === 'session_required'))
        invalidateOtherTabs();
    }
    client.onSessionLoss = lost;
    client
      .bootstrap()
      .then(async (profile) => {
        if (active.current !== client) return;
        const capabilities = admin ? await new AdminClient(client).capabilities() : undefined;
        if (active.current !== client) return;
        const prior = suspended.current;
        const resumedAction =
          prior?.sessionID === profile.session.id ? (prior.action ?? undefined) : undefined;
        suspended.current = null;
        setState({
          client,
          profile,
          capabilities,
          route: sessionRoute,
          resumedAction,
          revalidated: Boolean(prior),
        });
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
  }, [attempt, admin, sessionRoute]);

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
      active.current?.dispose();
      active.current = null;
      clearSensitiveViews();
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
    function cleared() {
      discardIntent();
      // A link may clear children without changing pathname (for example a
      // modifier click). Internal invalidation detaches the client first, so
      // only an external clear starts this single revalidation, never a loop.
      if (
        !admin ||
        !active.current ||
        terminal.current ||
        signingOut.current ||
        requireReconciliation.current
      )
        return;
      active.current.dispose();
      active.current = null;
      setState(null);
      setPhase('checking');
      wasHidden.current = document.visibilityState === 'hidden';
      if (!wasHidden.current) setAttempt((value) => value + 1);
    }
    function navigation() {
      if (admin) changedSession();
      else discardIntent();
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
    window.addEventListener(sensitiveClearEvent, cleared);
    window.addEventListener('popstate', navigation);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('pageshow', pageshow);
    return () => {
      unsubscribe();
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener(sensitiveClearEvent, cleared);
      window.removeEventListener('popstate', navigation);
      window.removeEventListener('pagehide', pagehide);
      window.removeEventListener('pageshow', pageshow);
    };
  }, [admin]);

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
      setError(errorMessage(failure));
      invalidateOtherTabs();
    } finally {
      signingOut.current = false;
    }
  }

  async function deleteAccount(
    grant: StepUpGrant,
    signal: AbortSignal,
    locale: Locale = preferences.locale
  ) {
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
      await client.deleteAccount(
        grant,
        signal,
        () => {
          throwIfAborted(signal);
          operation.sent = true;
        },
        locale
      );
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
    setState({ ...state, client, profile });
  }

  function rememberStepUp(intent: StepUpIntent) {
    const pending = suspended.current;
    if (!pending || pending.sessionID !== active.current?.profile?.session.id) return;
    if (intent.kind === 'recovery') pending.action = { kind: 'recovery' };
    else if (intent.kind === 'moderation') {
      if (admin) pending.action = { kind: 'moderation', status: intent.status };
    } else if (intent.kind === 'legal') {
      if (admin && pathname === '/admin/legal')
        pending.action = { kind: 'legal', operation: intent.operation };
    } else {
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

  const reportPermissionLoss = useCallback(() => {
    if (!admin) return;
    clear();
    setPhase('no-access');
    setError({ key: 'portal.shell.permissionLost' });
  }, [admin, clear]);

  const reportModerationInterruption = useCallback(() => {
    if (alive.current) setModerationInterrupted(true);
  }, []);

  const reportLegalInterruption = useCallback((operation: LegalOperation) => {
    if (alive.current) setLegalInterrupted(operation);
  }, []);

  const permissions = ready ? state?.capabilities?.capabilities : undefined;
  const navigation = admin
    ? [
        ['/admin', t('portal.navigation.workspaces')],
        ...(permissions?.users_read ? [['/admin/users', t('portal.navigation.accounts')]] : []),
        ...(permissions?.audit_logs_read
          ? [['/admin/audit-logs', t('portal.navigation.audit')]]
          : []),
        ...(permissions?.audit_chain_verify || permissions?.ledger_verify
          ? [['/admin/integrity', t('portal.navigation.integrity')]]
          : []),
        ...(permissions?.legal_holds_read ||
        permissions?.legal_holds_apply ||
        permissions?.legal_holds_release ||
        permissions?.preservation_requests_create ||
        permissions?.legal_inquiry_lookup
          ? [['/admin/legal', t('portal.navigation.legal')]]
          : []),
      ]
    : [
        ['/dashboard', t('portal.navigation.overview')],
        ['/dashboard/profile', t('portal.profile.title')],
        ['/dashboard/security', t('security.title')],
        ['/dashboard/sessions', t('portal.sessions.title')],
        ['/dashboard/privacy', t('privacy.title')],
      ];
  return (
    <div className="min-h-svh bg-muted/20">
      <a
        href="#portal-content"
        className="sr-only focus:not-sr-only focus:absolute focus:start-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-background focus:p-3 focus:ring-2 focus:ring-ring"
      >
        {admin ? t('portal.shell.skipAdmin') : t('portal.shell.skipAccount')}
      </a>
      <header className={cn('border-b bg-background', admin && 'border-t-4 border-t-primary')}>
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
          <Link
            href="/"
            prefetch={false}
            onClick={clearSensitiveViews}
            className="flex min-h-11 items-center gap-3 rounded-md px-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={t('portal.shell.home')}
          >
            <span className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldCheck aria-hidden="true" className="size-5" />
            </span>
            <span className="font-semibold tracking-tight">{t('auth.brand')}</span>
          </Link>
          <PreferenceControls />
          {admin && (
            <span className="rounded-md border px-3 py-2 text-xs font-semibold uppercase tracking-wider">
              {t('portal.shell.elevated')}
            </span>
          )}
          {ready && !deletionOutcome && (
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={() => signOut()}
            >
              {t('portal.shell.signOut')}
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
        <nav
          aria-label={
            admin ? t('portal.shell.adminNavigation') : t('portal.shell.accountNavigation')
          }
          className="min-w-0"
          hidden={Boolean(deletionOutcome)}
        >
          <p className="mb-3 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            {admin ? t('portal.shell.adminTitle') : t('portal.shell.accountTitle')}
          </p>
          <ul className="grid grid-cols-2 gap-1 sm:grid-cols-5 lg:grid-cols-1">
            {navigation.map(([href, label]) => (
              <li key={href}>
                <Link
                  href={href}
                  prefetch={false}
                  onClick={() => {
                    if (pathname !== href) clearSensitiveViews();
                  }}
                  aria-current={
                    pathname === href ||
                    (href === '/admin/users' && pathname.startsWith(`${href}/`))
                      ? 'page'
                      : undefined
                  }
                  className={cn(
                    'flex min-h-11 items-center rounded-md px-3 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
                    pathname === href ||
                      (href === '/admin/users' && pathname.startsWith(`${href}/`))
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  )}
                >
                  {label}
                </Link>
              </li>
            ))}
          </ul>
          <Link
            href={admin ? '/dashboard' : '/admin'}
            prefetch={false}
            onClick={clearSensitiveViews}
            className={`${linkClass} mt-4`}
          >
            {admin ? t('portal.shell.returnAccount') : t('portal.shell.admin')}
          </Link>
        </nav>
        <main id="portal-content" tabIndex={-1} className="min-w-0 space-y-6 focus:outline-none">
          {admin && moderationInterrupted && (
            <Feedback status={t('portal.shell.moderationInterrupted')} />
          )}
          {admin && legalInterrupted && (
            <div data-testid="legal-interruption">
              <Feedback
                status={
                  legalInterrupted === 'lookup'
                    ? t('portal.shell.lookupInterrupted')
                    : legalInterrupted === 'release'
                      ? t('portal.shell.releaseInterrupted')
                      : t('portal.shell.creationInterrupted')
                }
              />
            </div>
          )}
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
                  ? t('privacy.confirmedTitle')
                  : t('privacy.unconfirmedTitle')}
              </h1>
              <Feedback
                status={
                  deletionOutcome === 'confirmed'
                    ? t('privacy.confirmed')
                    : t('privacy.unconfirmed')
                }
              />
              {deletionOutcome === 'confirmed' ? (
                <p className="text-sm leading-relaxed">{t('privacy.confirmedMail')}</p>
              ) : (
                <p className="text-sm leading-relaxed">{t('privacy.unconfirmedMail')}</p>
              )}
              <p className="text-sm leading-relaxed text-muted-foreground">
                {t('privacy.recoveryPolicy')}
              </p>
              <Link href="/" className={linkClass}>
                {t('privacy.home')}
              </Link>
            </section>
          ) : ready && state ? (
            <PortalContext
              value={{
                ...state,
                updateProfile,
                signOut,
                deleteAccount,
                rememberStepUp,
                reportPermissionLoss,
                reportModerationInterruption,
                reportLegalInterruption,
                moderationInterrupted,
              }}
            >
              <div
                data-testid={admin ? 'admin-ready' : 'portal-ready'}
                className="min-w-0 space-y-6"
              >
                {state.revalidated && (
                  <p role="status" className="text-sm text-muted-foreground">
                    {admin && pathname === '/admin/legal'
                      ? t('portal.shell.legalRevalidated')
                      : t('portal.shell.revalidated')}
                  </p>
                )}
                {children}
              </div>
            </PortalContext>
          ) : (
            <section className="space-y-5 rounded-xl border bg-card p-6 sm:p-8">
              <h1 className="text-2xl font-semibold tracking-tight">
                {admin ? t('portal.shell.adminTitle') : t('portal.shell.accountTitle')}
              </h1>
              <Feedback
                status={
                  phase === 'checking' || (phase === 'ready' && !ready)
                    ? admin
                      ? t('portal.shell.checkingAdmin')
                      : t('portal.shell.checking')
                    : phase === 'signing-out'
                      ? t('portal.shell.signingOut')
                      : ''
                }
                error={
                  requireReconciliation.current && error
                    ? `${t('portal.shell.signOutUnconfirmed')} ${message(error)}`
                    : error
                }
              />
              {(phase === 'failed' || phase === 'no-access' || phase === 'disabled') && (
                <div className="flex flex-wrap gap-3">
                  <Button type="button" className={controlClass} onClick={checkSession}>
                    {admin ? t('portal.shell.checkAccess') : t('portal.shell.checkSession')}
                  </Button>
                  <Link
                    href={`/login?returnTo=${encodeURIComponent(safeReturnPath(pathname))}`}
                    prefetch={false}
                    className={linkClass}
                  >
                    {t('portal.shell.signIn')}
                  </Link>
                </div>
              )}
              <noscript>
                <p className="text-sm">{t('portal.shell.noScript')}</p>
              </noscript>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
