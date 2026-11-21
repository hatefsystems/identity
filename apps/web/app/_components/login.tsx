'use client';

import { Button } from '@hatef/ui';
import { useTranslations } from 'next-intl';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { AuthField, AuthForm } from '../(auth)/_components/form-controls';
import { TotpForm } from '../(auth)/_components/forms';
import { useAuthForm, type FormOutcome } from '../(auth)/_lib/use-auth-form';
import { validateTotp, type FieldErrors } from '../(auth)/_lib/validation';
import { normalizeNumericInput } from '../_lib/numeric-input';
import { PortalClient } from '../_lib/portal/client';
import { browserKey } from '../_lib/portal/dpop';
import { PortalError, throwIfAborted } from '../_lib/portal/errors';
import { invalidateOtherTabs } from '../_lib/portal/invalidation';
import { LoginCoordinator, type LoginChannel, type LoginState } from '../_lib/portal/login-coordinator';
import { safeReturnPath } from '../_lib/portal/validation';
import type { Message } from '../../i18n/messages';
import { useMessage } from '../../i18n/use-message';

function validateUsername({ username }: { username: string }): FieldErrors<{ username: string }> {
  if (!username) return { username: { key: 'auth.login.usernameRequired' } };
  if (new TextEncoder().encode(username).length > 1024 || /[\p{Cc}\p{Cs}]/u.test(username))
    return { username: { key: 'auth.login.usernameInvalid' } };
  return {};
}

function Credentials({ submit, method }: {
  submit: (username: string, value: string) => Promise<FormOutcome>;
  method: 'password' | 'contact';
}) {
  const t = useTranslations('auth');
  const [channel, setChannel] = useState<LoginChannel>('email');
  const form = useAuthForm({ username: '', password: '' }, (values) => ({
    ...validateUsername(values),
    ...(method === 'password' && !values.password ? { password: { key: 'auth.validation.passwordRequired' as const } } : {}),
  }), (values) => submit(values.username, method === 'password' ? values.password : channel), true);
  const channelId = 'login-delivery-channel';

  return <AuthForm {...form}
    label={t(method === 'password' ? 'forms.login.label' : 'login.contactLabel')}
    submitLabel={t(method === 'password' ? 'forms.login.submit' : 'login.requestCode')}
    messages={{ pending: t('login.pending'), success: t('forms.login.success'), error: t('login.failure') }}>
    <AuthField {...form.field('username')} label={t('login.username')} hint={t('login.usernameHint')}
      autoComplete="username" autoCapitalize="none" spellCheck={false} required />
    {method === 'password' ? <AuthField {...form.field('password')} label={t('fields.password')}
      type="password" autoComplete="current-password" required /> : <div className="space-y-2">
      <label htmlFor={channelId} className="text-sm font-medium">{t('login.channel')}</label>
      <select id={channelId} name="channel" value={channel} disabled={form.status === 'pending'}
        onChange={(event) => setChannel(event.target.value as LoginChannel)}
        className="h-11 w-full rounded-md border border-slate-500 bg-background px-3 text-sm dark:border-slate-400">
        <option value="email">{t('login.email')}</option>
        <option value="sms">{t('login.sms')}</option>
      </select>
      <p className="text-sm leading-relaxed text-muted-foreground">{t('login.destinationHint')}</p>
    </div>}
  </AuthForm>;
}

function DeliveredCode({ submit, channel }: {
  submit: (code: string) => Promise<FormOutcome>;
  channel: LoginChannel;
}) {
  const t = useTranslations('auth');
  const form = useAuthForm({ code: '' }, validateTotp, ({ code }) => submit(code), true);
  const code = form.field('code');
  return <AuthForm {...form}
    onSubmit={(event) => {
      const input = event.currentTarget.elements.namedItem('code');
      if (input instanceof HTMLInputElement) input.value = normalizeNumericInput(input.value);
      void form.onSubmit(event);
    }}
    label={t('login.deliveredLabel')} submitLabel={t('login.verifyDelivered')}
    messages={{ pending: t('login.pending'), success: t('forms.login.success'), error: t('login.codeFailure') }}>
    <p className="rounded-md bg-muted/50 p-3 text-sm leading-relaxed">
      {t(channel === 'email' ? 'login.emailRequested' : 'login.smsRequested')}
    </p>
    <AuthField {...code} onChange={(event) => {
      event.target.value = normalizeNumericInput(event.target.value);
      code.onChange(event);
    }} label={t('login.deliveredCode')} hint={t('login.deliveredHint')}
      inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" spellCheck={false}
      className="text-center font-mono text-lg tracking-[0.35em] md:text-lg" required />
  </AuthForm>;
}

export function Login({ coordinator: initialCoordinator, onRestart }: {
  coordinator?: LoginCoordinator;
  onRestart?: () => void;
}) {
  const t = useTranslations('auth');
  const message = useMessage();
  const router = useRouter();
  const [hydrated, setHydrated] = useState(false);
  const [method, setMethod] = useState<'password' | 'contact'>('password');
  const [state, setState] = useState<LoginState>(() => initialCoordinator?.state ?? { stage: 'credentials' });
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<Message>('');
  const active = useRef<{ controller: AbortController; coordinator?: LoginCoordinator } | null>(
    initialCoordinator ? { controller: new AbortController(), coordinator: initialCoordinator } : null
  );
  const busy = useRef(false);
  const feedback = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setHydrated(true);
    if (initialCoordinator && !active.current)
      active.current = { controller: new AbortController(), coordinator: initialCoordinator };
    const leave = () => {
      const unconfirmed = busy.current;
      active.current?.controller.abort();
      active.current?.coordinator?.dispose();
      active.current = null;
      busy.current = false;
      setPending(false);
      setState({ stage: unconfirmed ? 'unconfirmed' : 'closed' });
      setNotice(unconfirmed ? { key: 'auth.login.unconfirmed' } : '');
    };
    window.addEventListener('pagehide', leave);
    return () => {
      window.removeEventListener('pagehide', leave);
      active.current?.controller.abort();
      // PasskeyLogin owns an injected coordinator, including Strict Mode cleanup.
      if (active.current?.coordinator !== initialCoordinator) active.current?.coordinator?.dispose();
      active.current = null;
    };
  }, [initialCoordinator]);

  const expiresAt = 'expiresAt' in state ? state.expiresAt : undefined;
  useEffect(() => {
    if (!expiresAt) return;
    const check = () => {
      const current = active.current?.coordinator?.state;
      if (current?.stage === 'expired') setState(current);
    };
    const timer = setInterval(check, 1000);
    window.addEventListener('focus', check);
    document.addEventListener('visibilitychange', check);
    return () => {
      clearInterval(timer);
      window.removeEventListener('focus', check);
      document.removeEventListener('visibilitychange', check);
    };
  }, [expiresAt]);

  useEffect(() => {
    if (notice || state.stage !== 'credentials') feedback.current?.focus();
  }, [notice, state.stage]);

  async function perform(operation: 'password' | 'request' | 'delivered' | 'mfa', value: string, username = ''): Promise<FormOutcome> {
    if (busy.current) return 'error';
    busy.current = true;
    setPending(true);
    setNotice('');
    const lifetime: { controller: AbortController; coordinator?: LoginCoordinator } =
      active.current ?? { controller: new AbortController() };
    active.current = lifetime;
    let issuedSession = false;
    try {
      if (!lifetime.coordinator) {
        await browserKey(true, lifetime.controller.signal);
        throwIfAborted(lifetime.controller.signal);
        lifetime.coordinator = new LoginCoordinator(new PortalClient());
      }
      const coordinator = lifetime.coordinator;
      try {
        if (operation === 'password') await coordinator.password(username, value);
        else if (operation === 'request') await coordinator.requestCode(username, value as LoginChannel);
        else if (operation === 'delivered') await coordinator.verifyCode(value);
        else await coordinator.verifyTotp(value);
      } finally {
        // A lost response from a session-issuing mutation may have changed the cookie.
        if (operation !== 'request') invalidateOtherTabs();
      }
      throwIfAborted(lifetime.controller.signal);
      const next = coordinator.state;
      setState(next);
      if (next.stage === 'session') {
        issuedSession = true;
        await coordinator.client.bootstrap(lifetime.controller.signal);
        throwIfAborted(lifetime.controller.signal);
        router.replace(safeReturnPath(new URLSearchParams(window.location.search).get('returnTo')));
        coordinator.dispose();
      }
      return 'success';
    } catch (failure) {
      if (active.current !== lifetime || lifetime.controller.signal.aborted) return 'error';
      if (issuedSession) lifetime.coordinator?.unconfirmed();
      const next = lifetime.coordinator?.state ?? { stage: 'credentials' as const };
      setState(next);
      if (next.stage === 'unconfirmed') setNotice({ key: 'auth.login.unconfirmed' });
      else if (failure instanceof PortalError && failure.status === 429) return 'rate-limited';
      return 'error';
    } finally {
      if (active.current === lifetime) {
        busy.current = false;
        setPending(false);
      }
    }
  }

  function restart() {
    if (busy.current) return;
    active.current?.controller.abort();
    active.current?.coordinator?.dispose();
    active.current = null;
    setNotice('');
    setState({ stage: 'credentials' });
    onRestart?.();
  }

  const terminal = ['unconfirmed', 'expired', 'closed', 'session'].includes(state.stage);
  return <div className="space-y-5">
    <noscript><p className="text-sm">{t('login.noScript')}</p></noscript>
    <div ref={feedback} tabIndex={-1} className="focus:outline-none" role="status" aria-live="polite" aria-atomic="true">
      {notice ? message(notice) : state.stage === 'expired' ? t('login.expired') :
        state.stage === 'closed' ? t('login.closed') : state.stage === 'session' ? t('login.checkingSession') :
          state.stage === 'mfa' ? t('login.mfaRequired') : null}
    </div>
    {hydrated && !terminal && <>
      {state.stage === 'credentials' && <>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="group" aria-label={t('login.methods')}>
          <Button type="button" variant="outline" disabled={pending} aria-pressed={method === 'password'}
            onClick={() => setMethod('password')}>{t('login.passwordMethod')}</Button>
          <Button type="button" variant="outline" disabled={pending} aria-pressed={method === 'contact'}
            onClick={() => setMethod('contact')}>{t('login.contactMethod')}</Button>
        </div>
        <Credentials key={method} method={method} submit={(username, value) => perform(method === 'password' ? 'password' : 'request', value, username)} />
      </>}
      {state.stage === 'delivered' && <DeliveredCode channel={state.channel} submit={(code) => perform('delivered', code)} />}
      {state.stage === 'mfa' && <TotpForm clearAfterSubmit submit={({ code }) => perform('mfa', code)} />}
    </>}
    {hydrated && state.stage !== 'credentials' && state.stage !== 'session' && <Button type="button" variant="outline"
      disabled={pending} onClick={restart} className="min-h-11 w-full">{t('login.restart')}</Button>}
  </div>;
}
