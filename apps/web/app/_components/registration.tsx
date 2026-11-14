'use client';

import { useTranslations } from 'next-intl';
import type { Message, MessageDescriptor } from '../../i18n/messages';
import { useMessage } from '../../i18n/use-message';
import { useDisplayPreferences } from '../../i18n/provider';
import { formatDisplayDate } from '../../i18n/formats';

import { Button } from '@hatef/ui';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AuthCard, AuthLink } from '../(auth)/_components/auth-card';
import { AuthField } from '../(auth)/_components/form-controls';
import {
  validateRegistration,
  validateTotp,
  type FieldErrors,
} from '../(auth)/_lib/validation';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../_lib/portal/errors';
import { onOtherTabInvalidation, sensitiveClearEvent } from '../_lib/portal/invalidation';
import {
  RegistrationClient,
  scrubRegistrationFragment,
  type EmailProof,
  type RegistrationAttempt,
  type RegistrationOutcome,
  type RegistrationValues,
} from '../_lib/portal/registration-client';
import { requireWebAuthn, usePasskey } from '../_lib/portal/webauthn';
import { normalizeNumericInput } from '../_lib/numeric-input';

const cleared: MessageDescriptor =
  { key: 'registration.cleared' };
const invalidLink: MessageDescriptor =
  { key: 'registration.invalidLink' };
const emailConfirmed: MessageDescriptor = { key: 'registration.emailConfirmed' };
const verifyingEmail: MessageDescriptor = { key: 'registration.verifyingEmail' };
function registrationError(failure: unknown): MessageDescriptor {
  if (failure instanceof PortalError) {
    if (failure.uncertain || failure.code === 'result_required')
      return { key: 'registration.completionLost' };
    switch (failure.code) {
      case 'invalid_registration':
      case 'registration_key_changed':
        return { key: 'registration.keyChanged' };
      case 'registration_expired':
        return { key: 'registration.proofExpired' };
      case 'registration_conflict':
      case 'restart_registration':
        return { key: 'registration.conflict' };
      case 'invalid_username':
        return { key: 'registration.usernameInvalid' };
      case 'username_unavailable':
        return { key: 'registration.usernameUnavailable' };
      case 'username_policy_changed':
        return { key: 'registration.usernamePolicyChanged' };
      case 'proof_required':
        return { key: 'registration.proofRequired' };
      case 'restart_phone_proof':
        return { key: 'registration.phoneProofLost' };
      case 'send_failed':
        return { key: 'registration.deliveryUnconfirmed' };
      case 'temporarily_unavailable':
        return { key: 'registration.temporarilyUnavailable' };
      case 'not_found':
        return { key: 'registration.unavailable' };
    }
  }
  return errorMessage(failure, 'webauthn');
}

// Backgrounding must not lose the signup capability: the email proof may be
// opened in another tab. Clear OTPs/prompts while hidden; recheck the key on return.
function useRegistrationLifetime(clear: () => void, foreground: () => void, hidden: () => void) {
  const callbacks = useRef({ clear, foreground, hidden });
  callbacks.current = { clear, foreground, hidden };
  useEffect(() => {
    const discard = () => callbacks.current.clear();
    const visibility = () =>
      document.visibilityState === 'hidden'
        ? callbacks.current.hidden()
        : callbacks.current.foreground();
    const navigation = (event: MouseEvent) => {
      if (event.target instanceof Element && event.target.closest('a[href]')) discard();
    };
    const unsubscribe = onOtherTabInvalidation(discard);
    window.addEventListener('pagehide', discard);
    window.addEventListener('popstate', discard);
    window.addEventListener('hashchange', discard);
    window.addEventListener(sensitiveClearEvent, discard);
    document.addEventListener('visibilitychange', visibility);
    document.addEventListener('click', navigation, true);
    return () => {
      unsubscribe();
      window.removeEventListener('pagehide', discard);
      window.removeEventListener('popstate', discard);
      window.removeEventListener('hashchange', discard);
      window.removeEventListener(sensitiveClearEvent, discard);
      document.removeEventListener('visibilitychange', visibility);
      document.removeEventListener('click', navigation, true);
    };
  }, []);
}

function Feedback({
  message,
  error,
  pending,
}: {
  message: Message;
  error: Message;
  pending: Message;
}) {
  const translate = useMessage();
  const feedback = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (message || error) feedback.current?.focus();
  }, [message, error]);
  return (
    <div
      ref={feedback}
      data-registration-feedback
      tabIndex={-1}
      className="rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <p
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className={
          message || pending ? 'rounded-md bg-muted/50 p-3 text-sm leading-relaxed' : 'sr-only'
        }
      >
        {translate(pending || message)}
      </p>
      {error && (
        <p
          role="alert"
          className="rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          {translate(error)}
        </p>
      )}
    </div>
  );
}

type Phase = 'contacts' | 'email' | 'phone' | 'passkey' | 'uncertain' | 'completed' | 'closed';
export function Registration() {
  const t = useTranslations();
  const preferences = useDisplayPreferences();
  const [hydrated, setHydrated] = useState(false);
  const [phase, setPhase] = useState<Phase>('contacts');
  const [attempt, setAttempt] = useState<RegistrationAttempt>();
  const [values, setValues] = useState<RegistrationValues>({ email: '', phone: '', username: '' });
  const [errors, setErrors] = useState<FieldErrors<RegistrationValues>>({});
  const [codeError, setCodeError] = useState<Message>('');
  const [smsCode, setSMSCode] = useState('');
  const [hasSMS, setHasSMS] = useState(false);
  const [pending, setPending] = useState<Message>('');
  const [error, setError] = useState<Message>('');
  const [message, setMessage] = useState<Message>('');
  const api = useRef<RegistrationClient | null>(null);
  const active = useRef<AbortController | null>(null);
  const alive = useRef(false);
  const deadline = useRef<{ wall: number; monotonic: number } | null>(null);
  const pendingDeadline = useRef<{ wall: number; monotonic: number } | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const code = useRef<HTMLInputElement>(null);
  const view = useRef<HTMLDivElement>(null);

  const clear = useCallback((message: Message = cleared) => {
    active.current?.abort();
    active.current = null;
    api.current?.dispose();
    api.current = null;
    deadline.current = null;
    pendingDeadline.current = null;
    if (code.current) code.current.value = '';
    for (const input of form.current?.querySelectorAll('input') ?? []) input.value = '';
    if (alive.current) {
      setAttempt(undefined);
      setValues({ email: '', phone: '', username: '' });
      setErrors({});
      setCodeError('');
      setSMSCode('');
      setHasSMS(false);
      setPending('');
      setMessage('');
      setError(message);
      setPhase('closed');
    }
  }, []);
  function usable() {
    const limit = deadline.current;
    if (limit && (Date.now() >= limit.wall || performance.now() >= limit.monotonic)) {
      clear({ key: 'registration.expiredNoSend' });
      return false;
    }
    return hydrated && document.visibilityState !== 'hidden';
  }
  async function foreground() {
    if (!api.current || active.current || !usable()) return;
    const current = api.current;
    try {
      await current.assertKey(new AbortController().signal);
    } catch {
      if (api.current === current) clear();
    }
  }
  useRegistrationLifetime(
    () => clear(),
    () => {
      void foreground();
    },
    () => {
      if (code.current) code.current.value = '';
      setSMSCode('');
      if (active.current) clear();
    }
  );
  useEffect(() => {
    alive.current = true;
    setHydrated(true);
    return () => {
      alive.current = false;
      clear();
    };
  }, [clear]);
  useEffect(() => {
    if (!attempt || phase === 'completed' || phase === 'closed') return;
    let timeout: ReturnType<typeof setTimeout>;
    const expire = () => {
      const limit = deadline.current;
      if (!limit) return;
      const remaining = Math.min(limit.wall - Date.now(), limit.monotonic - performance.now());
      // A queued pending timer must observe the synchronous completion handoff.
      if (remaining > 0) timeout = setTimeout(expire, remaining);
      else clear({ key: 'registration.expired' });
    };
    expire();
    return () => clearTimeout(timeout);
  }, [attempt, phase, clear]);
  useEffect(() => {
    if (phase === 'phone' && hasSMS) code.current?.focus();
  }, [phase, hasSMS]);

  function applyOutcome(result: RegistrationOutcome, signal: AbortSignal) {
    throwIfAborted(signal);
    if (!alive.current || active.current?.signal !== signal) return;
    setHasSMS(false);
    if (code.current) code.current.value = '';
    setSMSCode('');
    if (result.state === 'completed') {
      api.current?.dispose();
      api.current = null;
      deadline.current = null;
      pendingDeadline.current = null;
      setAttempt(undefined);
      setValues({ email: '', phone: '', username: '' });
      setPhase('completed');
      setMessage(
        { key: 'registration.created' }
      );
    } else if (result.state === 'failed')
      clear({ key: 'registration.failed' });
    else {
      deadline.current = pendingDeadline.current;
      if (!usable()) return;
      setPhase(result.phone_verified ? 'passkey' : result.email_verified ? 'phone' : 'email');
      setMessage(
        result.phone_verified
          ? { key: 'registration.contactsVerified' }
          : result.email_verified
            ? { key: 'registration.emailVerified' }
            : { key: 'registration.emailNotVerified' }
      );
    }
  }
  async function run(
    label: MessageDescriptor,
    operation: (client: RegistrationClient, signal: AbortSignal) => Promise<void>
  ) {
    if (active.current || !usable()) return;
    const controller = new AbortController();
    const current = api.current ?? (api.current = new RegistrationClient());
    active.current = controller;
    setError('');
    setMessage('');
    setPending(label);
    try {
      await operation(current, controller.signal);
      throwIfAborted(controller.signal);
    } catch (failure) {
      if (alive.current && active.current === controller && !isAborted(failure)) {
        if (
          failure instanceof PortalError &&
          (failure.uncertain || failure.code === 'result_required')
        ) {
          setPhase('uncertain');
        }
        if (
          failure instanceof PortalError &&
          [
            'invalid_registration',
            'registration_expired',
            'registration_key_changed',
            'key_unavailable',
            'registration_conflict',
            'username_unavailable',
            'username_policy_changed',
            'restart_registration',
            'invalid_response',
            'invalid_dpop_proof',
          ].includes(failure.code) &&
          !failure.uncertain
        )
          clear(registrationError(failure));
        else {
          if (failure instanceof PortalError && failure.code === 'invalid_username')
            setErrors({ username: { key: 'registration.usernameInvalid' } });
          setError(registrationError(failure));
        }
      }
    } finally {
      if (active.current === controller) {
        active.current = null;
        if (alive.current) setPending('');
      }
    }
  }
  function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hydrated || active.current || phase !== 'contacts') return;
    const data = new FormData(event.currentTarget);
    const contacts = {
      email: String(data.get('email') ?? ''),
      phone: normalizeNumericInput(String(data.get('phone') ?? '')),
      username: String(data.get('username') ?? ''),
    };
    const invalid: FieldErrors<RegistrationValues> = validateRegistration(contacts);
    if (!contacts.username) invalid.username = { key: 'registration.usernameRequired' };
    setValues(contacts);
    setErrors(invalid);
    if (Object.keys(invalid).length) {
      event.currentTarget
        .querySelector<HTMLInputElement>(`input[name="${Object.keys(invalid)[0]}"]`)
        ?.focus();
      return;
    }
    void run(
      { key: 'registration.starting' },
      async (client, signal) => {
        requireWebAuthn();
        const next = await client.start(contacts, signal);
        throwIfAborted(signal);
        const wall = Date.parse(next.expires_at);
        deadline.current = { wall, monotonic: performance.now() + wall - Date.now() };
        pendingDeadline.current = deadline.current;
        setAttempt(next);
        setValues({ email: '', phone: '', username: '' });
        setPhase('email');
        setMessage(
          next.email_sent
            ? { key: 'registration.emailAccepted' }
            : { key: 'registration.emailUnconfirmed' }
        );
      }
    );
  }
  function verifyPhone(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = normalizeNumericInput(code.current?.value ?? '');
    if (code.current) code.current.value = value;
    setSMSCode(value);
    const invalid = validateTotp({ code: value }).code;
    setCodeError(invalid ?? '');
    if (invalid) {
      code.current?.focus();
      return;
    }
    void run({ key: 'registration.verifyingPhone' }, async (client, signal) => {
      if (code.current) code.current.value = '';
      setSMSCode('');
      try {
        await client.verifyPhone(value, signal);
      } catch (failure) {
        if (!signal.aborted) setHasSMS(client.hasPhoneVerification());
        throw failure;
      }
      throwIfAborted(signal);
      setHasSMS(false);
      setPhase('passkey');
      setMessage(
        { key: 'registration.phoneVerified' }
      );
    });
  }
  const disabled = !hydrated || Boolean(pending);
  const actionClass = 'h-auto min-h-11 w-full whitespace-normal';
  return (
    <AuthCard
      title={t(`registration.headings.${phase}`)}
      description={phase === 'contacts' ? t('auth.pages.register.description') : undefined}
      footer={phase === 'completed' ? (
        <AuthLink href="/login">{t('registration.signIn')}</AuthLink>
      ) : (
        <>
          <span>{t('auth.pages.register.existing')}</span>
          <AuthLink href="/login">{t('auth.home.signIn')}</AuthLink>
        </>
      )}
    >
    <div ref={view} className="space-y-5">
      <Feedback message={message} error={error} pending={pending} />
      {phase === 'contacts' && (
        <form
          ref={form}
          data-registration-form
          method="post"
          noValidate
          aria-label={t('registration.formLabel')}
          onSubmit={start}
          className="space-y-5"
        >
          <p className="text-sm leading-relaxed text-muted-foreground">
            {t('registration.introduction')}</p>
          <AuthField
            name="email"
            label={t('registration.emailLabel')}
            type="text"
            inputMode="email"
            dir="ltr"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            required
            disabled={disabled}
            value={values.email}
            error={errors.email}
            hint={t('registration.emailHint')}
            onChange={(event) => {
              setValues({ ...values, email: event.target.value });
              setErrors({});
            }}
          />
          <AuthField
            name="phone"
            label={t('registration.phoneLabel')}
            type="tel"
            dir="ltr"
            inputMode="tel"
            autoComplete="tel"
            required
            disabled={disabled}
            value={values.phone}
            error={errors.phone}
            hint={t('registration.phoneHint')}
            onChange={(event) => {
              setValues({ ...values, phone: normalizeNumericInput(event.target.value) });
              setErrors({});
            }}
          />
          <AuthField
            name="username"
            label={t('registration.usernameLabel')}
            type="text"
            dir="auto"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            disabled={disabled}
            value={values.username}
            error={errors.username}
            hint={t('registration.usernameHint')}
            onChange={(event) => {
              setValues({ ...values, username: event.target.value });
              setErrors({});
              setMessage('');
              setError('');
            }}
          />
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            className={actionClass}
            onClick={() => {
              const username = String(new FormData(form.current ?? undefined).get('username') ?? '');
              if (!username) {
                setErrors({ username: { key: 'registration.usernameRequired' } });
                form.current?.querySelector<HTMLInputElement>('input[name="username"]')?.focus();
                return;
              }
              void run({ key: 'registration.checkingUsername' }, async (client, signal) => {
                const result = await client.validateUsername(username, signal);
                throwIfAborted(signal);
                setValues((current) => ({ ...current, username: result.username_display }));
                setErrors(result.available ? {} : { username: { key: 'registration.usernameUnavailable' } });
                setMessage(result.available ? { key: 'registration.usernameAvailable' } : '');
              });
            }}
          >
            {t('registration.checkUsername')}
          </Button>
          <Button type="submit" disabled={disabled} className={actionClass}>
            {t('registration.start')}</Button>
        </form>
      )}
      {phase === 'email' && (
        <div className="space-y-3">
          <Button
            type="button"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run({ key: 'registration.checkingEmail' }, async (client, signal) =>
                applyOutcome(await client.result(signal), signal)
              )
            }
          >
            {t('registration.checkEmail')}</Button>
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run({ key: 'registration.resendingEmail' }, async (client, signal) => {
                await client.resendEmail(signal);
                throwIfAborted(signal);
                setMessage(
                  { key: 'registration.emailResent' }
                );
              })
            }
          >
            {t('registration.resendEmail')}</Button>
        </div>
      )}
      {phase === 'phone' && (
        <div className="space-y-4">
          {hasSMS && (
            <form
              method="post"
              noValidate
              aria-label={t('registration.verifyPhoneLabel')}
              className="space-y-4"
              onSubmit={verifyPhone}
            >
              <AuthField
                ref={code}
                name="code"
                label={t('registration.smsCode')}
                type="text"
                dir="ltr"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                spellCheck={false}
                required
                disabled={disabled}
                error={codeError || undefined}
                hint={t('registration.codeHint')}
                value={smsCode}
                onChange={(event) => {
                  setSMSCode(normalizeNumericInput(event.target.value));
                  setCodeError('');
                }}
              />
              <Button type="submit" disabled={disabled} className={actionClass}>
                {t('registration.verifyPhone')}</Button>
            </form>
          )}
          <Button
            type="button"
            variant={hasSMS ? 'outline' : 'default'}
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run({ key: 'registration.requestingSMS' }, async (client, signal) => {
                setHasSMS(false);
                if (code.current) code.current.value = '';
                setSMSCode('');
                await client.sendPhone(signal);
                throwIfAborted(signal);
                setHasSMS(true);
                setMessage({ key: 'registration.smsAccepted' });
              })
            }
          >
            {hasSMS ? t('registration.resendSMS') : t('registration.sendSMS')}
          </Button>
        </div>
      )}
      {phase === 'passkey' && (
        <Button
          type="button"
          disabled={disabled}
          className={actionClass}
          onClick={() =>
            void run(
              { key: 'registration.creatingPasskey' },
              async (client, signal) => {
                requireWebAuthn();
                const options = await client.passkeyOptions(signal);
                const credential = await usePasskey(options, signal, true);
                await client.assertKey(signal);
                throwIfAborted(signal);
                if (!usable()) return;
                deadline.current = {
                  wall: Date.now() + 3600000,
                  monotonic: performance.now() + 3600000,
                };
                setPhase('uncertain');
                applyOutcome(await client.complete(credential, signal), signal);
              }
            )
          }
        >
          {t('registration.complete')}</Button>
      )}
      {phase === 'uncertain' && (
        <Button
          type="button"
          disabled={disabled}
          className={actionClass}
          onClick={() =>
            void run({ key: 'registration.readingResult' }, async (client, signal) =>
              applyOutcome(await client.result(signal), signal)
            )
          }
        >
          {t('registration.checkResult')}</Button>
      )}
      {phase === 'closed' && (
        <Button
          type="button"
          disabled={!hydrated}
          className={actionClass}
          onClick={() => {
            setError('');
            setMessage('');
            setPhase('contacts');
          }}
        >
          {t('registration.restart')}</Button>
      )}
      {!['completed', 'closed'].includes(phase) && (
        <Button
          type="button"
          variant="outline"
          disabled={!hydrated}
          className={actionClass}
          onClick={() => clear()}
        >
          {t('registration.cancel')}</Button>
      )}
      {phase === 'uncertain' && <AuthLink href="/login">{t('registration.normalSignIn')}</AuthLink>}
      {attempt && (
        <div className="space-y-3">
          <p className="break-words rounded-md bg-muted/50 p-3 text-sm leading-relaxed">
            {t.rich('registration.canonicalMailbox', {
              email: attempt.canonical_email,
              mailbox: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
            })}
            <br />
            {t.rich('registration.acceptedUsername', {
              username: attempt.username_display,
              name: (chunks) => <bdi dir="auto" data-username-private>{chunks}</bdi>,
            })}
            <br />
            {t.rich('registration.deadline', {
              deadline: formatDisplayDate(attempt.expires_at, preferences),
              time: (chunks) => <time dateTime={attempt.expires_at}>{chunks}</time>,
            })}
          </p>
          {phase === 'phone' && (
            <Button
              type="button"
              variant="outline"
              disabled={disabled}
              className={actionClass}
              onClick={() =>
                void run({ key: 'registration.checkingProofs' }, async (client, signal) =>
                  applyOutcome(await client.result(signal), signal)
                )
              }
            >
              {t('registration.checkProofs')}
            </Button>
          )}
        </div>
      )}
      <noscript>
        <p className="text-sm">
          {t('registration.noScript')}</p>
      </noscript>
    </div>
    </AuthCard>
  );
}

export function RegistrationEmailVerification() {
  const t = useTranslations();
  const [phase, setPhase] = useState<'loading' | 'ready' | 'verifying' | 'confirmed' | 'closed'>('loading');
  const captured = useRef(false);
  const proof = useRef<EmailProof | undefined>(undefined);
  const deadline = useRef<{ wall: number; monotonic: number } | undefined>(undefined);
  const active = useRef<AbortController | null>(null);
  const api = useRef<RegistrationClient | null>(null);
  const alive = useRef(false);
  const generation = useRef(0);
  const clear = useCallback(() => {
    proof.current = undefined;
    active.current?.abort();
    active.current = null;
    api.current?.dispose();
    api.current = null;
    try {
      window.history.replaceState(null, '', window.location.pathname);
    } catch {
      /* Verification stays disabled. */
    }
    if (alive.current) {
      setPhase((current) => current === 'confirmed' ? current : 'closed');
    }
  }, []);
  useRegistrationLifetime(
    clear,
    () => {
      const limit = deadline.current;
      if (limit && (Date.now() >= limit.wall || performance.now() >= limit.monotonic)) clear();
    },
    () => {
      if (active.current) clear();
    }
  );
  useEffect(() => {
    alive.current = true;
    const mounted = ++generation.current;
    if (!captured.current) {
      captured.current = true;
      try {
        proof.current = scrubRegistrationFragment();
      } catch {
        proof.current = undefined;
      }
      deadline.current = { wall: Date.now() + 600000, monotonic: performance.now() + 600000 };
    }
    // Update App Router's history integration after its parent effect installs,
    // using only the scrubbed public pathname. Locale actions must not restore
    // the original email bearer fragment from router state.
    const cleanPath = window.location.pathname;
    if (!window.location.hash && !window.location.search) {
      queueMicrotask(() => {
        if (!alive.current || generation.current !== mounted || window.location.pathname !== cleanPath) return;
        try { window.history.replaceState(null, '', cleanPath); }
        catch { clear(); }
      });
    }
    setPhase(proof.current ? 'ready' : 'closed');
    const timer = setTimeout(
      clear,
      Math.max(
        0,
        Math.min(
          (deadline.current?.wall ?? 0) - Date.now(),
          (deadline.current?.monotonic ?? 0) - performance.now()
        )
      )
    );
    return () => {
      alive.current = false;
      active.current?.abort();
      active.current = null;
      api.current?.dispose();
      api.current = null;
      clearTimeout(timer);
      queueMicrotask(() => {
        if (generation.current === mounted) proof.current = undefined;
      });
    };
  }, [clear]);
  async function verify() {
    const limit = deadline.current;
    if (
      phase !== 'ready' ||
      !proof.current ||
      active.current ||
      !limit ||
      document.visibilityState === 'hidden'
    )
      return;
    if (Date.now() >= limit.wall || performance.now() >= limit.monotonic) {
      clear();
      return;
    }
    const controller = new AbortController();
    active.current = controller;
    const current = new RegistrationClient();
    api.current = current;
    const capturedProof = proof.current;
    proof.current = undefined;
    setPhase('verifying');
    try {
      // No key initialization here. Another browser cannot redeem this link.
      await current.verifyEmail(capturedProof, controller.signal);
      throwIfAborted(controller.signal);
      setPhase('confirmed');
    } catch (failure) {
      if (alive.current && active.current === controller && !isAborted(failure))
        setPhase('closed');
    } finally {
      current.dispose();
      if (active.current === controller) {
        active.current = null;
        api.current = null;
      }
    }
  }
  return (
    <AuthCard
      title={t(`registration.verifyHeadings.${phase}`)}
      description={['loading', 'ready'].includes(phase) ? t('registration.verifyDescription') : undefined}
      footer={phase === 'confirmed' ? (
        <p>{t('registration.returnOriginalTab')}</p>
      ) : (
        <AuthLink href="/register">{t('registration.restartLink')}</AuthLink>
      )}
    >
    <div className="space-y-5">
      {phase !== 'confirmed' && <p className="text-sm leading-relaxed">
        {t('registration.originalBrowser')}</p>}
      <Feedback
        message={phase === 'confirmed' ? emailConfirmed : ''}
        error={phase === 'closed' ? invalidLink : ''}
        pending={phase === 'verifying' ? verifyingEmail : ''}
      />
      {phase !== 'confirmed' && <Button
        type="button"
        disabled={phase !== 'ready'}
        className="h-auto min-h-11 w-full whitespace-normal"
        onClick={() => void verify()}
      >
        {t('registration.verifyEmail')}</Button>}
      {phase === 'verifying' && (
        <Button type="button" variant="outline" className="min-h-11 w-full" onClick={clear}>
          {t('registration.cancelEmail')}</Button>
      )}
      <noscript>
        <p className="text-sm">
          {t('registration.emailNoScript')}</p>
      </noscript>
    </div>
    </AuthCard>
  );
}
