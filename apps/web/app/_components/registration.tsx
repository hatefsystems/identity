'use client';

import { Button } from '@hatef/ui';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AuthLink } from '../(auth)/_components/auth-card';
import { AuthField } from '../(auth)/_components/form-controls';
import {
  validateRegistration,
  validateTotp,
  type FieldErrors,
  type RegistrationValues,
} from '../(auth)/_lib/validation';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../_lib/portal/errors';
import { onOtherTabInvalidation, sensitiveClearEvent } from '../_lib/portal/invalidation';
import {
  RegistrationClient,
  scrubRegistrationFragment,
  type EmailProof,
  type RegistrationAttempt,
  type RegistrationOutcome,
} from '../_lib/portal/registration-client';
import { requireWebAuthn, usePasskey } from '../_lib/portal/webauthn';

const cleared =
  'Registration was cleared. Start again, or sign in normally if account creation may have completed.';
const invalidLink =
  'This link cannot be verified here. Use the original browser, or restart registration. The link cannot recover signup authority.';
function registrationError(failure: unknown): string {
  if (failure instanceof PortalError) {
    if (failure.uncertain || failure.code === 'result_required')
      return 'The completion response was lost. Check the registration result before creating anything else. You can also try normal passkey sign-in.';
    switch (failure.code) {
      case 'invalid_registration':
      case 'registration_key_changed':
        return 'Registration no longer belongs to this browser key. Start again in the original browser, or sign in normally.';
      case 'registration_expired':
        return 'Registration or an ownership proof expired. Start again; resending never extends the registration deadline.';
      case 'registration_conflict':
      case 'restart_registration':
        return 'Registration could not be completed. Start again or use normal sign-in. No existing account has been changed.';
      case 'proof_required':
        return 'The ownership proof could not be accepted. Check the saved result and use fresh verification.';
      case 'restart_phone_proof':
        return 'The phone proof could not be saved. Check the saved result, then explicitly request a fresh SMS if needed.';
      case 'send_failed':
        return 'Delivery was not confirmed. Ownership is not verified. Any new send requires your action and is separately rate-limited.';
      case 'temporarily_unavailable':
        return 'Registration is temporarily unavailable. No delivery or account creation is confirmed.';
      case 'not_found':
        return 'Registration is currently unavailable. Use normal passkey sign-in for an existing account.';
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
  message: string;
  error: string;
  pending: string;
}) {
  const feedback = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (message || error) feedback.current?.focus();
  }, [message, error]);
  return (
    <div
      ref={feedback}
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
        {pending || message}
      </p>
      {error && (
        <p
          role="alert"
          className="rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          {error}
        </p>
      )}
    </div>
  );
}

type Phase = 'contacts' | 'email' | 'phone' | 'passkey' | 'uncertain' | 'completed' | 'closed';
export function Registration() {
  const [hydrated, setHydrated] = useState(false);
  const [phase, setPhase] = useState<Phase>('contacts');
  const [attempt, setAttempt] = useState<RegistrationAttempt>();
  const [values, setValues] = useState<RegistrationValues>({ email: '', phone: '' });
  const [errors, setErrors] = useState<FieldErrors<RegistrationValues>>({});
  const [codeError, setCodeError] = useState('');
  const [hasSMS, setHasSMS] = useState(false);
  const [pending, setPending] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const api = useRef<RegistrationClient | null>(null);
  const active = useRef<AbortController | null>(null);
  const alive = useRef(false);
  const deadline = useRef<{ wall: number; monotonic: number } | null>(null);
  const pendingDeadline = useRef<{ wall: number; monotonic: number } | null>(null);
  const form = useRef<HTMLFormElement>(null);
  const code = useRef<HTMLInputElement>(null);
  const view = useRef<HTMLDivElement>(null);

  const clear = useCallback((message = cleared) => {
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
      setValues({ email: '', phone: '' });
      setErrors({});
      setCodeError('');
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
      clear('Registration expired. Start again; no message is sent automatically.');
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
      else clear('Registration expired. Start again or try normal passkey sign-in.');
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
    if (result.state === 'completed') {
      api.current?.dispose();
      api.current = null;
      deadline.current = null;
      pendingDeadline.current = null;
      setAttempt(undefined);
      setValues({ email: '', phone: '' });
      setPhase('completed');
      setMessage(
        'Your account was created. Sign in with your passkey to continue. Registration did not sign you in.'
      );
    } else if (result.state === 'failed')
      clear('Registration could not complete. Start again or use normal sign-in.');
    else {
      deadline.current = pendingDeadline.current;
      if (!usable()) return;
      setPhase(result.phone_verified ? 'passkey' : result.email_verified ? 'phone' : 'email');
      setMessage(
        result.phone_verified
          ? 'Email and phone ownership are verified. Create a discoverable passkey with a device PIN or biometrics.'
          : result.email_verified
            ? 'Email ownership is verified. Request an SMS when you are ready.'
            : 'Email ownership is not yet verified. Open the email link in this browser and confirm it, then check again.'
      );
    }
  }
  async function run(
    label: string,
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
            'restart_registration',
            'invalid_response',
            'invalid_dpop_proof',
          ].includes(failure.code) &&
          !failure.uncertain
        )
          clear(registrationError(failure));
        else setError(registrationError(failure));
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
      phone: String(data.get('phone') ?? ''),
    };
    const invalid = validateRegistration(contacts);
    setValues(contacts);
    setErrors(invalid);
    if (Object.keys(invalid).length) {
      event.currentTarget
        .querySelector<HTMLInputElement>(`input[name="${Object.keys(invalid)[0]}"]`)
        ?.focus();
      return;
    }
    void run(
      'Starting registration and requesting your verification email...',
      async (client, signal) => {
        requireWebAuthn();
        const next = await client.start(contacts, signal);
        throwIfAborted(signal);
        const wall = Date.parse(next.expires_at);
        deadline.current = { wall, monotonic: performance.now() + wall - Date.now() };
        pendingDeadline.current = deadline.current;
        setAttempt(next);
        setValues({ email: '', phone: '' });
        setPhase('email');
        setMessage(
          next.email_sent
            ? 'Verification email accepted for delivery. Open its link in this browser and explicitly confirm it. No account exists yet.'
            : 'Email delivery was not confirmed. Request another email explicitly when ready. No ownership is verified.'
        );
      }
    );
  }
  function verifyPhone(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = code.current?.value ?? '';
    const invalid = validateTotp({ code: value }).code;
    setCodeError(invalid ?? '');
    if (invalid) {
      code.current?.focus();
      return;
    }
    void run('Verifying phone ownership...', async (client, signal) => {
      if (code.current) code.current.value = '';
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
        'Phone ownership is verified. Create a discoverable passkey with a device PIN or biometrics.'
      );
    });
  }
  const disabled = !hydrated || Boolean(pending);
  const actionClass = 'h-auto min-h-11 w-full whitespace-normal';
  return (
    <div ref={view} className="space-y-5">
      <Feedback message={message} error={error} pending={pending} />
      {phase === 'contacts' && (
        <form
          ref={form}
          method="post"
          noValidate
          aria-label="Create an account"
          onSubmit={start}
          className="space-y-5"
        >
          <p className="text-sm leading-relaxed text-muted-foreground">
            Use an existing mailbox you own and an Iranian mobile number. Verify both before
            creating a passkey. No password, invitation or new mailbox is needed.
          </p>
          <AuthField
            name="email"
            label="Email address"
            type="text"
            inputMode="email"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            required
            disabled={disabled}
            value={values.email}
            error={errors.email}
            hint="Unicode addresses are supported. The server determines the canonical address; input is limited to 1024 UTF-8 bytes."
            onChange={(event) => {
              setValues({ ...values, email: event.target.value });
              setErrors({});
            }}
          />
          <AuthField
            name="phone"
            label="Iranian mobile number"
            type="tel"
            inputMode="tel"
            autoComplete="tel"
            required
            disabled={disabled}
            value={values.phone}
            error={errors.phone}
            hint="For example, +989123456789. SMS is sent only when you request it after email verification."
            onChange={(event) => {
              setValues({ ...values, phone: event.target.value });
              setErrors({});
            }}
          />
          <Button type="submit" disabled={disabled} className={actionClass}>
            Start registration and send email
          </Button>
        </form>
      )}
      {attempt && (
        <p className="break-words rounded-md bg-muted/50 p-3 text-sm leading-relaxed">
          Canonical mailbox: <bdi dir="auto">{attempt.canonical_email}</bdi>
          <br />
          Registration expires at{' '}
          <time dateTime={attempt.expires_at}>
            {new Date(attempt.expires_at).toLocaleTimeString()}
          </time>
          . Resends do not extend this deadline. Keep this registration tab open.
        </p>
      )}
      {phase === 'email' && (
        <div className="space-y-3">
          <Button
            type="button"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run('Checking email ownership...', async (client, signal) =>
                applyOutcome(await client.result(signal), signal)
              )
            }
          >
            Check email verification
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run('Requesting a new verification email...', async (client, signal) => {
                await client.resendEmail(signal);
                throwIfAborted(signal);
                setMessage(
                  'A new email was accepted for delivery. Previous email and phone proofs are invalidated. Confirm the new email link before continuing.'
                );
              })
            }
          >
            Send another verification email
          </Button>
        </div>
      )}
      {phase === 'phone' && (
        <div className="space-y-4">
          <Button
            type="button"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run('Requesting your SMS code...', async (client, signal) => {
                setHasSMS(false);
                if (code.current) code.current.value = '';
                await client.sendPhone(signal);
                throwIfAborted(signal);
                setHasSMS(true);
                setMessage(
                  'SMS accepted for delivery. Enter the six-digit code to prove ownership; delivery alone does not verify your phone.'
                );
              })
            }
          >
            {hasSMS ? 'Send a new SMS code' : 'Send SMS code'}
          </Button>
          {hasSMS && (
            <form
              method="post"
              noValidate
              aria-label="Verify registration phone"
              className="space-y-4"
              onSubmit={verifyPhone}
            >
              <AuthField
                ref={code}
                name="code"
                label="SMS verification code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                spellCheck={false}
                required
                disabled={disabled}
                error={codeError}
                hint="Enter six ASCII digits, including any leading zero. The code is never submitted automatically."
              />
              <Button type="submit" disabled={disabled} className={actionClass}>
                Verify phone
              </Button>
            </form>
          )}
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            className={actionClass}
            onClick={() =>
              void run('Checking saved ownership proofs...', async (client, signal) =>
                applyOutcome(await client.result(signal), signal)
              )
            }
          >
            Check saved proofs
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
              'Create a passkey with a device PIN or biometrics...',
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
          Create passkey and complete registration
        </Button>
      )}
      {phase === 'uncertain' && (
        <Button
          type="button"
          disabled={disabled}
          className={actionClass}
          onClick={() =>
            void run('Reading the durable registration result...', async (client, signal) =>
              applyOutcome(await client.result(signal), signal)
            )
          }
        >
          Check registration result
        </Button>
      )}
      {phase === 'completed' && <AuthLink href="/login">Sign in with your passkey</AuthLink>}
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
          Start a new registration
        </Button>
      )}
      {!['completed', 'closed'].includes(phase) && (
        <Button
          type="button"
          variant="outline"
          disabled={!hydrated}
          className={actionClass}
          onClick={() => clear()}
        >
          Cancel registration
        </Button>
      )}
      {phase === 'uncertain' && <AuthLink href="/login">Try normal passkey sign-in</AuthLink>}
      <noscript>
        <p className="text-sm">
          JavaScript is required for secure registration. No credentials or verification request are
          submitted without it.
        </p>
      </noscript>
    </div>
  );
}

export function RegistrationEmailVerification() {
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
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
      setReady(false);
      setPending('');
      setError(invalidLink);
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
    setReady(Boolean(proof.current));
    if (!proof.current) setError(invalidLink);
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
      !ready ||
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
    setReady(false);
    setError('');
    setPending('Verifying email ownership in the original browser...');
    try {
      // No key initialization here. Another browser cannot redeem this link.
      await current.verifyEmail(capturedProof, controller.signal);
      throwIfAborted(controller.signal);
      setMessage(
        'Email ownership is verified. Return to the original registration tab and check email verification there. This page cannot create an account or recover signup authority.'
      );
    } catch (failure) {
      if (alive.current && active.current === controller && !isAborted(failure))
        setError(invalidLink);
    } finally {
      current.dispose();
      if (active.current === controller) {
        active.current = null;
        api.current = null;
        if (alive.current) setPending('');
      }
    }
  }
  return (
    <div className="space-y-5">
      <p className="text-sm leading-relaxed">
        Confirm only in the browser where registration started. Keep the original registration tab
        open. A different browser must restart registration.
      </p>
      <Feedback message={message} error={error} pending={pending} />
      <Button
        type="button"
        disabled={!ready || Boolean(pending)}
        className="h-auto min-h-11 w-full whitespace-normal"
        onClick={() => void verify()}
      >
        Verify email ownership
      </Button>
      {pending && (
        <Button type="button" variant="outline" className="min-h-11 w-full" onClick={clear}>
          Cancel email verification
        </Button>
      )}
      <noscript>
        <p className="text-sm">
          JavaScript is required to scrub and verify this link securely. No verification request is
          submitted without it.
        </p>
      </noscript>
    </div>
  );
}
