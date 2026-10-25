'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import type { StepUpChallenge, StepUpGrant } from '../../_lib/portal/contracts';
import type { StepUpIntent } from '../../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { sensitiveClearEvent, sensitiveSuspendEvent } from '../../_lib/portal/invalidation';
import { usePasskey } from '../../_lib/portal/webauthn';
import { controlClass, Feedback, inputClass } from './controls';
import { NativeDialog } from './native-dialog';
import { usePortal } from './portal-provider';

export function StepUpDialog({
  title,
  description,
  onCancel,
  onAuthorized,
  actionError,
  intent,
  resumeMethod,
}: {
  title: string;
  description: ReactNode;
  onCancel: () => void;
  onAuthorized: (grant: StepUpGrant, signal: AbortSignal) => Promise<void>;
  actionError?: (error: unknown) => string;
  intent?: StepUpIntent;
  resumeMethod?: 'totp';
}) {
  const { client, rememberStepUp } = usePortal();
  const [challenge, setChallenge] = useState<StepUpChallenge | null>(null);
  const [method, setMethod] = useState<'webauthn' | 'totp'>(resumeMethod ?? 'webauthn');
  const [pending, setPending] = useState('');
  const [error, setError] = useState('');
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState('');
  const busy = useRef(false);
  const close = useRef(onCancel);
  const lifetime = useRef<AbortController | null>(null);
  const authority = useRef<StepUpGrant | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const id = useId();

  useEffect(() => {
    close.current = onCancel;
  }, [onCancel]);

  useEffect(() => {
    lifetime.current = new AbortController();
    const clear = () => {
      authority.current?.clear();
      authority.current = null;
      lifetime.current?.abort();
      if (input.current) input.current.value = '';
      setCode('');
      setChallenge(null);
      close.current();
    };
    window.addEventListener(sensitiveClearEvent, clear);
    return () => {
      authority.current?.clear();
      authority.current = null;
      lifetime.current?.abort();
      window.removeEventListener(sensitiveClearEvent, clear);
    };
  }, []);
  useEffect(() => {
    const suspend = () => {
      // A submitted verification/action is never resumable. Only waiting for a
      // TOTP code may preserve intent; the code and all authority are discarded.
      if (intent && method === 'totp' && !busy.current) rememberStepUp(intent);
      authority.current?.clear();
      authority.current = null;
      lifetime.current?.abort();
      if (input.current) input.current.value = '';
      setCode('');
      setChallenge(null);
      close.current();
    };
    window.addEventListener(sensitiveSuspendEvent, suspend);
    return () => window.removeEventListener(sensitiveSuspendEvent, suspend);
  }, [intent, method, rememberStepUp]);
  useEffect(() => {
    if (method === 'totp' && challenge) input.current?.focus();
  }, [method, challenge]);

  function cancel() {
    authority.current?.clear();
    authority.current = null;
    lifetime.current?.abort();
    if (input.current) input.current.value = '';
    setCode('');
    onCancel();
  }

  async function start() {
    if (busy.current || !lifetime.current) return;
    busy.current = true;
    const { signal } = lifetime.current;
    setError('');
    setPending('Preparing fresh verification...');
    try {
      const value = await client.stepUpChallenge(signal);
      throwIfAborted(signal);
      setChallenge(value);
      setMethod((current) =>
        current === 'totp' && value.methods.includes('totp')
          ? 'totp'
          : value.methods.includes('webauthn')
            ? 'webauthn'
            : 'totp'
      );
    } catch (failure) {
      if (!signal.aborted && !isAborted(failure)) setError(errorMessage(failure));
    } finally {
      busy.current = false;
      if (!signal.aborted) setPending('');
    }
  }

  async function verify() {
    if (busy.current || !challenge || !lifetime.current) return;
    if (method === 'totp' && !/^[0-9]{6}$/.test(code)) {
      setCodeError('Enter the six-digit code from your authenticator app.');
      input.current?.focus();
      return;
    }
    busy.current = true;
    const { signal } = lifetime.current;
    let grant: StepUpGrant | undefined;
    let performingAction = false;
    setError('');
    setCodeError('');
    setPending(
      method === 'webauthn'
        ? 'Complete PIN or biometric verification on your authenticator.'
        : 'Verifying your authenticator code...'
    );
    try {
      const proof =
        method === 'webauthn'
          ? {
              method: 'webauthn' as const,
              assertion: await usePasskey(challenge.webauthn, signal, false, true),
            }
          : { method: 'totp' as const, code };
      throwIfAborted(signal);
      grant = await client.stepUpVerify(proof, signal);
      authority.current = grant;
      setCode('');
      throwIfAborted(signal);
      client.assertSession();
      performingAction = true;
      setPending('Applying the confirmed action...');
      await onAuthorized(grant, signal);
      throwIfAborted(signal);
      onCancel();
    } catch (failure) {
      if (!signal.aborted && !isAborted(failure)) {
        setError(performingAction && actionError ? actionError(failure) : errorMessage(failure));
        setCode('');
        // A failed TOTP verification is not a lost session. It may be retried
        // with a new code; any minted/used grant and WebAuthn ceremony are spent.
        if (
          performingAction ||
          method === 'webauthn' ||
          !(failure instanceof PortalError && failure.code === 'invalid_credentials')
        )
          setChallenge(null);
        else input.current?.focus();
      }
    } finally {
      grant?.clear();
      if (authority.current === grant) authority.current = null;
      busy.current = false;
      if (!signal.aborted) setPending('');
    }
  }

  return (
    <NativeDialog title={title} description={description} onCancel={cancel} testId="stepup-dialog">
      <Feedback error={error} status={pending} />
      {resumeMethod === 'totp' && (
        <p className="text-sm text-muted-foreground">
          Your pending action was restored after checking the same session. Start fresh
          verification; no previous code or grant was retained.
        </p>
      )}
      {!challenge ? (
        <Button
          type="button"
          className={`${controlClass} w-full`}
          disabled={Boolean(pending)}
          onClick={start}
        >
          {error ? 'Start new verification' : 'Continue to verification'}
        </Button>
      ) : (
        <div className="space-y-4">
          <p className="text-sm">
            Confirm your identity for this action only. Verification is single-use.
          </p>
          {method === 'webauthn' ? (
            <Button
              type="button"
              className={`${controlClass} w-full`}
              onClick={verify}
              disabled={Boolean(pending)}
            >
              Verify with a passkey
            </Button>
          ) : (
            <form
              aria-label="Step-up authenticator verification"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                void verify();
              }}
              className="space-y-3"
            >
              <Label htmlFor={id}>Authenticator code</Label>
              <Input
                ref={input}
                id={id}
                name="stepup-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(event) => {
                  setCode(event.target.value);
                  setCodeError('');
                }}
                disabled={Boolean(pending)}
                aria-invalid={Boolean(codeError)}
                aria-describedby={`${id}-hint${codeError ? ` ${id}-error` : ''}`}
                className={`${inputClass} font-mono tracking-widest`}
              />
              <p id={`${id}-hint`} className="text-sm text-muted-foreground">
                Use your enrolled authenticator app, not an email, text message, or recovery code.
              </p>
              {codeError && (
                <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
                  {codeError}
                </p>
              )}
              <Button
                type="submit"
                className={`${controlClass} w-full`}
                disabled={Boolean(pending)}
              >
                Verify code
              </Button>
            </form>
          )}
          {challenge.methods.includes('totp') && method !== 'totp' && (
            <Button
              type="button"
              variant="outline"
              className={`${controlClass} w-full`}
              disabled={Boolean(pending)}
              onClick={() => setMethod('totp')}
            >
              Use authenticator code
            </Button>
          )}
          {challenge.methods.includes('webauthn') && method !== 'webauthn' && (
            <Button
              type="button"
              variant="outline"
              className={`${controlClass} w-full`}
              disabled={Boolean(pending)}
              onClick={() => setMethod('webauthn')}
            >
              Use a passkey instead
            </Button>
          )}
        </div>
      )}
      <Button type="button" variant="ghost" className={`${controlClass} w-full`} onClick={cancel}>
        Cancel
      </Button>
    </NativeDialog>
  );
}
