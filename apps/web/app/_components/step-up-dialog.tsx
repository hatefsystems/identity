'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useTranslations } from 'next-intl';
import type { Message, MessageDescriptor } from '../../i18n/messages';
import { useMessage } from '../../i18n/use-message';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { normalizeNumericInput } from '../_lib/numeric-input';
import type { StepUpChallenge, StepUpGrant } from '../_lib/portal/contracts';
import type { StepUpIntent } from '../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../_lib/portal/errors';
import { sensitiveClearEvent, sensitiveSuspendEvent } from '../_lib/portal/invalidation';
import { usePasskey } from '../_lib/portal/webauthn';
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
  mode = 'default',
  layout = 'default',
  verifiedContent,
  verifiedActions,
  verifiedStatus = { key: 'security.stepUp.applying' },
}: {
  title: string;
  description: ReactNode;
  onCancel: () => void;
  onAuthorized: (grant: StepUpGrant, signal: AbortSignal) => Promise<void>;
  actionError?: (error: unknown) => MessageDescriptor;
  intent?: StepUpIntent;
  resumeMethod?: 'totp';
  mode?: 'default' | 'webauthn-only';
  layout?: 'default' | 'review';
  // Keep onAuthorized pending for the entire confirmation stage. Its finally
  // block owns the grant; callers must never retain authority after it returns.
  verifiedContent?: ReactNode;
  verifiedActions?: ReactNode;
  verifiedStatus?: MessageDescriptor;
}) {
  const t = useTranslations('security.stepUp');
  const message = useMessage();
  const { client, rememberStepUp } = usePortal();
  const webauthnOnly = mode === 'webauthn-only';
  const review = layout === 'review';
  const [challenge, setChallenge] = useState<StepUpChallenge | null>(null);
  const [method, setMethod] = useState<'webauthn' | 'totp'>(
    webauthnOnly ? 'webauthn' : (resumeMethod ?? 'webauthn')
  );
  const [pending, setPending] = useState<Message>('');
  const [error, setError] = useState<Message>('');
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<Message>('');
  const [verified, setVerified] = useState(false);
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
      clearCodeInput(input.current);
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
      if (!webauthnOnly && intent && method === 'totp' && !busy.current) rememberStepUp(intent);
      authority.current?.clear();
      authority.current = null;
      lifetime.current?.abort();
      clearCodeInput(input.current);
      setCode('');
      setChallenge(null);
      close.current();
    };
    window.addEventListener(sensitiveSuspendEvent, suspend);
    return () => window.removeEventListener(sensitiveSuspendEvent, suspend);
  }, [intent, method, rememberStepUp, webauthnOnly]);
  useEffect(() => {
    const field = input.current;
    if (method === 'totp' && challenge) field?.focus();
    return () => clearCodeInput(field);
  }, [method, challenge]);

  function cancel() {
    authority.current?.clear();
    authority.current = null;
    lifetime.current?.abort();
    clearCodeInput(input.current);
    setCode('');
    onCancel();
  }

  async function start() {
    if (busy.current || !lifetime.current) return;
    busy.current = true;
    const { signal } = lifetime.current;
    setError('');
    setPending({ key: 'security.stepUp.preparing' });
    try {
      const value = await client.stepUpChallenge(signal);
      throwIfAborted(signal);
      if (webauthnOnly && !value.methods.includes('webauthn'))
        throw new PortalError('no_stepup_factor');
      setChallenge(value);
      setMethod((current) =>
        !webauthnOnly && current === 'totp' && value.methods.includes('totp')
          ? 'totp'
          : value.methods.includes('webauthn')
            ? 'webauthn'
            : 'totp'
      );
    } catch (failure) {
      if (!signal.aborted && !isAborted(failure))
        setError(errorMessage(failure, webauthnOnly ? 'webauthn' : undefined));
    } finally {
      busy.current = false;
      if (!signal.aborted) setPending('');
    }
  }

  async function verify() {
    if (busy.current || !challenge || !lifetime.current) return;
    if (webauthnOnly && method !== 'webauthn') return;
    const normalizedCode = normalizeNumericInput(input.current?.value ?? code);
    if (method === 'totp' && !/^[0-9]{6}$/.test(normalizedCode)) {
      setCodeError({ key: 'security.stepUp.codeError' });
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
        ? { key: 'security.stepUp.passkeyPending' }
        : { key: 'security.stepUp.codePending' }
    );
    try {
      const proof =
        method === 'webauthn'
          ? {
              method: 'webauthn' as const,
              assertion: await usePasskey(challenge.webauthn, signal, false, true),
            }
          : { method: 'totp' as const, code: normalizedCode };
      throwIfAborted(signal);
      grant = await client.stepUpVerify(proof, signal);
      authority.current = grant;
      clearCodeInput(input.current);
      setCode('');
      throwIfAborted(signal);
      client.assertSession();
      performingAction = true;
      setChallenge(null);
      setVerified(true);
      setPending('');
      await onAuthorized(grant, signal);
      throwIfAborted(signal);
      onCancel();
    } catch (failure) {
      if (!signal.aborted && !isAborted(failure)) {
        setError(
          performingAction && actionError
            ? actionError(failure)
            : errorMessage(failure, webauthnOnly ? 'webauthn' : undefined)
        );
        clearCodeInput(input.current);
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
      if (!signal.aborted) {
        setPending('');
        setVerified(false);
      }
    }
  }

  const continueControl = (
    <Button
      type="button"
      className={`${controlClass} w-full`}
      disabled={Boolean(pending) || verified}
      onClick={start}
    >
      {t(error ? 'restart' : 'continue')}
    </Button>
  );
  const passkeyControl = (
    <Button
      type="button"
      className={`${controlClass} w-full`}
      onClick={verify}
      disabled={Boolean(pending)}
    >
      {t('passkey')}
    </Button>
  );
  const codeControl = (
    <Button
      type="submit"
      form={review ? `${id}-form` : undefined}
      className={`${controlClass} w-full`}
      disabled={Boolean(pending)}
    >
      {t('verifyCode')}
    </Button>
  );
  const cancelControl = (
    <Button type="button" variant="ghost" className={`${controlClass} w-full`} onClick={cancel}>
      {t('cancel')}
    </Button>
  );

  return (
    <NativeDialog
      title={title}
      description={description}
      onCancel={cancel}
      testId="stepup-dialog"
      layout={layout}
      footer={
        review && (
          <>
            {verified
              ? verifiedActions
              : !challenge
                ? continueControl
                : method === 'webauthn'
                  ? passkeyControl
                  : codeControl}
            {cancelControl}
          </>
        )
      }
    >
      <Feedback error={error} status={verified ? verifiedStatus : pending} />
      {!verified && !webauthnOnly && resumeMethod === 'totp' && (
        <p className="text-sm text-muted-foreground">
          {t('restored')}
        </p>
      )}
      {verified && verifiedContent ? (
        verifiedContent
      ) : !challenge ? (
        !review && continueControl
      ) : (
        <div className="space-y-4">
          <p className="text-sm">
            {t('singleUse')}
          </p>
          {method === 'webauthn' ? (
            !review && passkeyControl
          ) : (
            <form
              id={`${id}-form`}
              aria-label={t('form')}
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                void verify();
              }}
              className="space-y-3"
            >
              <Label htmlFor={id}>{t('code')}</Label>
              <Input
                ref={input}
                id={id}
                name="stepup-code"
                type="text"
                dir="ltr"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(event) => {
                  setCode(normalizeNumericInput(event.target.value));
                  setCodeError('');
                }}
                disabled={Boolean(pending)}
                aria-invalid={Boolean(codeError)}
                aria-describedby={`${id}-hint${codeError ? ` ${id}-error` : ''}`}
                className={`${inputClass} font-mono tracking-widest`}
              />
              <p id={`${id}-hint`} className="text-sm text-muted-foreground">
                {t('hint')}
              </p>
              {codeError && (
                <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
                  {message(codeError)}
                </p>
              )}
              {!review && codeControl}
            </form>
          )}
          {!webauthnOnly && challenge.methods.includes('totp') && method !== 'totp' && (
            <Button
              type="button"
              variant="outline"
              className={`${controlClass} w-full`}
              disabled={Boolean(pending)}
              onClick={() => setMethod('totp')}
            >
              {t('useCode')}
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
              {t('usePasskey')}
            </Button>
          )}
        </div>
      )}
      {!review && cancelControl}
    </NativeDialog>
  );
}

function clearCodeInput(input: HTMLInputElement | null) {
  if (!input) return;
  input.defaultValue = '';
  input.value = '';
}
