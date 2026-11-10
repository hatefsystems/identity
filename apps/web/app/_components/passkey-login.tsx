'use client';

import type { Message } from '../../i18n/messages';
import { useMessage } from '../../i18n/use-message';

import { useTranslations } from 'next-intl';

import { Button } from '@hatef/ui';
import { Fingerprint } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { PortalClient } from '../_lib/portal/client';
import { browserKey } from '../_lib/portal/dpop';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../_lib/portal/errors';
import { invalidateOtherTabs } from '../_lib/portal/invalidation';
import { safeReturnPath } from '../_lib/portal/validation';
import { requireWebAuthn, usePasskey } from '../_lib/portal/webauthn';

export function PasskeyLogin({
  label,
  introduction = false,
}: {
  label?: string;
  introduction?: boolean;
}) {
  const t = useTranslations();
  const message = useMessage();
  const router = useRouter();
  const [hydrated, setHydrated] = useState(false);
  const [pending, setPending] = useState(false);
  const [status, setStatus] = useState<Message>('');
  const [error, setError] = useState<Message>('');
  const active = useRef<{ controller: AbortController; verificationStarted: boolean } | null>(null);
  const feedback = useRef<HTMLParagraphElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setHydrated(true);
    return () => {
      active.current?.controller.abort();
      active.current = null;
    };
  }, []);
  useEffect(() => {
    if (error) feedback.current?.focus();
    else if (status) button.current?.focus();
  }, [error, status]);

  async function login() {
    if (active.current) return;
    const controller = new AbortController();
    const operation = { controller, verificationStarted: false };
    active.current = operation;
    setPending(true);
    setStatus('');
    setError('');
    let client: PortalClient | undefined;
    try {
      requireWebAuthn();
      await browserKey(true, controller.signal);
      throwIfAborted(controller.signal);
      client = new PortalClient();
      const options = await client.loginOptions(controller.signal);
      throwIfAborted(controller.signal);
      const assertion = await usePasskey(options, controller.signal);
      throwIfAborted(controller.signal);
      try {
        // No send callback is exposed here: verification may be sent from this point.
        operation.verificationStarted = true;
        await client.loginVerify(assertion, controller.signal);
      } finally {
        // A lost verify response may still have changed the shared cookie.
        invalidateOtherTabs();
      }
      throwIfAborted(controller.signal);
      await client.bootstrap(controller.signal);
      throwIfAborted(controller.signal);
      router.replace(safeReturnPath(new URLSearchParams(window.location.search).get('returnTo')));
    } catch (failure) {
      if (active.current !== operation || controller.signal.aborted) return;
      if (
        operation.verificationStarted &&
        (!(failure instanceof PortalError) ||
          failure.uncertain ||
          ['cancelled', 'network_error', 'invalid_response'].includes(failure.code))
      ) {
        setStatus({ key: 'auth.passkey.unconfirmed' });
      } else if (
        isAborted(failure) ||
        (failure instanceof PortalError && failure.code === 'cancelled')
      ) {
        setStatus({ key: 'auth.passkey.notCompleted' });
      } else setError(errorMessage(failure));
    } finally {
      client?.dispose();
      if (active.current === operation) {
        active.current = null;
        setPending(false);
      }
    }
  }

  function cancel() {
    const operation = active.current;
    if (!operation) return;
    operation.controller.abort();
    active.current = null;
    setPending(false);
    setError('');
    setStatus({
      key: operation.verificationStarted ? 'auth.passkey.unconfirmed' : 'auth.passkey.cancelled',
    });
  }

  return (
    <div className="space-y-4">
      {introduction && (
        <p className="rounded-md bg-muted/50 p-4 text-sm leading-relaxed">
          {t('auth.passkey.intro')}
        </p>
      )}
      <p
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className={pending || status ? 'text-sm leading-relaxed text-muted-foreground' : 'sr-only'}
      >
        {pending ? t('auth.passkey.pending') : message(status)}
      </p>
      {error && (
        <p
          ref={feedback}
          tabIndex={-1}
          role="alert"
          className="rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 focus:outline-none dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          {message(error)}
        </p>
      )}
      <Button
        ref={button}
        type="button"
        data-testid="passkey-login"
        onClick={login}
        disabled={!hydrated || pending}
        className="h-auto min-h-11 w-full whitespace-normal"
      >
        <Fingerprint aria-hidden="true" />
        {pending ? t('auth.passkey.verifying') : (label ?? t('auth.passkey.use'))}
      </Button>
      {pending && (
        <Button type="button" variant="outline" onClick={cancel} className="min-h-11 w-full">
          {t('auth.passkey.cancel')}
        </Button>
      )}
      <noscript>
        <p className="text-sm">{t('auth.passkey.noScript')}</p>
      </noscript>
    </div>
  );
}
