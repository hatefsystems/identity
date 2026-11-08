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
import { errorMessage, isAborted, throwIfAborted } from '../_lib/portal/errors';
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
  const [error, setError] = useState<Message>('');
  const active = useRef<AbortController | null>(null);
  const feedback = useRef<HTMLParagraphElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setHydrated(true);
    return () => {
      active.current?.abort();
      active.current = null;
    };
  }, []);
  useEffect(() => {
    if (error) feedback.current?.focus();
  }, [error]);

  async function login() {
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setPending(true);
    setError('');
    let client: PortalClient | undefined;
    try {
      requireWebAuthn();
      await browserKey(true, controller.signal);
      client = new PortalClient();
      const options = await client.loginOptions(controller.signal);
      const assertion = await usePasskey(options, controller.signal);
      throwIfAborted(controller.signal);
      try {
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
      if (!controller.signal.aborted && !isAborted(failure)) setError(errorMessage(failure));
    } finally {
      client?.dispose();
      if (active.current === controller) {
        active.current = null;
        setPending(false);
      }
    }
  }

  function cancel() {
    active.current?.abort();
    active.current = null;
    setPending(false);
    setError({ key: 'auth.passkey.cancelled' });
    button.current?.focus();
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
        className={pending ? 'text-sm text-muted-foreground' : 'sr-only'}
      >
        {pending ? t('auth.passkey.pending') : ''}
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
