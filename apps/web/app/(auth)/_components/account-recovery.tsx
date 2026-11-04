'use client';

import type { Message } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';

import { useTranslations } from 'next-intl';

import { Button, Input, Label } from '@hatef/ui';
import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import {
  isReclaimToken,
  ReclaimClient,
  type ReclaimOptions,
  type ReclaimProof,
} from '../../_lib/portal/reclaim-client';
import { usePasskey } from '../../_lib/portal/webauthn';
import { controlClass, Feedback, inputClass } from '../../dashboard/_components/controls';
import { AuthLink } from './auth-card';

const closedMessage: Message = { key: 'auth.reclaim.closed' };
const hiddenMessage: Message = { key: 'auth.reclaim.hidden' };
const opaqueFailure: Message = { key: 'auth.reclaim.opaque' };

function recoveryError(failure: unknown): Message {
  if (failure instanceof PortalError) {
    if (failure.code === 'invalid_token' || failure.code === 'invalid_credentials')
      return opaqueFailure;
    if (failure.status === 429 || failure.code === 'rate_limited')
      return { key: 'auth.reclaim.rateLimited' };
    if (
      ['unsupported', 'cancelled', 'authenticator_security', 'user_verification_required'].includes(
        failure.code
      )
    )
      return errorMessage(failure, 'webauthn');
  }
  return { key: 'auth.reclaim.unavailable' };
}

type Phase = 'loading' | 'ready' | 'working' | 'factor' | 'closed' | 'confirmed' | 'unconfirmed';
type Outcome = 'confirmed' | 'unconfirmed';

export function AccountRecovery() {
  const t = useTranslations();
  const message = useMessage();
  const [phase, setPhase] = useState<Phase>('loading');
  const [factor, setFactor] = useState<'webauthn' | 'totp' | null>(null);
  const [pending, setPending] = useState<Message>('');
  const [error, setError] = useState<Message>('');
  const [codeError, setCodeError] = useState<Message>('');
  const link = useRef<{ token: string; deadline: number; monotonicDeadline: number } | null>(null);
  const captured = useRef(false);
  const alive = useRef(false);
  const generation = useRef(0);
  const terminal = useRef<Outcome | null>(null);
  const client = useRef<ReclaimClient | null>(null);
  const active = useRef<{ controller: AbortController; sent: boolean } | null>(null);
  const challenge = useRef<ReclaimOptions | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const factorView = useRef<HTMLDivElement>(null);
  const outcomeHeading = useRef<HTMLHeadingElement>(null);
  const id = useId();

  const clearWork = useCallback(() => {
    const work = active.current;
    active.current = null;
    work?.controller.abort();
    challenge.current = null;
    if (input.current) input.current.value = '';
    if (factorView.current) factorView.current.hidden = true;
    if (alive.current) {
      setFactor(null);
      setCodeError('');
      setPending('');
    }
  }, []);

  const finish = useCallback(
    (outcome: Outcome) => {
      if (terminal.current) return;
      terminal.current = outcome;
      link.current = null;
      clearWork();
      if (alive.current) {
        setError('');
        setPhase(outcome);
      }
    },
    [clearWork]
  );

  const discard = useCallback(
    (message: Message, forget: boolean) => {
      if (active.current?.sent) {
        finish('unconfirmed');
        return;
      }
      if (forget) link.current = null;
      clearWork();
      if (alive.current && !terminal.current) {
        setPhase(link.current ? 'ready' : 'closed');
        setError(message);
      }
    },
    [clearWork, finish]
  );

  useEffect(() => {
    alive.current = true;
    const mountedGeneration = ++generation.current;
    if (!captured.current) {
      captured.current = true;
      const fragment = window.location.hash;
      const hasQuery = Boolean(window.location.search);
      const now = Date.now();
      const monotonicNow = performance.now();
      try {
        // Scrub before parsing, creating transport, or allowing any user action.
        // No token is put in history state, React state, storage, or navigation.
        window.history.replaceState(null, '', window.location.pathname);
        const token = fragment.startsWith('#token=') ? fragment.slice(7) : undefined;
        if (!hasQuery && isReclaimToken(token))
          link.current = {
            token,
            deadline: now + 300000,
            monotonicDeadline: monotonicNow + 300000,
          };
      } catch {
        link.current = null;
      }
    }
    client.current = new ReclaimClient();
    setPhase(link.current ? 'ready' : 'closed');
    setError(link.current ? '' : closedMessage);
    const token = link.current;
    const timer = token
      ? setTimeout(
          () => discard(closedMessage, true),
          Math.max(
            0,
            Math.min(token.deadline - Date.now(), token.monotonicDeadline - performance.now())
          )
        )
      : undefined;
    function visibility() {
      const value = link.current;
      if (value && (Date.now() >= value.deadline || performance.now() >= value.monotonicDeadline))
        discard(closedMessage, true);
      else if (document.visibilityState === 'hidden') discard(hiddenMessage, false);
    }
    function pagehide() {
      discard(closedMessage, true);
    }
    function changedLocation() {
      try {
        if (window.location.pathname === '/recover-account')
          window.history.replaceState(null, '', window.location.pathname);
      } catch {
        // A browser that refuses URL scrubbing must not continue recovery.
      }
      discard(closedMessage, true);
    }
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('popstate', changedLocation);
    window.addEventListener('hashchange', changedLocation);
    return () => {
      alive.current = false;
      if (active.current?.sent) terminal.current = 'unconfirmed';
      clearWork();
      client.current = null;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('pagehide', pagehide);
      window.removeEventListener('popstate', changedLocation);
      window.removeEventListener('hashchange', changedLocation);
      // StrictMode replays effects synchronously. Defer only token disposal for
      // that replay; a real unmount forgets it in this microtask, never in storage.
      queueMicrotask(() => {
        if (generation.current === mountedGeneration) link.current = null;
      });
    };
  }, [clearWork, discard]);

  useEffect(() => {
    if (phase === 'confirmed' || phase === 'unconfirmed') outcomeHeading.current?.focus();
    else if (phase === 'factor' && factor === 'totp') input.current?.focus();
  }, [phase, factor]);

  function usableLink(): boolean {
    const value = link.current;
    if (!value || Date.now() >= value.deadline || performance.now() >= value.monotonicDeadline) {
      discard(closedMessage, true);
      return false;
    }
    if (document.visibilityState === 'hidden') {
      discard(hiddenMessage, false);
      return false;
    }
    return true;
  }

  async function start() {
    if (active.current || terminal.current || !client.current || !usableLink() || !link.current)
      return;
    const work = { controller: new AbortController(), sent: false };
    active.current = work;
    setPhase('working');
    setError('');
    setPending({ key: 'auth.reclaim.preparing' });
    try {
      const options = await client.current.options(link.current.token, work.controller.signal);
      throwIfAborted(work.controller.signal);
      if (active.current !== work || !usableLink()) return;
      challenge.current = options;
      setFactor(options.factor);
      setPhase('factor');
    } catch (failure) {
      if (active.current === work && !work.controller.signal.aborted && !isAborted(failure)) {
        setPhase('ready');
        setError(recoveryError(failure));
      }
    } finally {
      if (active.current === work) {
        active.current = null;
        setPending('');
      }
    }
  }

  async function recover() {
    if (
      active.current ||
      terminal.current ||
      !challenge.current ||
      !client.current ||
      !usableLink() ||
      !link.current
    )
      return;
    const selected = challenge.current;
    let code = input.current?.value ?? '';
    if (selected.factor === 'totp' && (code.length !== 6 || !/^[0-9]{6}$/.test(code))) {
      setCodeError({ key: 'auth.reclaim.codeError' });
      input.current?.focus();
      return;
    }
    const work = { controller: new AbortController(), sent: false };
    const { signal } = work.controller;
    active.current = work;
    challenge.current = null;
    setPhase('working');
    setError('');
    setCodeError('');
    setPending(
      selected.factor === 'webauthn'
        ? { key: 'auth.reclaim.passkeyPending' }
        : { key: 'auth.reclaim.codePending' }
    );
    if (input.current) input.current.value = '';
    try {
      let proof: ReclaimProof;
      if (selected.factor === 'webauthn') {
        const assertion = await usePasskey(selected.webauthn, signal, false, true);
        throwIfAborted(signal);
        if (!usableLink() || !link.current) return;
        proof = { token: link.current.token, factor: 'webauthn', assertion };
      } else proof = { token: link.current.token, factor: 'totp', code };
      code = '';
      await client.current.complete(proof, signal, () => {
        work.sent = true;
      });
      throwIfAborted(signal);
      if (active.current === work) finish('confirmed');
    } catch (failure) {
      if (active.current !== work) return;
      if (
        work.sent &&
        (signal.aborted ||
          isAborted(failure) ||
          !(failure instanceof PortalError) ||
          failure.uncertain ||
          failure.status >= 500)
      )
        finish('unconfirmed');
      else if (!signal.aborted && !isAborted(failure)) {
        setFactor(null);
        setPhase('ready');
        setError(recoveryError(failure));
      }
    } finally {
      code = '';
      if (active.current === work) {
        active.current = null;
        setPending('');
      }
    }
  }

  const completed = phase === 'confirmed' || phase === 'unconfirmed';
  return (
    <div className="space-y-5" data-testid="account-recovery">
      <Feedback error={error} status={pending} />
      {completed ? (
        <div className="space-y-4" data-testid="reclaim-outcome" data-outcome={phase}>
          <h2
            ref={outcomeHeading}
            tabIndex={-1}
            className="text-lg font-semibold focus:outline-none"
          >
            {phase === 'confirmed'
              ? t('auth.reclaim.confirmedTitle')
              : t('auth.reclaim.unconfirmedTitle')}
          </h2>
          <p role="status" className="text-sm leading-relaxed">
            {phase === 'confirmed' ? t('auth.reclaim.confirmed') : t('auth.reclaim.unconfirmed')}
          </p>
          {phase === 'confirmed' && <AuthLink href="/login">{t('auth.reclaim.signIn')}</AuthLink>}
        </div>
      ) : (
        <>
          <p className="text-sm leading-relaxed text-muted-foreground">{t('auth.reclaim.intro')}</p>
          {factor ? (
            <div ref={factorView} className="space-y-4">
              {factor === 'webauthn' ? (
                <>
                  <p className="text-sm leading-relaxed">{t('auth.reclaim.passkeyHint')}</p>
                  <Button
                    type="button"
                    className={`${controlClass} w-full`}
                    disabled={Boolean(pending)}
                    onClick={recover}
                  >
                    {t('auth.reclaim.passkey')}
                  </Button>
                </>
              ) : (
                <form
                  method="post"
                  aria-label={t('auth.reclaim.form')}
                  noValidate
                  onSubmit={(event) => {
                    event.preventDefault();
                    void recover();
                  }}
                  className="space-y-3"
                >
                  <Label htmlFor={`${id}-code`}>{t('auth.reclaim.code')}</Label>
                  <Input
                    ref={input}
                    id={`${id}-code`}
                    name="reclaim-code"
                    dir="ltr"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    required
                    disabled={Boolean(pending)}
                    aria-invalid={Boolean(codeError)}
                    aria-describedby={`${id}-hint${codeError ? ` ${id}-error` : ''}`}
                    onChange={() => setCodeError('')}
                    className={`${inputClass} font-mono tracking-widest`}
                  />
                  <p id={`${id}-hint`} className="text-sm leading-relaxed text-muted-foreground">
                    {t('auth.reclaim.codeHint')}
                  </p>
                  {codeError && (
                    <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
                      {message(codeError)}
                    </p>
                  )}
                  <Button
                    type="submit"
                    className={`${controlClass} w-full`}
                    disabled={Boolean(pending)}
                  >
                    {t('auth.reclaim.recover')}
                  </Button>
                </form>
              )}
            </div>
          ) : (
            <Button
              type="button"
              className={`${controlClass} w-full`}
              disabled={phase !== 'ready'}
              onClick={start}
            >
              {t('auth.reclaim.start')}
            </Button>
          )}
          {(factor || pending) && (
            <Button
              type="button"
              variant="outline"
              className={`${controlClass} w-full`}
              onClick={() => discard({ key: 'auth.reclaim.cancelled' }, false)}
            >
              {t('auth.reclaim.cancel')}
            </Button>
          )}
        </>
      )}
      <noscript>
        <p className="text-sm">{t('auth.reclaim.noScript')}</p>
      </noscript>
    </div>
  );
}
