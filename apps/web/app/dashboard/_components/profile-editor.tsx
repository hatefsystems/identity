'use client';

import type { Message } from '../../../i18n/messages';
import { useMessage } from '../../../i18n/use-message';

import { useTranslations } from 'next-intl';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { normalizeName } from '../../_lib/portal/validation';
import { controlClass, Feedback, inputClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';

export function ProfileEditor() {
  const t = useTranslations();
  const message = useMessage();
  const { client, profile, updateProfile } = usePortal();
  const [saved, setSaved] = useState(profile);
  const [draft, setDraft] = useState(profile.display_name);
  const [pending, setPending] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [error, setError] = useState<Message>('');
  const [nameError, setNameError] = useState<Message>('');
  const [status, setStatus] = useState<Message>('');
  const operation = useRef<AbortController | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const id = useId();
  useEffect(
    () => () => {
      operation.current?.abort();
    },
    []
  );

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (operation.current || conflict) return;
    let name: string;
    try {
      name = normalizeName(draft);
    } catch (failure) {
      setNameError(errorMessage(failure));
      input.current?.focus();
      return;
    }
    const controller = new AbortController();
    operation.current = controller;
    setPending(true);
    setError('');
    setStatus({ key: 'portal.profile.saving' });
    setNameError('');
    try {
      const result = await client.saveProfile(name, saved.lifecycle_revision, controller.signal);
      throwIfAborted(controller.signal);
      setSaved(result);
      setDraft(result.display_name);
      updateProfile(result);
      setStatus({ key: 'portal.profile.saved' });
    } catch (failure) {
      if (!controller.signal.aborted && !isAborted(failure)) {
        setConflict(failure instanceof PortalError && failure.code === 'profile_conflict');
        setError(errorMessage(failure));
        setStatus('');
      }
    } finally {
      if (operation.current === controller) operation.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }

  async function refresh() {
    if (operation.current) return;
    const controller = new AbortController();
    operation.current = controller;
    setPending(true);
    setError('');
    setStatus({ key: 'portal.profile.refreshing' });
    try {
      const result = await client.bootstrap(controller.signal);
      throwIfAborted(controller.signal);
      setSaved(result);
      updateProfile(result);
      setConflict(false);
      // Never replace the unsaved draft with a conflict refresh.
      setStatus({ key: 'portal.profile.refreshed' });
    } catch (failure) {
      if (!controller.signal.aborted && !isAborted(failure)) {
        setError(errorMessage(failure));
        setStatus('');
      }
    } finally {
      if (operation.current === controller) operation.current = null;
      if (!controller.signal.aborted) setPending(false);
    }
  }

  return (
    <>
      <PageHeading title={t('portal.profile.title')}>{t('portal.profile.description')}</PageHeading>
      <Panel title={t('portal.profile.panel')} id="profile-editor">
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">{t('portal.overview.email')}</dt>
            <dd dir="ltr" className="mt-1 break-all font-medium isolate">
              {saved.email}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t('portal.overview.status')}</dt>
            <dd className="mt-1 font-medium">
              {(['active', 'disabled', 'suspended', 'pending_deletion'] as const)
                .map((value) => (value === saved.status ? t(`portal.status.${value}`) : ''))
                .join('') || saved.status}
            </dd>
          </div>
        </dl>
        <form
          noValidate
          aria-label={t('portal.profile.form')}
          onSubmit={save}
          className="space-y-4"
        >
          <div className="space-y-2">
            <Label htmlFor={id}>{t('portal.profile.name')}</Label>
            <Input
              ref={input}
              id={id}
              name="display_name"
              dir="auto"
              autoComplete="nickname"
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
                setNameError('');
                setStatus('');
              }}
              disabled={pending}
              aria-invalid={Boolean(nameError)}
              aria-describedby={`${id}-hint${nameError ? ` ${id}-error` : ''}`}
              className={inputClass}
            />
            <p id={`${id}-hint`} className="text-sm text-muted-foreground">
              {t('portal.profile.hint')}
            </p>
            {nameError && (
              <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
                {message(nameError)}
              </p>
            )}
          </div>
          <Feedback error={error} status={status} />
          {conflict && <p className="text-sm">{t('portal.profile.conflict')}</p>}
          <p className="break-words text-sm text-muted-foreground">
            {t.rich('portal.profile.current', {
              name: () => (
                <bdi
                  className="font-medium text-foreground"
                  data-testid="saved-display-name"
                  dir="auto"
                >
                  {saved.display_name || t('portal.profile.notSet')}
                </bdi>
              ),
            })}
          </p>
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending || conflict}>
              {t('portal.profile.save')}
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={refresh}
              disabled={pending}
            >
              {t('portal.profile.refresh')}
            </Button>
          </div>
        </form>
      </Panel>
    </>
  );
}
