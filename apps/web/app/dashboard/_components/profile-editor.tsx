'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { normalizeName } from '../../_lib/portal/validation';
import { controlClass, Feedback, inputClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';

export function ProfileEditor() {
  const { client, profile, updateProfile } = usePortal();
  const [saved, setSaved] = useState(profile);
  const [draft, setDraft] = useState(profile.display_name);
  const [pending, setPending] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [error, setError] = useState('');
  const [nameError, setNameError] = useState('');
  const [status, setStatus] = useState('');
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
      setNameError((failure as Error).message);
      input.current?.focus();
      return;
    }
    const controller = new AbortController();
    operation.current = controller;
    setPending(true);
    setError('');
    setStatus('Saving your profile...');
    setNameError('');
    try {
      const result = await client.saveProfile(name, saved.lifecycle_revision, controller.signal);
      throwIfAborted(controller.signal);
      setSaved(result);
      setDraft(result.display_name);
      updateProfile(result);
      setStatus('Profile saved.');
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
    setStatus('Refreshing the saved profile...');
    try {
      const result = await client.bootstrap(controller.signal);
      throwIfAborted(controller.signal);
      setSaved(result);
      updateProfile(result);
      setConflict(false);
      // Never replace the unsaved draft with a conflict refresh.
      setStatus('Saved profile refreshed. Your draft has not changed. Review it before saving.');
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
      <PageHeading title="Profile">
        Your display name is shared with supported Hatef services. Primary email and account status
        are read-only here.
      </PageHeading>
      <Panel title="Shared profile" id="profile-editor">
        <dl className="grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">Primary email</dt>
            <dd className="mt-1 break-all font-medium">{saved.email}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Account status</dt>
            <dd className="mt-1 font-medium">{saved.status}</dd>
          </div>
        </dl>
        <form noValidate aria-label="Edit profile" onSubmit={save} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={id}>Display name</Label>
            <Input
              ref={input}
              id={id}
              name="display_name"
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
              Up to 80 characters on one line. Leave empty to clear your display name.
            </p>
            {nameError && (
              <p id={`${id}-error`} className="text-sm text-red-700 dark:text-red-400">
                {nameError}
              </p>
            )}
          </div>
          <Feedback error={error} status={status} />
          {conflict && (
            <p className="text-sm">
              Your draft is preserved. Refresh the current saved name and revision before saving
              again.
            </p>
          )}
          <p className="break-words text-sm text-muted-foreground">
            Current saved name:{' '}
            <span className="font-medium text-foreground" data-testid="saved-display-name">
              {saved.display_name || 'Not set'}
            </span>
          </p>
          <div className="flex flex-wrap gap-3">
            <Button type="submit" className={controlClass} disabled={pending || conflict}>
              Save profile
            </Button>
            <Button
              type="button"
              variant="outline"
              className={controlClass}
              onClick={refresh}
              disabled={pending}
            >
              Refresh saved profile
            </Button>
          </div>
        </form>
      </Panel>
    </>
  );
}
