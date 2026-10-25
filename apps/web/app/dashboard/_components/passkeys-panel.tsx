'use client';

import { Button, Input, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState } from 'react';
import type { Passkey, StepUpGrant } from '../../_lib/portal/contracts';
import type { PasskeyAction } from '../../_lib/portal/action-intent';
import { errorMessage, isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';
import { normalizeName } from '../../_lib/portal/validation';
import { sensitiveClearEvent } from '../../_lib/portal/invalidation';
import { usePasskey } from '../../_lib/portal/webauthn';
import { controlClass, DateLabel, Feedback, inputClass, Panel } from './controls';
import { usePortal } from './portal-provider';
import { StepUpDialog } from './step-up-dialog';

export function PasskeysPanel() {
  const { client, resumedAction } = usePortal();
  const [keys, setKeys] = useState<Passkey[] | null>(null);
  const [name, setName] = useState('');
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);
  const [nameError, setNameError] = useState('');
  const [editError, setEditError] = useState('');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [action, setAction] = useState<PasskeyAction | null>(null);
  const [resumeTotp, setResumeTotp] = useState(false);
  const resume = useRef(resumedAction?.kind === 'passkey' ? resumedAction.action : null);
  const [attempt, setAttempt] = useState(0);
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const blocked = useRef(false);
  const mutation = useRef<{ sent: boolean } | null>(null);
  const read = useRef<AbortController | null>(null);
  const readGeneration = useRef(0);
  const pinned = useRef<PasskeyAction | null>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const editInput = useRef<HTMLInputElement>(null);
  const id = useId();

  useEffect(() => {
    const clearResume = () => {
      resume.current = null;
    };
    window.addEventListener(sensitiveClearEvent, clearResume);
    return () => window.removeEventListener(sensitiveClearEvent, clearResume);
  }, []);

  function invalidateRead() {
    readGeneration.current++;
    read.current?.abort();
    read.current = null;
  }

  useEffect(() => {
    const controller = new AbortController();
    const generation = ++readGeneration.current;
    read.current = controller;
    setError('');
    setStatus('Loading passkeys...');
    client
      .keys(controller.signal)
      .then((items) => {
        throwIfAborted(controller.signal);
        if (generation !== readGeneration.current) return;
        setKeys(items);
        blocked.current = false;
        setNeedsRefresh(false);
        setStatus(attempt ? 'Passkeys refreshed.' : '');
        const pending = resume.current;
        resume.current = null;
        if (pending) {
          const target =
            pending.kind === 'add' ? undefined : items.find((item) => item.id === pending.id);
          if (pending.kind !== 'add' && !target) {
            setError(
              'The passkey for the pending action is no longer listed. Choose a current passkey to continue.'
            );
          } else {
            const restored =
              pending.kind === 'remove' ? { ...pending, name: target?.name ?? '' } : pending;
            pinned.current = restored;
            setAction(restored);
            setResumeTotp(true);
          }
        }
      })
      .catch((failure) => {
        if (
          generation === readGeneration.current &&
          !controller.signal.aborted &&
          !isAborted(failure)
        ) {
          setError(errorMessage(failure));
          setStatus('');
        }
      });
    return () => controller.abort();
  }, [client, attempt]);

  function open(value: PasskeyAction) {
    if (pinned.current || blocked.current) return;
    pinned.current = value;
    setAction(value);
    setResumeTotp(false);
    setError('');
    setStatus('');
  }
  function close() {
    if (mutation.current?.sent) {
      invalidateRead();
      blocked.current = true;
      setNeedsRefresh(true);
      setError('');
      setStatus('');
    }
    mutation.current = null;
    pinned.current = null;
    setAction(null);
    setResumeTotp(false);
  }

  function add() {
    try {
      open({ kind: 'add', name: normalizeName(name) });
      setNameError('');
    } catch (failure) {
      setNameError((failure as Error).message);
      nameInput.current?.focus();
    }
  }
  function rename() {
    if (!editing) return;
    try {
      open({ kind: 'rename', id: editing.id, name: normalizeName(editing.name) });
      setEditError('');
    } catch (failure) {
      setEditError((failure as Error).message);
      editInput.current?.focus();
    }
  }

  async function perform(grant: StepUpGrant, signal: AbortSignal) {
    const target = pinned.current;
    if (!target) return;
    const operation = { sent: false };
    mutation.current = operation;
    invalidateRead();
    const onSend = () => {
      operation.sent = true;
    };
    try {
      if (target.kind === 'add') {
        const options = await client.registerOptions(target.name, grant, signal);
        throwIfAborted(signal);
        const attestation = await usePasskey(options, signal, true);
        throwIfAborted(signal);
        // Starting registration spends the grant, but only verify can add a key.
        const key = await client.registerVerify(attestation, signal, onSend);
        throwIfAborted(signal);
        invalidateRead();
        setKeys((items) => [...(items ?? []), key]);
        setName('');
        setStatus('Passkey added.');
      } else if (target.kind === 'rename') {
        const key = await client.renameKey(target.id, target.name, grant, signal, onSend);
        throwIfAborted(signal);
        invalidateRead();
        setKeys((items) => items?.map((item) => (item.id === key.id ? key : item)) ?? null);
        setEditing(null);
        setStatus('Passkey name saved.');
      } else {
        await client.removeKey(target.id, grant, signal, onSend);
        throwIfAborted(signal);
        invalidateRead();
        setKeys((items) => items?.filter((item) => item.id !== target.id) ?? null);
        if (editing?.id === target.id) setEditing(null);
        setStatus('Passkey removed.');
      }
    } catch (failure) {
      if (!signal.aborted && failure instanceof PortalError && failure.uncertain) {
        operation.sent = true;
        close();
      }
      throw failure;
    } finally {
      if (mutation.current === operation) mutation.current = null;
    }
  }

  return (
    <Panel title="Passkeys" id="passkeys-heading">
      <p className="text-sm leading-relaxed text-muted-foreground">
        Names are labels you choose, not verified device models. Keep at least one passkey to retain
        sign-in access.
      </p>
      <Feedback
        error={
          needsRefresh
            ? `The passkey change may already have completed. Refresh passkeys to check the saved state before starting another action.${error ? ` ${error}` : ''}`
            : error
        }
        status={status}
      />
      {keys && (
        <ul className="divide-y rounded-lg border" aria-label="Registered passkeys">
          {keys.map((key) => (
            <li
              key={key.id}
              data-testid="passkey-row"
              data-key-id={key.id}
              className="space-y-4 p-4"
            >
              <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
                <div className="min-w-0 space-y-1">
                  <h3 className="break-words font-medium">{key.name || 'Unnamed passkey'}</h3>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    Added <DateLabel value={key.created_at} />
                    {key.last_used_at ? (
                      <>
                        . Last used <DateLabel value={key.last_used_at} />.
                      </>
                    ) : (
                      '. Not used since registration.'
                    )}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {key.backup_eligible
                      ? 'Eligible for passkey syncing'
                      : 'Not marked as sync eligible'}
                    {key.user_verified ? '. User verified at enrollment.' : '.'}
                  </p>
                </div>
                <div className="flex shrink-0 flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    className={controlClass}
                    aria-label={`Rename ${key.name || 'unnamed passkey'}`}
                    disabled={needsRefresh}
                    onClick={() => {
                      setEditing({ id: key.id, name: key.name });
                      setEditError('');
                    }}
                  >
                    Rename
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    className={controlClass}
                    aria-label={`Remove ${key.name || 'unnamed passkey'}`}
                    disabled={keys.length === 1 || needsRefresh}
                    onClick={() => open({ kind: 'remove', id: key.id, name: key.name })}
                  >
                    Remove
                  </Button>
                </div>
              </div>
              {editing?.id === key.id && (
                <form
                  aria-label="Rename passkey"
                  noValidate
                  onSubmit={(event) => {
                    event.preventDefault();
                    rename();
                  }}
                  className="space-y-3"
                >
                  <Label htmlFor={`${id}-rename`}>Passkey name</Label>
                  <Input
                    ref={editInput}
                    id={`${id}-rename`}
                    name="passkey_name"
                    value={editing.name}
                    onChange={(event) => {
                      setEditing({ ...editing, name: event.target.value });
                      setEditError('');
                    }}
                    aria-invalid={Boolean(editError)}
                    aria-describedby={editError ? `${id}-rename-error` : undefined}
                    className={inputClass}
                  />
                  {editError && (
                    <p id={`${id}-rename-error`} className="text-sm text-red-700 dark:text-red-400">
                      {editError}
                    </p>
                  )}
                  <div className="flex flex-wrap gap-2">
                    <Button type="submit" className={controlClass} disabled={needsRefresh}>
                      Save passkey name
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      className={controlClass}
                      onClick={() => setEditing(null)}
                    >
                      Cancel rename
                    </Button>
                  </div>
                </form>
              )}
            </li>
          ))}
        </ul>
      )}
      {keys?.length === 0 && <p className="text-sm">No passkeys are listed for this session.</p>}
      {keys?.length === 1 && (
        <p className="text-sm text-muted-foreground">
          Add another passkey before removing your last one.
        </p>
      )}
      <Button
        type="button"
        variant="outline"
        className={controlClass}
        disabled={Boolean(action)}
        onClick={() => {
          invalidateRead();
          setAttempt((value) => value + 1);
        }}
      >
        Refresh passkeys
      </Button>
      <form
        aria-label="Add passkey"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          add();
        }}
        className="space-y-3 border-t pt-5"
      >
        <Label htmlFor={`${id}-name`}>New passkey name</Label>
        <Input
          ref={nameInput}
          id={`${id}-name`}
          name="new_passkey_name"
          value={name}
          onChange={(event) => {
            setName(event.target.value);
            setNameError('');
          }}
          aria-invalid={Boolean(nameError)}
          aria-describedby={`${id}-hint${nameError ? ` ${id}-name-error` : ''}`}
          className={inputClass}
        />
        <p id={`${id}-hint`} className="text-sm text-muted-foreground">
          Optional, up to 80 characters. Choose a label that helps you recognize this credential.
        </p>
        {nameError && (
          <p id={`${id}-name-error`} className="text-sm text-red-700 dark:text-red-400">
            {nameError}
          </p>
        )}
        <Button type="submit" className={controlClass} disabled={!keys || needsRefresh}>
          Add passkey
        </Button>
      </form>
      {action && (
        <StepUpDialog
          title={
            action.kind === 'add'
              ? 'Add a passkey'
              : action.kind === 'rename'
                ? 'Rename passkey'
                : 'Remove passkey'
          }
          description={
            action.kind === 'remove' ? (
              <>
                Remove{' '}
                <strong className="text-foreground">{action.name || 'Unnamed passkey'}</strong> from
                this account? It will no longer be accepted for sign-in.
              </>
            ) : action.kind === 'rename' ? (
              <>
                Change this passkey label to{' '}
                <strong className="text-foreground">{action.name || '(no name)'}</strong>?
              </>
            ) : (
              <>
                Create a new sign-in credential named{' '}
                <strong className="text-foreground">{action.name || '(no name)'}</strong>. After
                verification, your authenticator will ask to create the passkey.
              </>
            )
          }
          onCancel={close}
          onAuthorized={perform}
          intent={{ kind: 'passkey', action }}
          resumeMethod={resumeTotp ? 'totp' : undefined}
        />
      )}
    </Panel>
  );
}
