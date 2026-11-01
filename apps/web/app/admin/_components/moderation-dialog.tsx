'use client';

import { Button, Label } from '@hatef/ui';
import { useEffect, useId, useRef, useState } from 'react';
import { controlClass, inputClass } from '../../_components/controls';
import { StepUpDialog } from '../../_components/step-up-dialog';
import { usePortal } from '../../_components/portal-provider';
import { AdminClient } from '../../_lib/admin/client';
import type { AdminModerationStatus, AdminUser } from '../../_lib/admin/contracts';
import { normalizeModerationReason } from '../../_lib/admin/validation';
import type { StepUpGrant } from '../../_lib/portal/contracts';
import { isAborted, PortalError, throwIfAborted } from '../../_lib/portal/errors';

export type ModerationStatus = AdminModerationStatus;
export type ModerationOutcome =
  | { kind: 'cancelled' | 'confirmed' | 'conflict' | 'unconfirmed' | 'expired' }
  | { kind: 'failed'; error: unknown };

export const moderationLabel: Record<ModerationStatus, string> = {
  active: 'Reactivate',
  suspended: 'Suspend',
  banned: 'Ban',
};

export function canModerate(user: AdminUser, actorID: string): boolean {
  return (
    user.id !== actorID &&
    !user.deleted_at &&
    (user.status === 'active' || user.status === 'suspended' || user.status === 'banned')
  );
}

export function ModerationDialog({
  target,
  desiredStatus,
  resumeTotp,
  onOutcome,
}: {
  target: AdminUser;
  desiredStatus: ModerationStatus;
  resumeTotp: boolean;
  onOutcome: (outcome: ModerationOutcome) => void;
}) {
  const { client, profile, capabilities, reportPermissionLoss, reportModerationInterruption } =
    usePortal();
  const [deadline, setDeadline] = useState<number | null>(null);
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const input = useRef<HTMLTextAreaElement>(null);
  const id = useId();
  const settled = useRef(false);
  const waiting = useRef<{
    grant: StepUpGrant;
    signal: AbortSignal;
    sent: boolean;
    denial?: PortalError;
    submitting: boolean;
    finish: () => void;
    timer: ReturnType<typeof setTimeout>;
  } | null>(null);

  useEffect(() => {
    const editor = input.current;
    if (deadline) editor?.focus();
    return () => {
      if (editor) editor.value = '';
    };
  }, [deadline]);

  useEffect(() => {
    return () => {
      const operation = waiting.current;
      waiting.current = null;
      if (input.current) input.current.value = '';
      if (!operation) return;
      clearTimeout(operation.timer);
      operation.grant.clear();
      operation.finish();
      if (operation.denial) {
        if (client.profile && document.visibilityState !== 'hidden') reportPermissionLoss();
      } else if (operation.sent && !settled.current) reportModerationInterruption();
    };
  }, [client, reportModerationInterruption, reportPermissionLoss]);

  function finish(outcome: ModerationOutcome) {
    if (settled.current) return;
    settled.current = true;
    const operation = waiting.current;
    waiting.current = null;
    if (operation?.denial) outcome = { kind: 'failed', error: operation.denial };
    if (operation) {
      clearTimeout(operation.timer);
      operation.grant.clear();
      operation.finish();
    }
    if (input.current) input.current.value = '';
    setReason('');
    setAcknowledged(false);
    if (outcome.kind === 'unconfirmed') reportModerationInterruption();
    onOutcome(outcome);
    // Suspension or independent session loss already owns provider revalidation.
    if (operation?.denial && client.profile && document.visibilityState !== 'hidden')
      reportPermissionLoss();
  }

  function cancel() {
    finish({ kind: waiting.current?.sent ? 'unconfirmed' : 'cancelled' });
  }

  async function authorized(grant: StepUpGrant, signal: AbortSignal) {
    try {
      const current = await new AdminClient(client).user(target.id, signal);
      throwIfAborted(signal);
      if (settled.current) return;
      if (
        current.lifecycle_revision !== target.lifecycle_revision ||
        current.status !== target.status ||
        !canModerate(current, profile.id)
      ) {
        finish({ kind: 'conflict' });
        return;
      }
      if (Date.now() >= grant.deadline) {
        finish({ kind: 'expired' });
        return;
      }
      // The shared dialog retains and clears the grant in its finally block.
      // Do not return from this callback while the final form owns authority.
      await new Promise<void>((resolve) => {
        const timer = setTimeout(
          () => finish({ kind: waiting.current?.sent ? 'unconfirmed' : 'expired' }),
          Math.max(0, grant.deadline - Date.now())
        );
        waiting.current = { grant, signal, sent: false, submitting: false, finish: resolve, timer };
        setDeadline(grant.deadline);
      });
    } catch (failure) {
      if (signal.aborted || settled.current || isAborted(failure)) return;
      finish({ kind: 'failed', error: failure });
      if (failure instanceof PortalError && failure.status === 403) reportPermissionLoss();
    }
  }

  async function submit() {
    const operation = waiting.current;
    if (!operation || operation.submitting || settled.current || !acknowledged) return;
    let narrative: string;
    try {
      narrative = normalizeModerationReason(reason);
    } catch {
      setReasonError('Enter a reason using no more than 2,000 UTF-8 bytes.');
      input.current?.focus();
      return;
    }
    if (Date.now() >= operation.grant.deadline) {
      finish({ kind: 'expired' });
      return;
    }
    operation.submitting = true;
    setSubmitting(true);
    setReasonError('');
    try {
      await new AdminClient(client).updateStatus(
        target.id,
        { status: desiredStatus, reason: narrative, expected_revision: target.lifecycle_revision },
        operation.grant,
        operation.signal,
        () => {
          throwIfAborted(operation.signal);
          if (waiting.current !== operation) throw new DOMException('Cancelled', 'AbortError');
          operation.sent = true;
        }
      );
      if (waiting.current !== operation || settled.current) return;
      finish({ kind: operation.signal.aborted ? 'unconfirmed' : 'confirmed' });
    } catch (failure) {
      if (waiting.current !== operation || settled.current) return;
      if (
        operation.sent &&
        !(failure instanceof PortalError && failure.status === 403) &&
        (operation.signal.aborted ||
          isAborted(failure) ||
          !(failure instanceof PortalError) ||
          failure.uncertain ||
          failure.status >= 500)
      ) {
        finish({ kind: 'unconfirmed' });
      } else if (
        failure instanceof PortalError &&
        failure.status === 409 &&
        failure.code === 'account_conflict'
      ) {
        finish({ kind: 'conflict' });
      } else {
        let permissionLost = false;
        if (failure instanceof PortalError && failure.status === 403) {
          // Only a capability read remains; interruption cannot undo this known denial.
          operation.denial = failure;
          // A protected-target denial is deliberately indistinguishable from a
          // permissions denial, including an unreadable error body. Recheck all
          // our own flags so independent PII/lookup loss cannot retain old views.
          try {
            const current = await new AdminClient(client).capabilities(operation.signal);
            throwIfAborted(operation.signal);
            const previous = capabilities?.capabilities;
            permissionLost =
              !previous ||
              Object.entries(previous).some(
                ([key, granted]) => granted && !current.capabilities[key as keyof typeof previous]
              );
          } catch {
            permissionLost = true;
          }
        }
        if (waiting.current !== operation || settled.current) return;
        operation.denial = undefined;
        // Settle the known denial before clearing the shared view; cancellation
        // of an already rejected request must not become an uncertain outcome.
        finish({ kind: 'failed', error: failure });
        if (permissionLost) reportPermissionLoss();
      }
    }
  }

  return (
    <StepUpDialog
      title={`${moderationLabel[desiredStatus]} account`}
      description={
        <div className="space-y-3">
          <p>
            Account <span className="break-all font-mono text-foreground">{target.id}</span>
          </p>
          <p>
            Current status: <strong>{target.status}</strong>. Proposed status:{' '}
            <strong>{desiredStatus}</strong>.
          </p>
          <p>
            Suspension and ban remain until explicit restoration. They are not erasure and do not
            prevent re-registration. Subsequent live credential checks reject old credentials;
            already admitted requests and offline JWT consumers may retain bounded residual access.
            Reactivation never restores old credentials.
          </p>
          <p>
            Verify first, then enter the reason and explicitly confirm. Cancel before sending to
            make no change.
          </p>
        </div>
      }
      onCancel={cancel}
      onAuthorized={authorized}
      intent={{ kind: 'moderation', status: desiredStatus }}
      resumeMethod={resumeTotp ? 'totp' : undefined}
      verifiedStatus={
        submitting
          ? 'Sending status change. Do not submit again.'
          : deadline
            ? 'Verification complete. Enter a reason and review the final confirmation before verification expires.'
            : 'Verification complete. Checking the pinned account before final confirmation.'
      }
      verifiedContent={
        deadline && (
          <form
            aria-label="Confirm account status change"
            className="space-y-4"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <p className="text-sm">
              Confirm <strong>{target.status}</strong> to <strong>{desiredStatus}</strong> for the
              account above, at revision{' '}
              <span className="break-all font-mono">{target.lifecycle_revision}</span>.
            </p>
            <p className="text-sm text-muted-foreground">
              Single-use verification expires at{' '}
              <time dateTime={new Date(deadline).toISOString()}>
                {new Date(deadline).toLocaleTimeString()}
              </time>
              . Expiry or leaving this page clears the reason and requires fresh verification.
            </p>
            <div className="space-y-2">
              <Label htmlFor={`${id}-reason`}>Moderation reason</Label>
              <textarea
                ref={input}
                id={`${id}-reason`}
                name="moderation-reason"
                value={reason}
                autoComplete="off"
                spellCheck={false}
                maxLength={2000}
                rows={4}
                disabled={submitting}
                onChange={(event) => {
                  setReason(event.target.value);
                  setReasonError('');
                }}
                aria-invalid={Boolean(reasonError)}
                aria-describedby={`${id}-hint${reasonError ? ` ${id}-error` : ''}`}
                className={`${inputClass} min-h-28 w-full resize-y rounded-md border bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring`}
              />
              <p id={`${id}-hint`} className="text-sm text-muted-foreground">
                Required for every action. At most 2,000 UTF-8 bytes; avoid unnecessary personal
                information.
              </p>
              {reasonError && (
                <p id={`${id}-error`} role="alert" className="text-sm text-destructive">
                  {reasonError}
                </p>
              )}
            </div>
            <label className="flex min-h-11 items-start gap-3 rounded-md py-2 text-sm leading-relaxed">
              <input
                type="checkbox"
                checked={acknowledged}
                disabled={submitting}
                onChange={(event) => setAcknowledged(event.target.checked)}
                className="mt-1 size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
              I reviewed the account, current status, new status, and consequences of this action.
            </label>
            <Button
              type="submit"
              className={`${controlClass} w-full`}
              disabled={!acknowledged || submitting}
            >
              {submitting
                ? 'Submitting status change...'
                : `Confirm ${moderationLabel[desiredStatus].toLowerCase()}`}
            </Button>
          </form>
        )
      }
    />
  );
}
