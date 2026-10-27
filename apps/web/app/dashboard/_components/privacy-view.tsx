'use client';

import { Button, Label } from '@hatef/ui';
import { useId, useRef, useState } from 'react';
import { errorMessage } from '../../_lib/portal/errors';
import { controlClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';
import { StepUpDialog } from './step-up-dialog';

export function PrivacyView() {
  const { profile, deleteAccount } = usePortal();
  const [acknowledged, setAcknowledged] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const opening = useRef(false);
  const id = useId();

  return (
    <>
      <PageHeading title="Privacy">
        Manage deletion of your identity account across the Hatef platform, not just a tenant
        membership or an account in one service.
      </PageHeading>
      <Panel title="Before you request deletion" id={`${id}-consequences`}>
        <ul className="list-disc space-y-3 pl-5 text-sm leading-relaxed">
          <li>
            Your identity account is deactivated immediately. You are signed out across the identity
            platform and existing sessions and tokens are revoked. Downstream services may take time
            to apply the change.
          </li>
          <li>
            You have 30 days from the original request to cancel deletion using an emailed recovery
            link and strong verification. The email gives the exact deadline. Retries and lawful
            preservation do not extend this window.
          </li>
          <li>
            A recovery notification is queued for your primary email and any configured backup
            email. You must still be able to access a configured mailbox after deactivation. Email
            delivery can be delayed or fail; this page cannot confirm inbox delivery.
          </li>
          <li>
            Your identifiers remain reserved until your account is purged. After the recovery
            window, account and authentication data (Class A) become eligible for deletion, subject
            to lawful preservation. Deletion is not guaranteed to finish exactly on day 30.
          </li>
        </ul>
      </Panel>
      <Panel title="What may remain" id={`${id}-retention`}>
        <p className="text-sm leading-relaxed text-muted-foreground">
          Pseudonymized security and audit records are retained separately under their applicable
          retention policies. Some records may need to be preserved for legal obligations. Backups
          expire through their rotation schedules, and downstream services have their own deletion
          and retention responsibilities. This request is not a promise of complete erasure of every
          copy or record.
        </p>
      </Panel>
      <Panel title="Delete your identity account" id={`${id}-delete`}>
        <p className="text-sm leading-relaxed text-muted-foreground">
          This action requires fresh passkey verification with a device PIN or biometrics.
          Touch-only security keys and authenticator codes cannot authorize deletion. Cancelling
          verification before the deletion request is sent leaves your account unchanged.
        </p>
        {!profile.deletion_enabled && (
          <p role="status" className="rounded-md border bg-muted/40 p-4 text-sm leading-relaxed">
            Account deletion is currently unavailable. New requests remain disabled until the
            service is ready and access to recovery email after deactivation is assured. Existing
            recovery links can still be used within their original deadline.
          </p>
        )}
        <div className="flex items-start gap-3">
          <input
            id={`${id}-acknowledge`}
            type="checkbox"
            checked={acknowledged}
            disabled={!profile.deletion_enabled || confirm}
            onChange={(event) => setAcknowledged(event.target.checked)}
            aria-describedby={`${id}-acknowledgement-hint`}
            className="mt-3 size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          />
          <Label
            htmlFor={`${id}-acknowledge`}
            className="flex min-h-11 items-center text-sm leading-relaxed"
          >
            I understand the account-deletion consequences and the 30-day recovery window.
          </Label>
        </div>
        <p id={`${id}-acknowledgement-hint`} className="text-sm text-muted-foreground">
          This acknowledgement is not consent to retention or a waiver of your rights.
        </p>
        <Button
          type="button"
          variant="destructive"
          className={controlClass}
          disabled={!profile.deletion_enabled || !acknowledged || confirm}
          onClick={() => {
            if (!profile.deletion_enabled || !acknowledged || opening.current) return;
            opening.current = true;
            setConfirm(true);
          }}
        >
          Delete my account
        </Button>
      </Panel>
      {confirm && (
        <StepUpDialog
          title="Confirm account deletion"
          description="Verify with your passkey to request deletion of this identity account. Once the request is sent, cancelling or closing this page cannot undo it. Recovery uses the emailed link within the original recovery window."
          mode="webauthn-only"
          onAuthorized={deleteAccount}
          actionError={(failure) => errorMessage(failure, 'webauthn')}
          onCancel={() => {
            opening.current = false;
            setConfirm(false);
            setAcknowledged(false);
          }}
        />
      )}
    </>
  );
}
