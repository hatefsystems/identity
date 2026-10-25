'use client';

import { PageHeading } from './controls';
import { PasskeysPanel } from './passkeys-panel';
import { RecoveryPanel } from './recovery-panel';

export function SecurityView() {
  return (
    <>
      <PageHeading title="Security">
        Review your sign-in credentials. Sensitive changes require fresh passkey or enrolled
        authenticator verification.
      </PageHeading>
      <PasskeysPanel />
      <RecoveryPanel />
    </>
  );
}
