import { AccountRecovery } from '../_components/account-recovery';
import { AuthCard } from '../_components/auth-card';

export const metadata = {
  title: 'Recover your account | Hatef Identity',
  robots: { index: false, follow: false },
};

export default function RecoverAccountPage() {
  return (
    <AuthCard
      title="Recover your account"
      description="Cancel a pending account deletion using the recovery link from your email and strong verification."
      footer="Recovery does not sign you in or restore old sessions."
    >
      <AccountRecovery />
    </AuthCard>
  );
}
