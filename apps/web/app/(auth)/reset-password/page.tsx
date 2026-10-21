import { AuthCard, AuthLink } from '../_components/auth-card';
import { ResetPasswordScreen } from '../_components/screens';

export const metadata = { title: 'Set a new password | Hatef Identity' };

export default function ResetPasswordPage() {
  return (
    <AuthCard
      title="Set a new password"
      description="Choose a new password for your account. Reset-link verification is not connected yet."
      footer={<AuthLink href="/login">Return to sign in</AuthLink>}
    >
      <ResetPasswordScreen />
    </AuthCard>
  );
}
