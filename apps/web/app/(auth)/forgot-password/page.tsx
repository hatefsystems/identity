import { AuthCard, AuthLink } from '../_components/auth-card';
import { ForgotPasswordScreen } from '../_components/screens';

export const metadata = { title: 'Reset your password | Hatef Identity' };

export default function ForgotPasswordPage() {
  return (
    <AuthCard
      title="Reset your password"
      description="Enter your primary email address to request a password reset link."
      footer={<AuthLink href="/login">Return to sign in</AuthLink>}
    >
      <ForgotPasswordScreen />
    </AuthCard>
  );
}
