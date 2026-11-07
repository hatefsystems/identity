import { RegistrationEmailVerification } from '../../../_components/registration';
import { AuthCard, AuthLink } from '../../_components/auth-card';

export const metadata = {
  title: 'Verify registration email | Hatef Identity',
  referrer: 'no-referrer' as const,
};

export default function VerifyRegistrationEmailPage() {
  return (
    <AuthCard
      title="Verify your email ownership"
      description="Confirm your registration link in the original browser."
      footer={<AuthLink href="/register">Restart registration</AuthLink>}
    >
      <RegistrationEmailVerification />
    </AuthCard>
  );
}
