import { AuthCard, AuthLink } from '../_components/auth-card';
import { RegistrationScreen } from '../_components/screens';

export const metadata = { title: 'Create an account | Hatef Identity' };

export default function RegistrationPage() {
  return (
    <AuthCard
      title="Create your account"
      description="Start with your email and a password that you do not use anywhere else."
      footer={
        <>
          <span>Already have an account?</span>
          <AuthLink href="/login">Sign in</AuthLink>
        </>
      }
    >
      <RegistrationScreen />
    </AuthCard>
  );
}
