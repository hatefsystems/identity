import { AuthCard, AuthLink } from '../_components/auth-card';
import { LoginScreen } from '../_components/screens';

export const metadata = { title: 'Sign in | Hatef Identity' };

export default function LoginPage() {
  return (
    <AuthCard
      title="Sign in to Hatef"
      description="Sign in to an existing account with a passkey. Password sign-in is not available yet."
      footer={
        <>
          <span>New to Hatef?</span>
          <AuthLink href="/register">Create an account</AuthLink>
        </>
      }
    >
      <LoginScreen />
    </AuthCard>
  );
}
