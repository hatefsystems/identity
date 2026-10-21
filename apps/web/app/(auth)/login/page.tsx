import { AuthCard, AuthLink } from '../_components/auth-card';
import { LoginScreen } from '../_components/screens';

export const metadata = { title: 'Sign in | Hatef Identity' };

export default function LoginPage() {
  return (
    <AuthCard
      title="Sign in to Hatef"
      description="Choose a passkey for a password-free sign-in, or use your email and password."
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
