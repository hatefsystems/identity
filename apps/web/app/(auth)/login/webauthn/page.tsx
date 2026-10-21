import { AuthCard, AuthLink } from '../../_components/auth-card';
import { PasskeyScreen } from '../../_components/screens';

export const metadata = { title: 'Sign in with a passkey | Hatef Identity' };

export default function PasskeyPage() {
  return (
    <AuthCard
      title="Sign in with a passkey"
      description="Use a passkey already saved on your device or security key."
      footer={<AuthLink href="/login">Use email and password instead</AuthLink>}
    >
      <PasskeyScreen />
    </AuthCard>
  );
}
