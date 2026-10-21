import { AuthCard, AuthLink } from '../_components/auth-card';
import { TotpScreen } from '../_components/screens';

export const metadata = { title: 'Verify authenticator code | Hatef Identity' };

export default function TotpPage() {
  return (
    <AuthCard
      title="Verify your authenticator code"
      description="Use the current code from your authenticator app. No verification session is connected to this preview."
      footer={<AuthLink href="/login">Return to sign in</AuthLink>}
    >
      <TotpScreen />
    </AuthCard>
  );
}
