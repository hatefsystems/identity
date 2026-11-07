'use client';

import { ForgotPasswordForm, LoginForm, ResetPasswordForm, TotpForm } from './forms';
import { PasskeyLogin } from '../../_components/passkey-login';
import { Registration } from '../../_components/registration';

// Password and reset forms remain unavailable; signup is passkey-only.
export function LoginScreen() {
  return <LoginForm passkeyAction={<PasskeyLogin label="Continue with a passkey" />} />;
}

export function RegistrationScreen() {
  return <Registration />;
}

export function PasskeyScreen() {
  return <PasskeyLogin introduction />;
}

export function TotpScreen() {
  return <TotpForm />;
}

export function ForgotPasswordScreen() {
  return <ForgotPasswordForm />;
}

export function ResetPasswordScreen() {
  return <ResetPasswordForm />;
}
