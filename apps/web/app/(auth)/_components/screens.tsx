'use client';

import {
  ForgotPasswordForm,
  LoginForm,
  RegistrationForm,
  ResetPasswordForm,
  TotpForm,
} from './forms';
import { PasskeyLogin } from '../../_components/passkey-login';

// Only passkey sign-in is live. Other Task 7.2 forms remain disconnected.
export function LoginScreen() {
  return <LoginForm passkeyAction={<PasskeyLogin label="Continue with a passkey" />} />;
}

export function RegistrationScreen() {
  return <RegistrationForm />;
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
