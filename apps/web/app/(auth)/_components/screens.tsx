'use client';

import {
  ForgotPasswordForm,
  LoginForm,
  PasskeyForm,
  RegistrationForm,
  ResetPasswordForm,
  TotpForm,
} from './forms';

// Keep submission callbacks behind this boundary; no public route has an auth implementation.
export function LoginScreen() {
  return <LoginForm />;
}

export function RegistrationScreen() {
  return <RegistrationForm />;
}

export function PasskeyScreen() {
  return <PasskeyForm />;
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
