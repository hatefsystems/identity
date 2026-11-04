'use client';

import { useTranslations } from 'next-intl';

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
  const t = useTranslations();
  return <LoginForm passkeyAction={<PasskeyLogin label={t('auth.passkey.continue')} />} />;
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
