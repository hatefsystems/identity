'use client';

import { useTranslations } from 'next-intl';
import { Button } from '@hatef/ui';
import Link from 'next/link';

import { PasskeyLogin } from '../../_components/passkey-login';
import { Registration } from '../../_components/registration';

export function LoginScreen() {
  const t = useTranslations();
  return <PasskeyLogin label={t('auth.passkey.continue')} />;
}

export function RegistrationScreen() {
  return <Registration />;
}

export function PasskeyScreen() {
  return <PasskeyLogin introduction />;
}

export function TotpScreen() {
  return <UnavailableAuthScreen />;
}

export function ForgotPasswordScreen() {
  return <UnavailableAuthScreen />;
}

export function ResetPasswordScreen() {
  return <UnavailableAuthScreen />;
}

function UnavailableAuthScreen() {
  const t = useTranslations();
  return (
    <div className="space-y-5">
      <p className="rounded-md bg-muted/50 p-3 text-sm leading-relaxed">
        {t('auth.availability.notice')}
      </p>
      <Button asChild className="h-auto min-h-11 w-full whitespace-normal">
        <Link href="/login">{t('auth.passkey.continue')}</Link>
      </Button>
    </div>
  );
}
