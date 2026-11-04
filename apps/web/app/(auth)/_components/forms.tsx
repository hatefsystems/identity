import { useTranslations } from 'next-intl';
import { Button } from '@hatef/ui';
import { Fingerprint } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { useAuthForm, type FormOutcome, type FormSubmit } from '../_lib/use-auth-form';
import {
  validateEmail,
  validateLogin,
  validatePassword,
  validateRegistration,
  validateTotp,
  type EmailValues,
  type LoginValues,
  type PasswordValues,
  type RegistrationValues,
  type TotpValues,
} from '../_lib/validation';
import { AuthLink } from './auth-card';
import { AuthField, AuthForm } from './form-controls';

export function LoginForm({
  submit,
  passkeyAction,
}: {
  submit?: FormSubmit<LoginValues>;
  passkeyAction?: ReactNode;
}) {
  const t = useTranslations();
  const form = useAuthForm({ email: '', password: '' }, validateLogin, submit);

  return (
    <>
      {passkeyAction ?? (
        <Button asChild className="h-auto min-h-11 w-full whitespace-normal">
          <Link href="/login/webauthn">
            <Fingerprint aria-hidden="true" />
            {t('auth.passkey.continue')}
          </Link>
        </Button>
      )}
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span aria-hidden="true" className="h-px flex-1 bg-border" />
        <span>{t('auth.forms.login.separator')}</span>
        <span aria-hidden="true" className="h-px flex-1 bg-border" />
      </div>
      <AuthForm
        {...form}
        label={t('auth.forms.login.label')}
        submitLabel={t('auth.forms.login.submit')}
        messages={{
          pending: t('auth.forms.login.pending'),
          success: t('auth.forms.login.success'),
          error: t('auth.forms.login.error'),
        }}
      >
        <AuthField
          {...form.field('email')}
          label={t('auth.fields.email')}
          type="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
        />
        <AuthField
          {...form.field('password')}
          label={t('auth.fields.password')}
          type="password"
          autoComplete="current-password"
          required
        />
        <div className="flex justify-end">
          <AuthLink href="/forgot-password">{t('auth.forms.login.forgot')}</AuthLink>
        </div>
      </AuthForm>
    </>
  );
}

export function RegistrationForm({ submit }: { submit?: FormSubmit<RegistrationValues> }) {
  const t = useTranslations();
  const form = useAuthForm(
    { email: '', password: '', confirmation: '' },
    validateRegistration,
    submit
  );

  return (
    <AuthForm
      {...form}
      label={t('auth.forms.register.label')}
      submitLabel={t('auth.forms.register.submit')}
      messages={{
        pending: t('auth.forms.register.pending'),
        success: t('auth.forms.register.success'),
        error: t('auth.forms.register.error'),
      }}
    >
      <AuthField
        {...form.field('email')}
        label={t('auth.fields.email')}
        type="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        required
      />
      <AuthField
        {...form.field('password')}
        label={t('auth.fields.newPassword')}
        type="password"
        autoComplete="new-password"
        hint={t('auth.fields.passwordHint')}
        required
      />
      <AuthField
        {...form.field('confirmation')}
        label={t('auth.fields.confirmPassword')}
        type="password"
        autoComplete="new-password"
        required
      />
    </AuthForm>
  );
}

export function PasskeyForm({ submit }: { submit?: () => Promise<FormOutcome> }) {
  const t = useTranslations();
  const form = useAuthForm({}, () => ({}), submit);

  return (
    <>
      <div className="flex items-start gap-3 rounded-md bg-muted/50 p-4">
        <Fingerprint aria-hidden="true" className="mt-0.5 size-6 shrink-0" />
        <p className="text-sm leading-relaxed">{t('auth.forms.passkey.intro')}</p>
      </div>
      <AuthForm
        {...form}
        label={t('auth.forms.passkey.label')}
        submitLabel={t('auth.forms.passkey.submit')}
        messages={{
          pending: t('auth.forms.passkey.pending'),
          success: t('auth.forms.passkey.success'),
          error: t('auth.forms.passkey.error'),
          cancelled: t('auth.forms.passkey.cancelled'),
          unsupported: t('auth.forms.passkey.unsupported'),
        }}
      />
    </>
  );
}

export function TotpForm({ submit }: { submit?: FormSubmit<TotpValues> }) {
  const t = useTranslations();
  const form = useAuthForm({ code: '' }, validateTotp, submit);

  return (
    <AuthForm
      {...form}
      label={t('auth.forms.totp.label')}
      submitLabel={t('auth.forms.totp.submit')}
      messages={{
        pending: t('auth.forms.totp.pending'),
        success: t('auth.forms.totp.success'),
        error: t('auth.forms.totp.error'),
      }}
    >
      <AuthField
        {...form.field('code')}
        label={t('security.stepUp.code')}
        hint={t('auth.fields.codeHint')}
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern="[0-9]{6}"
        spellCheck={false}
        className="text-center font-mono text-lg tracking-[0.35em] md:text-lg"
        required
      />
    </AuthForm>
  );
}

export function ForgotPasswordForm({ submit }: { submit?: FormSubmit<EmailValues> }) {
  const t = useTranslations();
  const form = useAuthForm({ email: '' }, validateEmail, submit);

  return (
    <AuthForm
      {...form}
      label={t('auth.forms.forgot.label')}
      submitLabel={t('auth.forms.forgot.submit')}
      messages={{
        pending: t('auth.forms.forgot.pending'),
        success: t('auth.forms.forgot.success'),
        error: t('auth.forms.forgot.error'),
      }}
    >
      <AuthField
        {...form.field('email')}
        label={t('auth.fields.email')}
        type="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        hint={t('auth.fields.emailHint')}
        required
      />
    </AuthForm>
  );
}

export function ResetPasswordForm({
  submit,
  linkState = 'unverified',
}: {
  submit?: FormSubmit<PasswordValues>;
  linkState?: 'unverified' | 'ready' | 'invalid' | 'expired';
}) {
  const t = useTranslations();
  const form = useAuthForm(
    { password: '', confirmation: '' },
    validatePassword,
    linkState === 'ready' ? submit : undefined
  );

  if (linkState === 'invalid' || linkState === 'expired') {
    return (
      <div className="space-y-4">
        <p
          role="alert"
          className="rounded-md border border-red-700 bg-red-50 p-3 text-sm leading-relaxed text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200"
        >
          {linkState === 'expired' ? t('auth.forms.reset.expired') : t('auth.forms.reset.invalid')}
        </p>
        <AuthLink href="/forgot-password">{t('auth.forms.reset.newLink')}</AuthLink>
      </div>
    );
  }

  return (
    <AuthForm
      {...form}
      label={t('auth.forms.reset.label')}
      submitLabel={t('auth.forms.reset.submit')}
      messages={{
        pending: t('auth.forms.reset.pending'),
        success: t('auth.forms.reset.success'),
        error: t('auth.forms.reset.error'),
      }}
    >
      <AuthField
        {...form.field('password')}
        label={t('auth.fields.newPassword')}
        type="password"
        autoComplete="new-password"
        hint={t('auth.fields.passwordHint')}
        required
      />
      <AuthField
        {...form.field('confirmation')}
        label={t('auth.fields.confirmPassword')}
        type="password"
        autoComplete="new-password"
        required
      />
    </AuthForm>
  );
}
