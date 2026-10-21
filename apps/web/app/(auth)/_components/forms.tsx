import { Button } from '@hatef/ui';
import { Fingerprint } from 'lucide-react';
import Link from 'next/link';
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

export function LoginForm({ submit }: { submit?: FormSubmit<LoginValues> }) {
  const form = useAuthForm({ email: '', password: '' }, validateLogin, submit);

  return (
    <>
      <Button asChild className="h-auto min-h-11 w-full whitespace-normal">
        <Link href="/login/webauthn">
          <Fingerprint aria-hidden="true" />
          Continue with a passkey
        </Link>
      </Button>
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span aria-hidden="true" className="h-px flex-1 bg-border" />
        <span>or use your password</span>
        <span aria-hidden="true" className="h-px flex-1 bg-border" />
      </div>
      <AuthForm
        {...form}
        label="Password sign in"
        submitLabel="Sign in with password"
        messages={{
          pending: 'Signing in...',
          success: 'Sign-in completed.',
          error: 'We could not sign you in. Check your details and try again.',
        }}
      >
        <AuthField
          {...form.field('email')}
          label="Email address"
          type="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
        />
        <AuthField
          {...form.field('password')}
          label="Password"
          type="password"
          autoComplete="current-password"
          required
        />
        <div className="flex justify-end">
          <AuthLink href="/forgot-password">Forgot password?</AuthLink>
        </div>
      </AuthForm>
    </>
  );
}

export function RegistrationForm({ submit }: { submit?: FormSubmit<RegistrationValues> }) {
  const form = useAuthForm(
    { email: '', password: '', confirmation: '' },
    validateRegistration,
    submit
  );

  return (
    <AuthForm
      {...form}
      label="Create an account"
      submitLabel="Create account"
      messages={{
        pending: 'Creating your account...',
        success: 'Registration completed. Return to sign in to continue.',
        error: 'We could not complete registration. Please try again.',
      }}
    >
      <AuthField
        {...form.field('email')}
        label="Email address"
        type="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        required
      />
      <AuthField
        {...form.field('password')}
        label="New password"
        type="password"
        autoComplete="new-password"
        hint="Use a long, unique password. You can include spaces."
        required
      />
      <AuthField
        {...form.field('confirmation')}
        label="Confirm password"
        type="password"
        autoComplete="new-password"
        required
      />
    </AuthForm>
  );
}

export function PasskeyForm({ submit }: { submit?: () => Promise<FormOutcome> }) {
  const form = useAuthForm({}, () => ({}), submit);

  return (
    <>
      <div className="flex items-start gap-3 rounded-md bg-muted/50 p-4">
        <Fingerprint aria-hidden="true" className="mt-0.5 size-6 shrink-0" />
        <p className="text-sm leading-relaxed">
          Use a fingerprint, face recognition, device PIN, or a security key. Your device chooses
          the account, so you do not need to enter an email address.
        </p>
      </div>
      <AuthForm
        {...form}
        label="Passkey sign in"
        submitLabel="Use a passkey"
        messages={{
          pending: 'Complete the prompt on your device.',
          success: 'Passkey verification completed.',
          error: 'We could not verify the passkey. Please try again.',
          cancelled: 'The passkey request was cancelled. You can try again.',
          unsupported:
            'Passkeys are not supported in this browser. Try another browser or use the password form.',
        }}
      />
    </>
  );
}

export function TotpForm({ submit }: { submit?: FormSubmit<TotpValues> }) {
  const form = useAuthForm({ code: '' }, validateTotp, submit);

  return (
    <AuthForm
      {...form}
      label="Authenticator verification"
      submitLabel="Verify code"
      messages={{
        pending: 'Verifying your code...',
        success: 'Code verification completed.',
        error:
          'We could not verify that code. Use the current code from your authenticator and try again.',
      }}
    >
      <AuthField
        {...form.field('code')}
        label="Authenticator code"
        hint="Enter the six-digit code from your authenticator app, not an email or text message."
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
  const form = useAuthForm({ email: '' }, validateEmail, submit);

  return (
    <AuthForm
      {...form}
      label="Request a password reset"
      submitLabel="Send reset link"
      messages={{
        pending: 'Requesting a reset link...',
        success:
          'If an account matches that email address, you will receive a password reset link. Check your inbox and spam folder.',
        error: 'We could not request a reset link. Please try again.',
      }}
    >
      <AuthField
        {...form.field('email')}
        label="Email address"
        type="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        hint="Use the primary email address for your account."
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
          {linkState === 'expired'
            ? 'This reset link has expired. Request a new link to continue.'
            : 'This reset link cannot be used. Request a new link to continue.'}
        </p>
        <AuthLink href="/forgot-password">Request a new reset link</AuthLink>
      </div>
    );
  }

  return (
    <AuthForm
      {...form}
      label="Set a new password"
      submitLabel="Reset password"
      messages={{
        pending: 'Resetting your password...',
        success: 'Password reset completed. Return to sign in with your new password.',
        error: 'We could not reset your password. Please try again or request a new link.',
      }}
    >
      <AuthField
        {...form.field('password')}
        label="New password"
        type="password"
        autoComplete="new-password"
        hint="Use a long, unique password. You can include spaces."
        required
      />
      <AuthField
        {...form.field('confirmation')}
        label="Confirm password"
        type="password"
        autoComplete="new-password"
        required
      />
    </AuthForm>
  );
}
