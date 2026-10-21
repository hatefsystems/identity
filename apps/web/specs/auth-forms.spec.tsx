import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  ForgotPasswordForm,
  LoginForm,
  PasskeyForm,
  RegistrationForm,
  ResetPasswordForm,
  TotpForm,
} from '../app/(auth)/_components/forms';
import type { FormOutcome } from '../app/(auth)/_lib/use-auth-form';

function enter(label: string, value: string) {
  const input = screen.getByLabelText<HTMLInputElement>(label);
  fireEvent.change(input, { target: { value } });
  return input;
}

function deferredOutcome() {
  let resolve!: (outcome: FormOutcome) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<FormOutcome>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('auth field interaction', () => {
  it('validates touched fields without moving focus, then focuses the first invalid submit field', () => {
    const submit = jest.fn();
    render(<LoginForm submit={submit} />);
    const email = enter('Email address', 'invalid');
    const password = screen.getByLabelText<HTMLInputElement>('Password');

    expect(email.getAttribute('aria-invalid')).toBe('false');
    expect(password.getAttribute('aria-invalid')).toBe('false');
    act(() => password.focus());
    fireEvent.blur(email);

    expect(document.activeElement).toBe(password);
    expect(email.getAttribute('aria-invalid')).toBe('true');
    expect(document.getElementById(email.getAttribute('aria-describedby') ?? '')?.textContent).toBe(
      'Enter a valid email address.'
    );
    expect(password.getAttribute('aria-describedby')).toBeNull();

    fireEvent.submit(screen.getByRole('form', { name: 'Password sign in' }));
    expect(document.activeElement).toBe(email);
    expect(password.getAttribute('aria-invalid')).toBe('true');
    expect(
      document.getElementById(password.getAttribute('aria-describedby') ?? '')?.textContent
    ).toBe('Enter your password.');
    expect(submit).not.toHaveBeenCalled();

    enter('Email address', 'person@example.test');
    expect(email.getAttribute('aria-invalid')).toBe('false');
    expect(email.getAttribute('aria-describedby')).toBeNull();
    fireEvent.submit(screen.getByRole('form', { name: 'Password sign in' }));
    expect(document.activeElement).toBe(password);
    expect(submit).not.toHaveBeenCalled();
  });

  it.each([
    ['registration', <RegistrationForm />],
    ['password reset', <ResetPasswordForm />],
  ])('revalidates a previously valid confirmation when the %s password changes', (_name, form) => {
    render(form);
    const password = enter('New password', ' original ');
    const confirmation = enter('Confirm password', ' original ');
    fireEvent.blur(password);
    fireEvent.blur(confirmation);
    expect(confirmation.getAttribute('aria-invalid')).toBe('false');

    enter('New password', 'changed');
    expect(confirmation.getAttribute('aria-invalid')).toBe('true');
    expect(
      document.getElementById(confirmation.getAttribute('aria-describedby') ?? '')?.textContent
    ).toBe('Passwords do not match.');

    enter('Confirm password', 'changed');
    expect(confirmation.getAttribute('aria-invalid')).toBe('false');
    expect(confirmation.getAttribute('aria-describedby')).toBeNull();
  });

  it('keeps password guidance associated when an error appears and disappears', () => {
    render(<RegistrationForm />);
    const password = screen.getByLabelText<HTMLInputElement>('New password');
    const id = password.id;
    const hintId = password.getAttribute('aria-describedby') ?? '';
    expect(document.getElementById(hintId)?.textContent).toBe(
      'Use a long, unique password. You can include spaces.'
    );

    fireEvent.blur(password);
    const descriptions = password.getAttribute('aria-describedby')?.split(' ') ?? [];
    expect(descriptions).toHaveLength(2);
    expect(descriptions).toContain(hintId);
    expect(
      descriptions.map((description) => document.getElementById(description)?.textContent)
    ).toContain('Enter a new password.');

    enter('New password', 'x');
    expect(password.id).toBe(id);
    expect(password.getAttribute('aria-invalid')).toBe('false');
    expect(password.getAttribute('aria-describedby')).toBe(hintId);
  });

  it('reveals each password independently without submitting or losing its value or toggle focus', () => {
    const submit = jest.fn();
    render(<RegistrationForm submit={submit} />);
    enter('Email address', 'person@example.test');
    const password = enter('New password', '  exact value  ');
    const confirmation = enter('Confirm password', '  exact value  ');
    const toggle = screen.getByRole<HTMLButtonElement>('button', { name: 'Show new password' });

    expect(toggle.type).toBe('button');
    expect(toggle.getAttribute('aria-controls')).toBe(password.id);
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    act(() => toggle.focus());
    fireEvent.click(toggle);

    expect(screen.getByRole('button', { name: 'Hide new password' })).toBe(toggle);
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(document.activeElement).toBe(toggle);
    expect(password.type).toBe('text');
    expect(password.value).toBe('  exact value  ');
    expect(confirmation.type).toBe('password');
    expect(confirmation.value).toBe('  exact value  ');
    fireEvent.click(toggle);
    expect(password.type).toBe('password');
    expect(password.value).toBe('  exact value  ');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');

    fireEvent.click(screen.getByRole('button', { name: 'Show confirm password' }));
    expect(confirmation.type).toBe('text');
    expect(password.type).toBe('password');
    expect(submit).not.toHaveBeenCalled();
  });

  it('accepts a pasted full leading-zero code, but never auto-submits the sixth digit', async () => {
    const submit = jest.fn().mockResolvedValue('success');
    render(<TotpForm submit={submit} />);
    const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
    expect(code.type).toBe('text');
    expect(code.inputMode).toBe('numeric');
    expect(code.autocomplete).toBe('one-time-code');
    expect(code.pattern).toBe('[0-9]{6}');
    expect(
      document.getElementById(code.getAttribute('aria-describedby') ?? '')?.textContent
    ).toContain('authenticator app, not an email or text message');

    // fireEvent does not perform the browser's default paste insertion.
    expect(fireEvent.paste(code, { clipboardData: { getData: () => '012345' } })).toBe(true);
    fireEvent.input(code, { target: { value: '012345' }, inputType: 'insertFromPaste' });
    fireEvent.blur(code);
    expect(code.value).toBe('012345');
    expect(code.getAttribute('aria-invalid')).toBe('false');
    expect(submit).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /resend/i })).toBeNull();

    fireEvent.submit(screen.getByRole('form', { name: 'Authenticator verification' }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe('Code verification completed.')
    );
    expect(submit).toHaveBeenCalledWith({ code: '012345' });
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
  });
});

describe('test-injected submission', () => {
  it('announces pending, prevents same-turn duplicate submissions, and removes sensitive controls on success', async () => {
    const outcome = deferredOutcome();
    const submit = jest.fn(() => outcome.promise);
    render(<LoginForm submit={submit} />);
    const email = enter('Email address', 'person@example.test');
    const password = enter('Password', '  unchanged password  ');
    const form = screen.getByRole<HTMLFormElement>('form', { name: 'Password sign in' });
    const status = screen.getByRole('status');
    expect(status.getAttribute('aria-live')).toBe('polite');
    expect(status.getAttribute('aria-atomic')).toBe('true');
    expect(status.textContent).toBe('');

    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });
    expect(submit).toHaveBeenCalledTimes(1);
    expect(submit).toHaveBeenCalledWith({
      email: 'person@example.test',
      password: '  unchanged password  ',
    });
    expect(status.textContent).toBe('Signing in...');
    expect(email.disabled).toBe(true);
    expect(password.disabled).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Show password' }).disabled).toBe(
      true
    );
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Signing in...' }).disabled).toBe(
      true
    );
    fireEvent.submit(form);
    expect(submit).toHaveBeenCalledTimes(1);

    await act(async () => outcome.resolve('success'));
    expect(status.textContent).toBe('Sign-in completed.');
    expect(document.activeElement?.contains(status)).toBe(true);
    expect(form.querySelector('input')).toBeNull();
    expect([...new FormData(form).entries()]).toEqual([]);
    expect(form.textContent).not.toContain('unchanged password');
    expect(screen.queryByRole('button', { name: 'Sign in with password' })).toBeNull();
    fireEvent.submit(form);
    expect(submit).toHaveBeenCalledTimes(1);
  });

  it('captures current password-manager DOM values even without React change events', async () => {
    const submit = jest.fn().mockResolvedValue('error');
    render(<LoginForm submit={submit} />);
    const email = enter('Email address', 'previous@example.test');
    const password = enter('Password', 'previous secret');
    const form = screen.getByRole('form', { name: 'Password sign in' });
    email.value = 'invalid';
    password.value = '';

    fireEvent.submit(form);
    expect(submit).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(email);
    expect(email.getAttribute('aria-invalid')).toBe('true');
    expect(password.getAttribute('aria-invalid')).toBe('true');

    email.value = 'autofilled@example.test';
    password.value = '  autofilled secret  ';
    fireEvent.submit(form);
    await screen.findByRole('alert');
    expect(submit).toHaveBeenCalledWith({
      email: 'autofilled@example.test',
      password: '  autofilled secret  ',
    });
    expect(email.value).toBe('autofilled@example.test');
    expect(password.value).toBe('  autofilled secret  ');
  });

  it.each(['error', 'rejection'] as const)(
    'uses fixed non-enumerating text after %s and permits a retry',
    async (failure) => {
      const outcome = deferredOutcome();
      const submit = jest
        .fn()
        .mockReturnValueOnce(outcome.promise)
        .mockResolvedValueOnce('success');
      const { container } = render(<LoginForm submit={submit} />);
      const email = enter('Email address', 'person@example.test');
      const password = enter('Password', 'kept for retry');
      const form = screen.getByRole('form', { name: 'Password sign in' });
      fireEvent.submit(form);

      await act(async () => {
        if (failure === 'rejection')
          outcome.reject(new Error('<script>private backend/account detail</script>'));
        else outcome.resolve('error');
      });
      const alert = screen.getByRole('alert');
      expect(alert.textContent).toBe('We could not sign you in. Check your details and try again.');
      expect(document.activeElement?.contains(alert)).toBe(true);
      expect(screen.getByRole('status').textContent).toBe('');
      expect(container.textContent).not.toContain('private backend/account detail');
      expect(container.querySelector('script')).toBeNull();
      expect(email.disabled).toBe(false);
      expect(password.disabled).toBe(false);
      expect(password.value).toBe('kept for retry');
      expect(
        screen.getByRole<HTMLButtonElement>('button', { name: 'Sign in with password' }).disabled
      ).toBe(false);
      expect(
        screen.getByRole<HTMLButtonElement>('button', { name: 'Show password' }).disabled
      ).toBe(false);

      enter('Password', 'corrected password');
      expect(screen.queryByRole('alert')).toBeNull();
      fireEvent.submit(form);
      await waitFor(() =>
        expect(screen.getByRole('status').textContent).toBe('Sign-in completed.')
      );
      expect(submit).toHaveBeenCalledTimes(2);
      expect(submit).toHaveBeenLastCalledWith({
        email: 'person@example.test',
        password: 'corrected password',
      });
    }
  );

  it('announces rate limiting without inventing a countdown and restores the controls', async () => {
    const submit = jest.fn().mockResolvedValue('rate-limited');
    render(<TotpForm submit={submit} />);
    const code = enter('Authenticator code', '012345');
    fireEvent.submit(screen.getByRole('form', { name: 'Authenticator verification' }));

    expect((await screen.findByRole('alert')).textContent).toBe(
      'Too many attempts. Please try again later.'
    );
    expect(code.disabled).toBe(false);
    expect(code.value).toBe('012345');
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Verify code' }).disabled).toBe(
      false
    );
    expect(screen.queryByRole('timer')).toBeNull();
  });

  it.each(['success', 'rejection'] as const)(
    'ignores %s after unmount without disturbing the replacement form',
    async (completion) => {
      const outcome = deferredOutcome();
      const submit = jest.fn(() => outcome.promise);
      const original = render(<LoginForm submit={submit} />);
      enter('Email address', 'person@example.test');
      enter('Password', 'discarded secret');
      fireEvent.submit(screen.getByRole('form', { name: 'Password sign in' }));
      original.unmount();

      render(<LoginForm />);
      const replacement = enter('Email address', 'replacement@example.test');
      act(() => replacement.focus());
      await act(async () => {
        if (completion === 'success') outcome.resolve('success');
        else outcome.reject(new Error('late private failure'));
      });

      expect(document.activeElement).toBe(replacement);
      expect(replacement.value).toBe('replacement@example.test');
      expect(screen.getByLabelText<HTMLInputElement>('Password').value).toBe('');
      expect(screen.getByRole('status').textContent).toBe('');
      expect(screen.queryByRole('alert')).toBeNull();
      expect(original.container.childElementCount).toBe(0);
      expect(submit).toHaveBeenCalledTimes(1);
    }
  );

  it('submits and clears registration without trimming or rejecting a whitespace-only password', async () => {
    const submit = jest.fn().mockResolvedValue('success');
    render(<RegistrationForm submit={submit} />);
    enter('Email address', 'person@example.test');
    enter('New password', ' ');
    enter('Confirm password', ' ');
    const form = screen.getByRole<HTMLFormElement>('form', { name: 'Create an account' });
    fireEvent.submit(form);

    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe(
        'Registration completed. Return to sign in to continue.'
      )
    );
    expect(submit).toHaveBeenCalledWith({
      email: 'person@example.test',
      password: ' ',
      confirmation: ' ',
    });
    expect([...new FormData(form).entries()]).toEqual([]);
  });

  it('gives a generic reset-request acknowledgement without revealing or repeating an account identity', async () => {
    const submit = jest.fn().mockResolvedValue('success');
    render(<ForgotPasswordForm submit={submit} />);
    enter('Email address', 'possibly-unknown@example.test');
    fireEvent.submit(screen.getByRole('form', { name: 'Request a password reset' }));

    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe(
        'If an account matches that email address, you will receive a password reset link. Check your inbox and spam folder.'
      )
    );
    expect(submit).toHaveBeenCalledWith({ email: 'possibly-unknown@example.test' });
    expect(screen.queryByLabelText('Email address')).toBeNull();
    expect(screen.getByRole('form').textContent).not.toContain('possibly-unknown@example.test');
  });
});

describe('operation-specific presentations', () => {
  it.each([
    ['cancelled', 'The passkey request was cancelled. You can try again.'],
    [
      'unsupported',
      'Passkeys are not supported in this browser. Try another browser or use the password form.',
    ],
    ['error', 'We could not verify the passkey. Please try again.'],
  ] as const)(
    'announces a %s passkey outcome and restores the action',
    async (outcome, message) => {
      const pending = deferredOutcome();
      const submit = jest.fn(() => pending.promise);
      render(<PasskeyForm submit={submit} />);
      const form = screen.getByRole('form', { name: 'Passkey sign in' });
      expect(form.querySelector('input')).toBeNull();
      fireEvent.submit(form);
      expect(screen.getByRole('status').textContent).toBe('Complete the prompt on your device.');
      expect(
        screen.getByRole<HTMLButtonElement>('button', {
          name: 'Complete the prompt on your device.',
        }).disabled
      ).toBe(true);
      await act(async () => pending.resolve(outcome));

      expect(screen.getByRole('alert').textContent).toBe(message);
      expect(
        screen.getByRole<HTMLButtonElement>('button', { name: 'Use a passkey' }).disabled
      ).toBe(false);
      expect(screen.getByRole('status').textContent).toBe('');
    }
  );

  it('presents passkey completion only for the injected handler', async () => {
    const submit = jest.fn().mockResolvedValue('success');
    render(<PasskeyForm submit={submit} />);
    fireEvent.submit(screen.getByRole('form', { name: 'Passkey sign in' }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe('Passkey verification completed.')
    );
    expect(submit).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Use a passkey' })).toBeNull();
  });

  it('requires both an explicitly ready reset link and a handler to enable submission', () => {
    const submit = jest.fn();
    const { rerender } = render(<ResetPasswordForm submit={submit} />);
    const form = screen.getByRole('form', { name: 'Set a new password' });
    enter('New password', 'x');
    enter('Confirm password', 'x');
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Reset password' }).disabled).toBe(
      true
    );
    fireEvent.submit(form);
    expect(submit).not.toHaveBeenCalled();

    rerender(<ResetPasswordForm linkState="ready" />);
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Reset password' }).disabled).toBe(
      true
    );
    fireEvent.submit(form);
    expect(submit).not.toHaveBeenCalled();

    rerender(<ResetPasswordForm linkState="ready" submit={submit} />);
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Reset password' }).disabled).toBe(
      false
    );
  });

  it.each([
    ['invalid', 'This reset link cannot be used. Request a new link to continue.'],
    ['expired', 'This reset link has expired. Request a new link to continue.'],
  ] as const)(
    'presents an %s reset link without password inputs or a submit action',
    (linkState, message) => {
      const submit = jest.fn();
      const { container } = render(<ResetPasswordForm linkState={linkState} submit={submit} />);
      expect(screen.getByRole('alert').textContent).toBe(message);
      expect(
        screen.getByRole('link', { name: 'Request a new reset link' }).getAttribute('href')
      ).toBe('/forgot-password');
      expect(container.querySelector('input, form, button[type="submit"]')).toBeNull();
      expect(submit).not.toHaveBeenCalled();
    }
  );

  it('validates, announces pending, and clears both password fields after a ready reset completes', async () => {
    const outcome = deferredOutcome();
    const submit = jest.fn(() => outcome.promise);
    render(<ResetPasswordForm linkState="ready" submit={submit} />);
    const password = enter('New password', ' x ');
    const confirmation = enter('Confirm password', 'x');
    const form = screen.getByRole<HTMLFormElement>('form', { name: 'Set a new password' });
    fireEvent.submit(form);
    expect(document.activeElement).toBe(confirmation);
    expect(confirmation.getAttribute('aria-invalid')).toBe('true');
    expect(submit).not.toHaveBeenCalled();

    enter('Confirm password', ' x ');
    fireEvent.submit(form);
    expect(screen.getByRole('status').textContent).toBe('Resetting your password...');
    expect(password.disabled).toBe(true);
    expect(confirmation.disabled).toBe(true);
    await act(async () => outcome.resolve('success'));
    expect(screen.getByRole('status').textContent).toBe(
      'Password reset completed. Return to sign in with your new password.'
    );
    expect(submit).toHaveBeenCalledWith({ password: ' x ', confirmation: ' x ' });
    expect(form.querySelector('input')).toBeNull();
    expect([...new FormData(form).entries()]).toEqual([]);
  });
});
