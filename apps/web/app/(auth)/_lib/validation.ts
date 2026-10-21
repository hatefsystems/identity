export type EmailValues = { email: string };
export type LoginValues = EmailValues & { password: string };
export type PasswordValues = { password: string; confirmation: string };
export type RegistrationValues = EmailValues & PasswordValues;
export type TotpValues = { code: string };
export type FieldErrors<T> = Partial<Record<keyof T, string>>;

export function validateEmail({ email }: EmailValues): FieldErrors<EmailValues> {
  if (!email) return { email: 'Enter your email address.' };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { email: 'Enter a valid email address.' };
  }
  return {};
}

export function validateLogin(values: LoginValues): FieldErrors<LoginValues> {
  return {
    ...validateEmail(values),
    ...(!values.password ? { password: 'Enter your password.' } : {}),
  };
}

export function validatePassword(values: PasswordValues): FieldErrors<PasswordValues> {
  const errors: FieldErrors<PasswordValues> = {};
  if (!values.password) errors.password = 'Enter a new password.';
  if (!values.confirmation) errors.confirmation = 'Confirm your password.';
  else if (values.confirmation !== values.password) {
    errors.confirmation = 'Passwords do not match.';
  }
  return errors;
}

export function validateRegistration(values: RegistrationValues): FieldErrors<RegistrationValues> {
  return { ...validateEmail(values), ...validatePassword(values) };
}

export function validateTotp({ code }: TotpValues): FieldErrors<TotpValues> {
  return /^[0-9]{6}$/.test(code) ? {} : { code: 'Enter exactly six digits (0-9).' };
}
