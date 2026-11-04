import type { MessageDescriptor } from '../../../i18n/messages';
export type EmailValues = { email: string };
export type LoginValues = EmailValues & { password: string };
export type PasswordValues = { password: string; confirmation: string };
export type RegistrationValues = EmailValues & PasswordValues;
export type TotpValues = { code: string };
export type FieldErrors<T> = Partial<Record<keyof T, MessageDescriptor>>;

export function validateEmail({ email }: EmailValues): FieldErrors<EmailValues> {
  if (!email) return { email: { key: 'auth.validation.emailRequired' } };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { email: { key: 'auth.validation.emailInvalid' } };
  }
  return {};
}

export function validateLogin(values: LoginValues): FieldErrors<LoginValues> {
  return {
    ...validateEmail(values),
    ...(!values.password ? { password: { key: 'auth.validation.passwordRequired' } } : {}),
  };
}

export function validatePassword(values: PasswordValues): FieldErrors<PasswordValues> {
  const errors: FieldErrors<PasswordValues> = {};
  if (!values.password) errors.password = { key: 'auth.validation.newPasswordRequired' };
  if (!values.confirmation) errors.confirmation = { key: 'auth.validation.confirmationRequired' };
  else if (values.confirmation !== values.password) {
    errors.confirmation = { key: 'auth.validation.passwordMismatch' };
  }
  return errors;
}

export function validateRegistration(values: RegistrationValues): FieldErrors<RegistrationValues> {
  return { ...validateEmail(values), ...validatePassword(values) };
}

export function validateTotp({ code }: TotpValues): FieldErrors<TotpValues> {
  return /^[0-9]{6}$/.test(code) ? {} : { code: { key: 'auth.validation.code' } };
}
