export type EmailValues = { email: string };
export type LoginValues = EmailValues & { password: string };
export type PasswordValues = { password: string; confirmation: string };
export type RegistrationValues = EmailValues & { phone: string };
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
  return {
    ...validateSignupEmail(values.email),
    ...(!/^(?:\+989[0-9]{9}|09[0-9]{9}|989[0-9]{9})$/.test(values.phone)
      ? { phone: 'Enter an Iranian mobile number, such as +989123456789.' }
      : {}),
  };
}

// Validate safe input, not identity. Only the backend applies casing and IDNA.
export function validateSignupEmail(email: string): FieldErrors<EmailValues> {
  if (!email) return { email: 'Enter your email address.' };
  const safe =
    !/[\p{Cc}\p{Cf}\p{Cs}\p{Default_Ignorable_Code_Point}\p{Noncharacter_Code_Point}\uFFFD]/u.test(
      email
    );
  const parts = email.trim().split('@');
  if (
    new TextEncoder().encode(email).length > 1024 ||
    !safe ||
    parts.length !== 2 ||
    !/^[\p{L}\p{N}\p{M}!#$%&'*+\-/=?^_`{|}~.]+$/u.test(parts[0]) ||
    parts[0].startsWith('.') ||
    parts[0].endsWith('.') ||
    parts[0].includes('..') ||
    !/^[\p{L}\p{N}\p{M}.\u3002\uFF0E\uFF61-]+$/u.test(parts[1]) ||
    !/[.\u3002\uFF0E\uFF61]/u.test(parts[1]) ||
    parts[1]
      .split(/[.\u3002\uFF0E\uFF61]/u)
      .some((label) => !label || label.startsWith('-') || label.endsWith('-'))
  )
    return {
      email: 'Enter a valid email address without invisible characters (at most 1024 UTF-8 bytes).',
    };
  return {};
}

export function validateTotp({ code }: TotpValues): FieldErrors<TotpValues> {
  return /^[0-9]{6}$/.test(code) ? {} : { code: 'Enter exactly six digits (0-9).' };
}
