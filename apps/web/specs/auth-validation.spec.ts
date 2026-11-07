import { TextEncoder } from 'node:util';
import {
  validateEmail,
  validateLogin,
  validatePassword,
  validateRegistration,
  validateTotp,
} from '../app/(auth)/_lib/validation';

const encoder = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder');
beforeAll(() =>
  Object.defineProperty(globalThis, 'TextEncoder', { configurable: true, value: TextEncoder })
);
afterAll(() => {
  if (encoder) Object.defineProperty(globalThis, 'TextEncoder', encoder);
  else Reflect.deleteProperty(globalThis, 'TextEncoder');
});

describe('local auth validation', () => {
  it('requires an email without claiming whether an account exists', () => {
    expect(validateEmail({ email: '' })).toEqual({ email: 'Enter your email address.' });
  });

  it.each([
    ' ',
    'person',
    'person@',
    '@example.test',
    'person@example',
    'a@@example.test',
    'a b@example.test',
    ' person@example.test',
    'person@example.test ',
  ])('rejects malformed email %j without silently normalizing it', (email) => {
    expect(validateEmail({ email })).toEqual({ email: 'Enter a valid email address.' });
  });

  it.each(['person@example.test', 'first.last+tag@sub.example.test'])(
    'accepts ordinary email syntax %j',
    (email) => {
      expect(validateEmail(Object.freeze({ email }))).toEqual({});
    }
  );

  it('reports all missing login and registration fields', () => {
    expect(validateLogin({ email: '', password: '' })).toEqual({
      email: 'Enter your email address.',
      password: 'Enter your password.',
    });
    expect(validateRegistration({ email: 'not-an-email', phone: '' })).toEqual({
      email: 'Enter a valid email address without invisible characters (at most 1024 UTF-8 bytes).',
      phone: 'Enter an Iranian mobile number, such as +989123456789.',
    });
  });

  it.each(['x', ' ', '\t', '  keep my spaces  ', 'p\u00e4ss\u00a0word'])(
    'accepts the exact nonempty password %j without inventing a new-password policy',
    (password) => {
      const values = Object.freeze({
        email: 'person@example.test',
        password,
        confirmation: password,
      });

      expect(validateLogin(values)).toEqual({});
      expect(validatePassword(values)).toEqual({});
      expect(values.password).toBe(password);
      expect(values.confirmation).toBe(password);
    }
  );

  it('requires both new-password fields', () => {
    expect(validatePassword({ password: '', confirmation: '' })).toEqual({
      password: 'Enter a new password.',
      confirmation: 'Confirm your password.',
    });
    expect(validatePassword({ password: 'x', confirmation: '' })).toEqual({
      confirmation: 'Confirm your password.',
    });
    expect(validatePassword({ password: '', confirmation: 'x' })).toEqual({
      password: 'Enter a new password.',
      confirmation: 'Passwords do not match.',
    });
  });

  it.each([
    ['password', 'Password'],
    [' password ', 'password'],
    [' ', '  '],
    ['caf\u00e9', 'cafe\u0301'],
  ])('compares confirmation exactly: %j versus %j', (password, confirmation) => {
    expect(validatePassword({ password, confirmation })).toEqual({
      confirmation: 'Passwords do not match.',
    });
  });

  it.each(['000000', '012345', '987654'])('accepts six ASCII digits, including %j', (code) => {
    expect(validateTotp(Object.freeze({ code }))).toEqual({});
  });

  it.each([
    '',
    '12345',
    '1234567',
    '12a456',
    '123 56',
    ' 123456',
    '123456 ',
    '123456\n',
    '\u0660\u0661\u0662\u0663\u0664\u0665',
    '\uff10\uff11\uff12\uff13\uff14\uff15',
  ])('rejects noncanonical authenticator code %j', (code) => {
    expect(validateTotp({ code })).toEqual({ code: 'Enter exactly six digits (0-9).' });
  });
});
