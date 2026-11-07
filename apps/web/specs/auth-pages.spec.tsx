jest.mock('next-intl/server', () => ({
  getTranslations: (namespace: string) =>
    jest.requireActual('../i18n/testing').getTestTranslations(namespace, mockPageLocale),
}));

import { fireEvent, render, screen } from '../i18n/testing';
import { renderToStaticMarkup as renderStatic } from 'react-dom/server';
import type { ReactElement } from 'react';
import { I18nTestProvider } from '../i18n/testing';
const renderToStaticMarkup = (element: ReactElement) =>
  renderStatic(<I18nTestProvider>{element}</I18nTestProvider>);
import AuthLayout from '../app/(auth)/layout';
import ForgotPasswordPage, {
  generateMetadata as forgotMetadata,
} from '../app/(auth)/forgot-password/page';
import LoginPage, { generateMetadata as loginMetadata } from '../app/(auth)/login/page';
import PasskeyPage, {
  generateMetadata as passkeyMetadata,
} from '../app/(auth)/login/webauthn/page';
import RegistrationPage, {
  generateMetadata as registrationMetadata,
} from '../app/(auth)/register/page';
import ResetPasswordPage, {
  generateMetadata as resetMetadata,
} from '../app/(auth)/reset-password/page';
import TotpPage, { generateMetadata as totpMetadata } from '../app/(auth)/verify-totp/page';

jest.mock('next/navigation', () => ({ useRouter: () => ({ replace: jest.fn() }) }));

let mockPageLocale: 'en' | 'fa-IR' = 'en';
afterEach(() => {
  mockPageLocale = 'en';
});

const notice = 'This form is not connected yet. Do not enter real credentials.';
const routes = [
  {
    path: '/login',
    Page: LoginPage,
    metadata: loginMetadata,
    title: 'Sign in | Hatef Identity',
    heading: 'Sign in to Hatef',
    action: 'Sign in with password',
    fields: [
      ['Email address', 'email', 'username'],
      ['Password', 'password', 'current-password'],
    ],
    links: [
      ['Forgot password?', '/forgot-password'],
      ['Create an account', '/register'],
    ],
  },
  {
    path: '/register',
    Page: RegistrationPage,
    metadata: registrationMetadata,
    title: 'Create an account | Hatef Identity',
    heading: 'Create your account',
    action: 'Start registration and send email',
    fields: [
      ['Email address', 'text', 'email'],
      ['Iranian mobile number', 'tel', 'tel'],
    ],
    links: [['Sign in', '/login']],
  },
  {
    path: '/login/webauthn',
    Page: PasskeyPage,
    metadata: passkeyMetadata,
    title: 'Sign in with a passkey | Hatef Identity',
    heading: 'Sign in with a passkey',
    action: 'Use a passkey',
    fields: [],
    links: [['Return to sign in', '/login']],
  },
  {
    path: '/verify-totp',
    Page: TotpPage,
    metadata: totpMetadata,
    title: 'Verify authenticator code | Hatef Identity',
    heading: 'Verify your authenticator code',
    action: 'Verify code',
    fields: [['Authenticator code', 'text', 'one-time-code']],
    links: [['Return to sign in', '/login']],
  },
  {
    path: '/forgot-password',
    Page: ForgotPasswordPage,
    metadata: forgotMetadata,
    title: 'Reset your password | Hatef Identity',
    heading: 'Reset your password',
    action: 'Send reset link',
    fields: [['Email address', 'email', 'email']],
    links: [['Return to sign in', '/login']],
  },
  {
    path: '/reset-password',
    Page: ResetPasswordPage,
    metadata: resetMetadata,
    title: 'Set a new password | Hatef Identity',
    heading: 'Set a new password',
    action: 'Reset password',
    fields: [
      ['New password', 'password', 'new-password'],
      ['Confirm password', 'password', 'new-password'],
    ],
    links: [['Return to sign in', '/login']],
  },
];

describe('public auth routes', () => {
  it.each(routes)(
    '$path has meaningful headings, associated labels, native controls, and real navigation',
    async ({ Page, metadata, title, heading, action, fields, links }) => {
      const { container } = render(await AuthLayout({ children: await Page() }));
      expect((await metadata()).title).toBe(title);
      expect(screen.getAllByRole('main')).toHaveLength(1);
      expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
      expect(screen.getByRole('heading', { level: 1, name: heading })).toBeTruthy();
      expect(screen.getByRole('link', { name: 'Hatef Identity home' }).getAttribute('href')).toBe(
        '/'
      );
      expect(document.activeElement).toBe(document.body);
      expect(container.querySelectorAll('input')).toHaveLength(fields.length);

      for (const [label, type, autocomplete] of fields) {
        const input = screen.getByLabelText<HTMLInputElement>(label);
        expect(input.id).not.toBe('');
        expect(
          [...container.querySelectorAll('label')].some(
            (element) => element.htmlFor === input.id && element.textContent === label
          )
        ).toBe(true);
        expect(input.name).not.toBe('');
        expect(input.type).toBe(type);
        expect(input.autocomplete).toBe(autocomplete);
        expect(input.required).toBe(true);
        expect(input.disabled).toBe(false);
        expect(input.getAttribute('aria-invalid')).toBe('false');
        expect(input.hasAttribute('autofocus')).toBe(false);
        if (type === 'email') {
          expect(input.getAttribute('autocapitalize')).toBe('none');
          expect(input.getAttribute('spellcheck')).toBe('false');
        }
      }
      for (const [name, href] of links) {
        expect(screen.getByRole('link', { name }).getAttribute('href')).toBe(href);
      }
      expect(screen.getAllByRole('link')).toHaveLength(links.length + 1);
      const submit = screen.getByRole<HTMLButtonElement>('button', { name: action });
      expect(submit.type).toBe(Page === PasskeyPage ? 'button' : 'submit');
      expect(submit.disabled).toBe(Page !== PasskeyPage && Page !== RegistrationPage);
      if (Page !== PasskeyPage && Page !== RegistrationPage)
        expect(
          document.getElementById(submit.getAttribute('aria-describedby') ?? '')?.textContent
        ).toContain(notice);
      for (const button of [...container.querySelectorAll<HTMLButtonElement>('form button')]) {
        expect(button.getAttribute('type')).toBe(
          button === submit && Page !== PasskeyPage ? 'submit' : 'button'
        );
        if (button !== submit) expect(button.disabled).toBe(false);
      }
      for (const icon of container.querySelectorAll('svg'))
        expect(icon.getAttribute('aria-hidden')).toBe('true');
      expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
    }
  );

  it.each(routes.filter(({ Page }) => Page !== PasskeyPage && Page !== RegistrationPage))(
    '$path is disconnected in the initial server HTML, before hydration or JavaScript',
    async ({ Page }) => {
      const html = renderToStaticMarkup(await AuthLayout({ children: await Page() }));
      const document = new DOMParser().parseFromString(html, 'text/html');
      expect(document.forms).toHaveLength(1);
      const form = document.forms[0];
      expect(form.getAttribute('method')).toBe('post');
      expect(form.getAttribute('action')).toBeNull();
      expect(form.textContent).toContain(notice);
      const buttons = [...form.querySelectorAll<HTMLButtonElement>('button[type="submit"]')];
      expect(buttons).toHaveLength(1);
      expect(buttons[0].disabled).toBe(true);
      expect(document.querySelector('style, script, [style], [onclick], [formaction]')).toBeNull();
    }
  );

  it('server-renders a disabled non-submitting passkey button without initiating a ceremony', async () => {
    const html = renderToStaticMarkup(await AuthLayout({ children: await PasskeyPage() }));
    const document = new DOMParser().parseFromString(html, 'text/html');
    expect(document.forms).toHaveLength(0);
    const button = document.querySelector<HTMLButtonElement>('[data-testid="passkey-login"]');
    expect(button?.disabled).toBe(true);
    expect(button?.type).toBe('button');
    expect(document.querySelector('style, script, [style], [onclick], [formaction]')).toBeNull();
  });
});

describe('disconnected route interaction', () => {
  const fetch = jest.fn();
  const credentials = { get: jest.fn(), create: jest.fn() };
  const sendBeacon = jest.fn();
  const capabilities = [
    { object: globalThis, key: 'fetch', value: fetch },
    { object: navigator, key: 'credentials', value: credentials },
    { object: navigator, key: 'sendBeacon', value: sendBeacon },
  ];
  const originals = capabilities.map(({ object, key }) =>
    Object.getOwnPropertyDescriptor(object, key)
  );

  beforeAll(() => {
    for (const { object, key, value } of capabilities)
      Object.defineProperty(object, key, { configurable: true, value });
  });
  afterAll(() => {
    capabilities.forEach(({ object, key }, index) => {
      const original = originals[index];
      if (original) Object.defineProperty(object, key, original);
      else Reflect.deleteProperty(object, key);
    });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  it.each(routes.filter(({ Page }) => Page !== PasskeyPage && Page !== RegistrationPage))(
    '$path keeps the notice and prevents submission without network, WebAuthn, storage, or navigation',
    async ({ Page, action, fields }) => {
      const requests = [
        fetch,
        credentials.get,
        credentials.create,
        sendBeacon,
        jest.spyOn(XMLHttpRequest.prototype, 'open').mockImplementation(() => undefined),
        jest.spyOn(XMLHttpRequest.prototype, 'send').mockImplementation(() => undefined),
        jest.spyOn(window, 'localStorage', 'get'),
        jest.spyOn(window, 'sessionStorage', 'get'),
        jest.spyOn(document, 'cookie', 'set').mockImplementation(() => undefined),
      ];
      const initialUrl = window.location.href;
      const { container } = render(await AuthLayout({ children: await Page() }));
      const form = screen.getByRole<HTMLFormElement>('form');
      expect(form.method).toBe('post');
      expect(form.getAttribute('action')).toBeNull();

      for (const [label, type] of fields) {
        const input = screen.getByLabelText<HTMLInputElement>(label);
        fireEvent.blur(input);
        expect(input.getAttribute('aria-invalid')).toBe('true');
        fireEvent.change(input, {
          target: {
            value:
              type === 'email'
                ? 'preview@example.test'
                : type === 'password'
                  ? 'not a real credential'
                  : '012345',
          },
        });
        fireEvent.blur(input);
        expect(input.getAttribute('aria-invalid')).toBe('false');
        fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
      }
      for (const toggle of screen.queryAllByRole('button', { name: /^Show / })) {
        fireEvent.click(toggle);
        expect(toggle.getAttribute('aria-pressed')).toBe('true');
        fireEvent.click(toggle);
      }
      const submit = screen.getByRole<HTMLButtonElement>('button', { name: action });
      fireEvent.click(submit);
      expect(fireEvent.submit(form)).toBe(false);
      expect(submit.disabled).toBe(true);
      expect(form.textContent).toContain(notice);
      expect(form.querySelector('[role="status"]')?.textContent).toBe('');
      expect(screen.queryByRole('alert')).toBeNull();
      expect(window.location.href).toBe(initialUrl);
      for (const request of requests) expect(request).not.toHaveBeenCalled();
      expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
    }
  );
});

describe('Persian public auth pages', () => {
  it.each([
    [LoginPage, loginMetadata, 'ورود به هاتف', 'ورود | هویت هاتف', 'ورود با گذرواژه'],
    [
      RegistrationPage,
      registrationMetadata,
      'حساب خود را ایجاد کنید',
      'ایجاد حساب | هویت هاتف',
      'شروع ثبت‌نام و ارسال ایمیل',
    ],
    [
      PasskeyPage,
      passkeyMetadata,
      'ورود با کلید عبور',
      'ورود با کلید عبور | هویت هاتف',
      'استفاده از کلید عبور',
    ],
    [
      TotpPage,
      totpMetadata,
      'کد رمزساز خود را تأیید کنید',
      'تأیید کد رمزساز | هویت هاتف',
      'تأیید کد',
    ],
    [
      ForgotPasswordPage,
      forgotMetadata,
      'گذرواژهٔ خود را بازنشانی کنید',
      'بازنشانی گذرواژه | هویت هاتف',
      'ارسال پیوند بازنشانی',
    ],
    [
      ResetPasswordPage,
      resetMetadata,
      'تعیین گذرواژهٔ جدید',
      'تعیین گذرواژهٔ جدید | هویت هاتف',
      'بازنشانی گذرواژه',
    ],
  ] as const)(
    'server-resolves the Persian heading, metadata and accessible action for %s',
    async (Page, metadata, heading, title, action) => {
      mockPageLocale = 'fa-IR';
      const content = await AuthLayout({ children: await Page() });
      const { container } = render(content, { locale: 'fa-IR' });
      expect((await metadata()).title).toBe(title);
      expect(screen.getByRole('heading', { name: heading, level: 1 })).toBeTruthy();
      expect(screen.getByRole('button', { name: action })).toBeTruthy();
      expect(screen.getByRole('combobox', { name: 'زبان' })).toBeTruthy();
      expect(screen.getByRole('link', { name: 'صفحهٔ اصلی هویت هاتف' }).getAttribute('href')).toBe(
        '/'
      );
      for (const input of container.querySelectorAll<HTMLInputElement>('input')) {
        expect(input.dir).toBe(input.name === 'email' && input.type === 'text' ? 'auto' : 'ltr');
        expect(input.getAttribute('aria-invalid')).toBe('false');
      }
      if (Page !== PasskeyPage && Page !== RegistrationPage) {
        expect(screen.getByRole<HTMLButtonElement>('button', { name: action }).disabled).toBe(true);
        expect(
          screen.getByText('این فرم هنوز متصل نیست. اطلاعات ورود واقعی را وارد نکنید.')
        ).toBeTruthy();
      }
    }
  );
});
