jest.mock('next-intl/server', () => ({
  getTranslations: (namespace: string) =>
    jest.requireActual('../i18n/testing').getTestTranslations(namespace, mockPageLocale),
}));

import { render, screen } from '../i18n/testing';
import { renderToStaticMarkup as renderStatic } from 'react-dom/server';
import type { ReactElement } from 'react';
import { I18nTestProvider } from '../i18n/testing';
import AuthLayout from '../app/(auth)/layout';
import ForgotPasswordPage, { generateMetadata as forgotMetadata } from '../app/(auth)/forgot-password/page';
import LoginPage, { generateMetadata as loginMetadata } from '../app/(auth)/login/page';
import PasskeyPage, { generateMetadata as passkeyMetadata } from '../app/(auth)/login/webauthn/page';
import RegistrationPage, { generateMetadata as registrationMetadata } from '../app/(auth)/register/page';
import VerifyEmailPage, { generateMetadata as verifyEmailMetadata } from '../app/(auth)/register/verify-email/page';
import ResetPasswordPage, { generateMetadata as resetMetadata } from '../app/(auth)/reset-password/page';
import TotpPage, { generateMetadata as totpMetadata } from '../app/(auth)/verify-totp/page';

jest.mock('next/navigation', () => ({ useRouter: () => ({ replace: jest.fn() }) }));

type Locale = 'en' | 'fa-IR';
let mockPageLocale: Locale = 'en';
afterEach(() => {
  mockPageLocale = 'en';
});

const presentation = {
  en: {
    home: 'Hatef Identity home',
    language: 'Language',
    register: 'Create an account',
    signIn: 'Sign in',
    continue: 'Continue with a passkey',
    use: 'Use a passkey',
    return: 'Return to sign in',
    start: 'Start registration and send email',
    notice: 'Use a passkey to sign in to an existing account, or create an account with email, phone and passkey verification.',
  },
  'fa-IR': {
    home: 'صفحهٔ اصلی هویت هاتف',
    language: 'زبان',
    register: 'ایجاد حساب',
    signIn: 'ورود',
    continue: 'ادامه با کلید عبور',
    use: 'استفاده از کلید عبور',
    return: 'بازگشت به ورود',
    start: 'شروع ثبت‌نام و ارسال ایمیل',
    notice: 'برای ورود به حساب موجود از کلید عبور استفاده کنید، یا با تأیید ایمیل، تلفن و کلید عبور حساب بسازید.',
  },
};
const routes = [
  {
    path: '/login', Page: LoginPage, metadata: loginMetadata,
    headings: ['Sign in to Hatef', 'ورود به هاتف'],
    titles: ['Sign in | Hatef Identity', 'ورود | هویت هاتف'],
  },
  {
    path: '/register', Page: RegistrationPage, metadata: registrationMetadata,
    headings: ['Create your account', 'حساب خود را ایجاد کنید'],
    titles: ['Create an account | Hatef Identity', 'ایجاد حساب | هویت هاتف'],
  },
  {
    path: '/login/webauthn', Page: PasskeyPage, metadata: passkeyMetadata,
    headings: ['Sign in with a passkey', 'ورود با کلید عبور'],
    titles: ['Sign in with a passkey | Hatef Identity', 'ورود با کلید عبور | هویت هاتف'],
  },
  {
    path: '/verify-totp', Page: TotpPage, metadata: totpMetadata,
    headings: ['Authenticator sign-in unavailable', 'ورود با رمزساز در دسترس نیست'],
    titles: ['Authenticator sign-in unavailable | Hatef Identity', 'ورود با رمزساز در دسترس نیست | هویت هاتف'],
  },
  {
    path: '/forgot-password', Page: ForgotPasswordPage, metadata: forgotMetadata,
    headings: ['Password reset unavailable', 'بازنشانی گذرواژه در دسترس نیست'],
    titles: ['Password reset unavailable | Hatef Identity', 'بازنشانی گذرواژه در دسترس نیست | هویت هاتف'],
  },
  {
    path: '/reset-password', Page: ResetPasswordPage, metadata: resetMetadata,
    headings: ['Password reset unavailable', 'بازنشانی گذرواژه در دسترس نیست'],
    titles: ['Password reset unavailable | Hatef Identity', 'بازنشانی گذرواژه در دسترس نیست | هویت هاتف'],
  },
];
const unavailable = routes.filter(({ Page }) => [TotpPage, ForgotPasswordPage, ResetPasswordPage].includes(Page));
const staticMarkup = (element: ReactElement, locale: Locale) =>
  renderStatic(<I18nTestProvider locale={locale}>{element}</I18nTestProvider>);

describe.each(['en', 'fa-IR'] as const)('public auth routes in %s', (locale) => {
  it.each(routes)('$path exposes one task heading, supported navigation and safe controls', async ({ Page, metadata, headings, titles }) => {
    mockPageLocale = locale;
    const copy = presentation[locale];
    const index = locale === 'en' ? 0 : 1;
    const { container } = render(await AuthLayout({ children: await Page() }), { locale });
    expect((await metadata()).title).toBe(titles[index]);
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { name: headings[index], level: 1 })).toBeTruthy();
    expect(screen.getByRole('link', { name: copy.home }).getAttribute('href')).toBe('/');
    expect(screen.getByRole('combobox', { name: copy.language })).toBeTruthy();
    expect(document.activeElement).toBe(document.body);

    if (Page === RegistrationPage) {
      const fields = locale === 'en'
        ? ['Email address', 'Iranian mobile number']
        : ['نشانی ایمیل', 'شمارهٔ همراه ایران'];
      expect(container.querySelectorAll('input')).toHaveLength(2);
      fields.forEach((label, fieldIndex) => {
        const input = screen.getByLabelText<HTMLInputElement>(label);
        expect(input.id).not.toBe('');
        expect(container.querySelector(`label[for="${input.id}"]`)?.textContent).toBe(label);
        expect(input.type).toBe(fieldIndex ? 'tel' : 'text');
        expect(input.autocomplete).toBe(fieldIndex ? 'tel' : 'email');
        expect(input.required).toBe(true);
        expect(input.disabled).toBe(false);
        expect(input.dir).toBe('ltr');
        expect(input.getAttribute('aria-invalid')).toBe('false');
        expect(input.hasAttribute('autofocus')).toBe(false);
      });
      const submit = screen.getByRole<HTMLButtonElement>('button', { name: copy.start });
      expect(submit.type).toBe('submit');
      expect(submit.disabled).toBe(false);
      expect(screen.getByRole('link', { name: copy.signIn }).getAttribute('href')).toBe('/login');
    } else if (Page === LoginPage || Page === PasskeyPage) {
      const action = screen.getByRole<HTMLButtonElement>('button', { name: Page === LoginPage ? copy.continue : copy.use });
      expect(action.type).toBe('button');
      expect(action.disabled).toBe(false);
      expect(container.querySelector('input, form')).toBeNull();
      expect(screen.getByRole('link', { name: Page === LoginPage ? copy.register : copy.return }).getAttribute('href')).toBe(Page === LoginPage ? '/register' : '/login');
      expect(container.querySelector('a[href="/forgot-password"]')).toBeNull();
      expect(container.textContent).not.toContain(locale === 'en' ? 'or use your password' : 'یا از گذرواژهٔ خود استفاده کنید');
    } else {
      expect(screen.getByText(copy.notice)).toBeTruthy();
      expect(screen.getByRole('link', { name: copy.continue }).getAttribute('href')).toBe('/login');
      expect(screen.getByRole('link', { name: copy.register }).getAttribute('href')).toBe('/register');
      expect(screen.getAllByRole('link')).toHaveLength(3);
      expect(container.querySelector('input, form, button[type="submit"]')).toBeNull();
      expect(container.textContent).not.toContain(locale === 'en' ? 'UI preview' : 'پیش‌نمایش رابط کاربری');
    }
    for (const icon of container.querySelectorAll('svg')) expect(icon.getAttribute('aria-hidden')).toBe('true');
    expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
  });

  it.each(unavailable)('$path retains useful no-JS notices and links without credential forms', async ({ Page }) => {
    mockPageLocale = locale;
    const doc = new DOMParser().parseFromString(staticMarkup(await AuthLayout({ children: await Page() }), locale), 'text/html');
    expect(doc.body.textContent).toContain(presentation[locale].notice);
    expect(doc.forms).toHaveLength(0);
    expect(doc.querySelector('input, button[type="submit"], [formaction], style, script, [style], [onclick]')).toBeNull();
    expect(doc.querySelector('a[href="/login"]')?.textContent).toBe(presentation[locale].continue);
    expect(doc.querySelector('a[href="/register"]')?.textContent).toBe(presentation[locale].register);
  });

  it.each([LoginPage, PasskeyPage])('server-renders an inert passkey action with no ceremony or submitting form', async (Page) => {
    mockPageLocale = locale;
    const doc = new DOMParser().parseFromString(staticMarkup(await AuthLayout({ children: await Page() }), locale), 'text/html');
    const button = doc.querySelector<HTMLButtonElement>('[data-testid="passkey-login"]');
    expect(button?.disabled).toBe(true);
    expect(button?.type).toBe('button');
    expect(doc.querySelector('input, form, script, [formaction]')).toBeNull();
    expect(doc.querySelector('noscript')?.textContent).toContain(locale === 'en' ? 'JavaScript is required' : 'جاوااسکریپت لازم است');
  });

  it('keeps registration-email metadata stable, private-value-free and separate from unavailable auth routes', async () => {
    mockPageLocale = locale;
    const metadata = await verifyEmailMetadata();
    expect(metadata).toEqual({ title: locale === 'en' ? 'Verify registration email | Hatef Identity' : 'تأیید ایمیل ثبت‌نام | هویت هاتف', referrer: 'no-referrer' });
    const html = staticMarkup(await AuthLayout({ children: await VerifyEmailPage() }), locale);
    const doc = new DOMParser().parseFromString(html, 'text/html');
    expect(doc.querySelectorAll('h1')).toHaveLength(1);
    expect(doc.querySelector('h1')?.textContent).toBe(locale === 'en' ? 'Verify your email ownership' : 'مالکیت ایمیل خود را تأیید کنید');
    expect(doc.querySelector<HTMLButtonElement>('button[data-testid="passkey-login"]')).toBeNull();
  });
});

describe('availability-page safety', () => {
  const fetch = jest.fn();
  const credentials = { get: jest.fn(), create: jest.fn() };
  const sendBeacon = jest.fn();
  const capabilities = [
    { object: globalThis, key: 'fetch', value: fetch },
    { object: navigator, key: 'credentials', value: credentials },
    { object: navigator, key: 'sendBeacon', value: sendBeacon },
  ];
  const originals = capabilities.map(({ object, key }) => Object.getOwnPropertyDescriptor(object, key));
  beforeAll(() => {
    for (const { object, key, value } of capabilities) Object.defineProperty(object, key, { configurable: true, value });
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
  it.each(unavailable)('$path does not request, access storage, write cookies or navigate on mount', async ({ Page }) => {
    const requests = [
      fetch, credentials.get, credentials.create, sendBeacon,
      jest.spyOn(XMLHttpRequest.prototype, 'open').mockImplementation(() => undefined),
      jest.spyOn(XMLHttpRequest.prototype, 'send').mockImplementation(() => undefined),
      jest.spyOn(window, 'localStorage', 'get'),
      jest.spyOn(window, 'sessionStorage', 'get'),
      jest.spyOn(document, 'cookie', 'set').mockImplementation(() => undefined),
    ];
    const initialUrl = window.location.href;
    const { container } = render(await AuthLayout({ children: await Page() }));
    expect(container.querySelector('input, form, [formaction]')).toBeNull();
    expect(screen.getByText(presentation.en.notice)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(window.location.href).toBe(initialUrl);
    for (const request of requests) expect(request).not.toHaveBeenCalled();
  });
});
