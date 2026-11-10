jest.mock('next-intl/server', () => ({
  getTranslations: (namespace: string) =>
    jest.requireActual('../i18n/testing').getTestTranslations(namespace, mockIndexLocale),
}));

import { render, screen } from '../i18n/testing';
import Page from '../app/page';
import NotFound from '../app/not-found';

let mockIndexLocale: 'en' | 'fa-IR' = 'en';
afterEach(() => { mockIndexLocale = 'en'; });

describe('Page', () => {
  it('preserves the homepage heading and links to the sign-in and registration routes', async () => {
    const { container } = render(await Page());

    expect(screen.getByRole('heading', { level: 1, name: 'Hatef Identity Platform' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Sign in' }).getAttribute('href')).toBe('/login');
    expect(screen.getByRole('link', { name: 'Create an account' }).getAttribute('href')).toBe(
      '/register'
    );
    expect(screen.getByRole('combobox', { name: 'Language' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Use device time zone', hidden: true })).toBeTruthy();
    expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
  });
});

describe.each(['en', 'fa-IR'] as const)('public product identity in %s', (locale) => {
  it.each([Page, NotFound])('uses the same localized, isolated home wordmark and display controls', async (Surface) => {
    mockIndexLocale = locale;
    const { container } = render(await Surface(), { locale });
    const home = screen.getByRole('link', { name: locale === 'en' ? 'Hatef Identity home' : 'صفحهٔ اصلی هویت هاتف' });
    expect(home.getAttribute('href')).toBe('/');
    expect(home.textContent).toBe(locale === 'en' ? 'Hatef Identity' : 'هویت هاتف');
    expect(home.querySelector('bdi')?.getAttribute('dir')).toBe('auto');
    expect(home.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByLabelText(locale === 'en' ? 'Language' : 'زبان')).toBeTruthy();
    expect(screen.getByLabelText(locale === 'en' ? 'Appearance' : 'ظاهر')).toBeTruthy();
    if (Surface === NotFound) expect(screen.getByRole('link', { name: locale === 'en' ? 'Return home' : 'بازگشت به صفحهٔ اصلی' }).getAttribute('href')).toBe('/');
    expect(container.querySelector('[style], style, script, [onclick]')).toBeNull();
  });
});
