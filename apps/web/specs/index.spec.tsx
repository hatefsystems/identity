jest.mock('next-intl/server', () => ({
  getTranslations: (...args: unknown[]) =>
    jest.requireActual('../i18n/testing').getTestTranslations(...args),
}));

import { render, screen } from '../i18n/testing';
import Page from '../app/page';

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
