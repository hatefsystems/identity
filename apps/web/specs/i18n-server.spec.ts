/** @jest-environment node */

import { AsyncLocalStorage } from 'node:async_hooks';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import RootLayout from '../app/layout';
import { themeInitializer } from '../i18n/theme';
import { getDisplayPreferences } from '../i18n/server';
import { saveDisplayPreferences } from '../i18n/actions';
import { defaultPreferences, preferenceCookie, preferenceMaxAge } from '../i18n/config';

const mockRequest = new AsyncLocalStorage<{ value?: string; header?: string; set: jest.Mock }>();

jest.mock('server-only', () => ({}), { virtual: true });
jest.mock('next/font/local', () => ({ __esModule: true, default: () => ({ className: 'persian-font' }) }));
jest.mock('next/server', () => ({ connection: async () => undefined }));
jest.mock('next-intl/server', () => ({ getTranslations: jest.fn() }));
jest.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === '__Host-hatef-ui' ? { value: mockRequest.getStore()?.value } : undefined,
    set: (...args: unknown[]) => mockRequest.getStore()?.set(...args),
  }),
  headers: async () => ({
    get: (name: string) => name === 'x-nonce' ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' : (name === 'cookie' ? (mockRequest.getStore()?.header ?? null) : null),
  }),
}));

describe('request-scoped display preference resolution', () => {
  it.each(['system', 'light', 'dark'] as const)('SSR emits validated %s appearance with a request nonce only for System', async (theme) => {
    const html = await mockRequest.run({ value: `2~fa-IR~persian~Asia/Tehran~${theme}`, set: jest.fn() }, async () =>
      renderToStaticMarkup(await RootLayout({ children: createElement('main') }))
    );
    expect(html).toContain('lang="fa-IR"');
    expect(html).toContain('dir="rtl"');
    expect(html).toContain(`data-theme="${theme}"`);
    expect(html.includes('class="dark"')).toBe(theme === 'dark');
    if (theme === 'system') {
      expect(html).toContain(`<script nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=">${themeInitializer}</script>`);
      expect(html.indexOf(themeInitializer)).toBeLessThan(html.indexOf('<body'));
    } else expect(html).not.toContain('<script');
    expect(html).not.toContain(' style=');
  });

  it('isolates concurrent English/Persian requests and never follows Accept-Language', async () => {
    const [persian, english] = await Promise.all([
      mockRequest.run({ value: '1~fa-IR~gregory~Asia/Tehran', set: jest.fn() }, async () => {
        await Promise.resolve();
        return getDisplayPreferences();
      }),
      mockRequest.run({ set: jest.fn() }, () => getDisplayPreferences()),
    ]);
    expect(persian).toEqual({ locale: 'fa-IR', calendar: 'gregory', timeZone: 'Asia/Tehran', theme: 'system' });
    expect(english).toEqual(defaultPreferences);
  });

  it('fails safely for duplicate preference cookies even after store collapse', async () => {
    await mockRequest.run(
      {
        value: '1~fa-IR~auto~UTC',
        header: `${preferenceCookie}=1~en~auto~UTC; ${preferenceCookie}=1~fa-IR~auto~UTC`,
        set: jest.fn(),
      },
      async () => {
        expect(await getDisplayPreferences()).toEqual(defaultPreferences);
      }
    );
  });

  it('writes only the host-only secure HttpOnly preference cookie with bounded lifetime', async () => {
    const set = jest.fn();
    await mockRequest.run({ set }, async () => {
      expect(
        await saveDisplayPreferences({ locale: 'fa-IR', calendar: 'auto', timeZone: 'US/Eastern', theme: 'dark' })
      ).toEqual({ ok: true });
    });
    expect(set).toHaveBeenCalledTimes(1);
    expect(set).toHaveBeenCalledWith(preferenceCookie, '2~fa-IR~auto~America/New_York~dark', {
      secure: true,
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
      maxAge: preferenceMaxAge,
    });
  });

  it('does not touch cookies on invalid preference submissions', async () => {
    const set = jest.fn();
    await mockRequest.run({ set }, async () => {
      expect(await saveDisplayPreferences({ ...defaultPreferences, locale: 'ar' })).toEqual({
        ok: false,
      });
      expect(await saveDisplayPreferences({ ...defaultPreferences, extra: 'secret' })).toEqual({
        ok: false,
      });
      expect(await saveDisplayPreferences({ locale: 'en', calendar: 'auto', timeZone: 'UTC' })).toEqual({ ok: false });
      expect(await saveDisplayPreferences({ ...defaultPreferences, theme: 'unsupported' })).toEqual({ ok: false });
    });
    expect(set).not.toHaveBeenCalled();
  });
});
