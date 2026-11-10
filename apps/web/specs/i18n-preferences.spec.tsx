import { useEffect, useState } from 'react';
import { render as renderWithoutProvider } from '@testing-library/react';
import { act, fireEvent, render, screen, waitFor, I18nTestProvider } from '../i18n/testing';
import { PreferenceControls } from '../i18n/preferences';
import { saveDisplayPreferences } from '../i18n/actions';
import { useMessage } from '../i18n/use-message';
import { useDisplayPreferences } from '../i18n/provider';
import type { ThemePreference } from '../i18n/config';

jest.mock('../i18n/actions', () => ({ saveDisplayPreferences: jest.fn() }));
const save = jest.mocked(saveDisplayPreferences);

beforeEach(() => save.mockReset());

describe('explicit display preference controls', () => {
  it('does not persist or infer preferences on mount', () => {
    render(<PreferenceControls />);
    expect(save).not.toHaveBeenCalled();
    expect((screen.getByRole('combobox', { name: 'Language' }) as HTMLSelectElement).value).toBe(
      'en'
    );
    expect(screen.getByText('Display settings')).toBeTruthy();
  });

  it.each([
    ['en', 'Appearance', 'Dark'],
    ['fa-IR', 'ظاهر', 'تیره'],
  ] as const)('saves an explicit appearance choice in %s without changing failed presentation', async (locale, appearance, darkLabel) => {
    save.mockResolvedValue({ ok: false });
    render(<PreferenceControls />, { locale, preferences: { theme: 'dark' } });
    const control = screen.getByLabelText<HTMLSelectElement>(appearance);
    expect(control.value).toBe('dark');
    expect(screen.getByRole('option', { name: darkLabel })).toBeTruthy();
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    fireEvent.change(control, { target: { value: 'light' } });
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    await waitFor(() => expect(control.disabled).toBe(false));
    expect(save).toHaveBeenCalledWith({ locale, calendar: 'auto', timeZone: 'UTC', theme: 'light' });
    expect(control.value).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('serializes rapid saves and retains the old presentation on failure', async () => {
    let finish!: (result: { ok: boolean }) => void;
    save.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        })
    );
    render(<PreferenceControls />);
    const language = screen.getByRole('combobox', { name: 'Language' });
    fireEvent.change(language, { target: { value: 'fa-IR' } });
    fireEvent.change(language, { target: { value: 'en' } });
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ locale: 'fa-IR', calendar: 'auto', timeZone: 'UTC', theme: 'system' });
    expect((language as HTMLSelectElement).disabled).toBe(true);
    await act(async () => finish({ ok: false }));
    expect(
      screen.getByText('Preferences could not be saved. Your previous settings are unchanged.')
    ).toBeTruthy();
    expect((language as HTMLSelectElement).value).toBe('en');
    expect((language as HTMLSelectElement).disabled).toBe(false);
  });

  it('localizes save failures without displaying exceptions', async () => {
    save.mockRejectedValue(new Error('private server failure'));
    render(<PreferenceControls />, { locale: 'fa-IR' });
    fireEvent.change(screen.getByRole('combobox', { name: 'زبان' }), { target: { value: 'en' } });
    await waitFor(() =>
      expect(
        screen.getByText('ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.')
      ).toBeTruthy()
    );
    expect(screen.queryByText('private server failure')).toBeNull();
  });

  it('submits concrete display settings only through explicit controls', async () => {
    save.mockResolvedValue({ ok: true });
    render(<PreferenceControls />, {
      locale: 'fa-IR',
      preferences: { calendar: 'gregory', timeZone: 'Asia/Tehran' },
    });
    fireEvent.click(screen.getByText('تنظیمات نمایش'));
    fireEvent.change(screen.getByLabelText('تقویم'), { target: { value: 'persian' } });
    await waitFor(() => expect(screen.getByText('تنظیمات ذخیره شد.')).toBeTruthy());
    expect(save).toHaveBeenLastCalledWith({
      locale: 'fa-IR',
      calendar: 'persian',
      timeZone: 'Asia/Tehran',
      theme: 'system',
    });
    expect(document.querySelector('[data-ui-preferences] form')).toBeNull();
    expect(
      screen.getByRole('button', { name: 'استفاده از منطقهٔ زمانی دستگاه' }).getAttribute('type')
    ).toBe('button');
  });

  it('updates feedback and preferences without remounting or resetting local state', () => {
    const mount = jest.fn();
    const unmount = jest.fn();
    function Probe() {
      const [draft, setDraft] = useState('unchanged draft');
      const translate = useMessage();
      const preferences = useDisplayPreferences();
      useEffect(() => {
        mount();
        return unmount;
      }, []);
      return (
        <>
          <input
            aria-label="test draft"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          <p>{translate({ key: 'common.pageError' })}</p>
          <output>
            {preferences.calendar}/{preferences.timeZone}
          </output>
        </>
      );
    }
    const view = render(
      <I18nTestProvider locale="en" preferences={{ calendar: 'gregory', timeZone: 'Asia/Tehran' }}>
        <Probe />
      </I18nTestProvider>
    );
    fireEvent.change(screen.getByRole('textbox', { name: 'test draft' }), {
      target: { value: 'preserved draft' },
    });
    view.rerender(
      <I18nTestProvider
        locale="fa-IR"
        preferences={{ calendar: 'gregory', timeZone: 'Asia/Tehran' }}
      >
        <Probe />
      </I18nTestProvider>
    );
    expect(screen.getByText('مشکلی پیش آمد')).toBeTruthy();
    expect((screen.getByRole('textbox', { name: 'test draft' }) as HTMLInputElement).value).toBe(
      'preserved draft'
    );
    expect(screen.getByText('gregory/Asia/Tehran')).toBeTruthy();
    expect(mount).toHaveBeenCalledTimes(1);
    expect(unmount).not.toHaveBeenCalled();
  });
});

describe('stable browser appearance controller', () => {
  const original = Object.getOwnPropertyDescriptor(window, 'matchMedia');
  afterEach(() => {
    if (original) Object.defineProperty(window, 'matchMedia', original);
    else Reflect.deleteProperty(window, 'matchMedia');
    document.documentElement.classList.remove('dark');
    document.documentElement.removeAttribute('data-theme');
  });

  it.each(['en', 'fa-IR'] as const)('covers all selected-mode/OS combinations in %s and follows OS only in System', (locale) => {
    for (const theme of ['system', 'light', 'dark'] as const) for (const osDark of [false, true]) {
      const listeners = new Set<() => void>();
      const query = {
        matches: osDark,
        addEventListener: jest.fn((_type: string, callback: () => void) => listeners.add(callback)),
        removeEventListener: jest.fn((_type: string, callback: () => void) => listeners.delete(callback)),
      };
      const matchMedia = jest.fn(() => query);
      Object.defineProperty(window, 'matchMedia', { configurable: true, value: matchMedia });
      const view = render(<span />, { locale, preferences: { theme } });
      expect(document.documentElement.getAttribute('data-theme')).toBe(theme);
      expect(document.documentElement.classList.contains('dark')).toBe(theme === 'dark' || (theme === 'system' && osDark));
      expect(matchMedia).toHaveBeenCalledTimes(theme === 'system' ? 1 : 0);
      act(() => { query.matches = !osDark; for (const callback of listeners) callback(); });
      expect(document.documentElement.classList.contains('dark')).toBe(theme === 'dark' || (theme === 'system' && !osDark));
      expect(save).not.toHaveBeenCalled();
      view.unmount();
      expect(listeners.size).toBe(0);
    }
  });

  it('applies successful presentation props before paint without remounting security work or restarting media on language changes', () => {
    const listeners = new Set<() => void>();
    const query = { matches: true, addEventListener: (_type: string, callback: () => void) => listeners.add(callback), removeEventListener: (_type: string, callback: () => void) => listeners.delete(callback) };
    const matchMedia = jest.fn(() => query);
    Object.defineProperty(window, 'matchMedia', { configurable: true, value: matchMedia });
    const mount = jest.fn();
    const unmount = jest.fn();
    function Probe() { useEffect(() => { mount(); return unmount; }, []); return <input aria-label="appearance draft" defaultValue="draft" />; }
    const viewFor = (locale: 'en' | 'fa-IR', theme: ThemePreference) => <I18nTestProvider locale={locale} preferences={{ theme }}><Probe /></I18nTestProvider>;
    const view = renderWithoutProvider(viewFor('en', 'system'));
    const input = screen.getByLabelText<HTMLInputElement>('appearance draft');
    fireEvent.change(input, { target: { value: 'preserved draft' } });
    view.rerender(viewFor('fa-IR', 'system'));
    expect(matchMedia).toHaveBeenCalledTimes(1);
    expect(listeners.size).toBe(1);
    view.rerender(viewFor('fa-IR', 'light'));
    expect(listeners.size).toBe(0);
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    view.rerender(viewFor('en', 'dark'));
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(screen.getByLabelText('appearance draft')).toBe(input);
    expect(input.value).toBe('preserved draft');
    expect(mount).toHaveBeenCalledTimes(1);
    expect(unmount).not.toHaveBeenCalled();
  });

  it('falls back to light with unavailable OS detection without storing a browser preference', () => {
    Reflect.deleteProperty(window, 'matchMedia');
    document.documentElement.classList.add('dark');
    render(<span />, { preferences: { theme: 'system' } });
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(save).not.toHaveBeenCalled();
  });
});
