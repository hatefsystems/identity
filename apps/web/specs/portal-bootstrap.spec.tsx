jest.mock('next-intl/server', () => ({
  getTranslations: (...args: unknown[]) =>
    jest.requireActual('../i18n/testing').getTestTranslations(...args),
}));

import { act, fireEvent, render, screen, waitFor, within } from '../i18n/testing';
import { renderToStaticMarkup as renderStatic } from 'react-dom/server';
import type { ReactElement } from 'react';
import { I18nTestProvider } from '../i18n/testing';
const renderToStaticMarkup = (element: ReactElement) =>
  renderStatic(<I18nTestProvider>{element}</I18nTestProvider>);
import { PortalProvider, usePortal } from '../app/dashboard/_components/portal-provider';
import { PortalClient, type SecurityChange } from '../app/_lib/portal/client';
import { passkeyResponse, type Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { clearSensitiveViews, invalidateOtherTabs, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';

const replace = jest.fn();
let mockPathname = '/dashboard';
jest.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useRouter: () => ({ replace }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({
  invalidateOtherTabs: jest.fn(),
  onOtherTabInvalidation: jest.fn(),
  clearSensitiveViews: jest.fn(),
  suspendSensitiveViews: jest.fn(),
  sensitiveClearEvent: 'portal-sensitive-clear',
}));

const profile = (): Profile => ({
  id: 'user-id',
  email: 'private@example.test',
  display_name: 'Private account',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '7',
  session: { id: 'session-id', expires_at: new Date(Date.now() + 60000).toISOString() },
});
function makeClient() {
  const value = profile();
  return {
    bootstrap: jest.fn().mockResolvedValue(value),
    dispose: jest.fn(),
    logout: jest.fn().mockResolvedValue(undefined),
    revokeSession: jest.fn().mockResolvedValue(undefined),
    profile: value as Profile | undefined,
    onSessionLoss: undefined as ((error: PortalError, settlingSecurity?: boolean) => void) | undefined,
    onSecurityChange: undefined as ((outcome: SecurityChange) => void) | undefined,
  };
}
function PrivateContent() {
  return <p>{usePortal().profile.email}</p>;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((finish) => { resolve = finish; });
  return { promise, resolve };
}
let api: ReturnType<typeof makeClient>;
let invalidate: () => void;
let visibility: PropertyDescriptor | undefined;
let mediaDescriptor: PropertyDescriptor | undefined;
beforeEach(() => {
  jest.clearAllMocks();
  mockPathname = '/dashboard';
  mediaDescriptor = Object.getOwnPropertyDescriptor(window, 'matchMedia');
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  api = makeClient();
  jest.mocked(PortalClient).mockImplementation(() => api as unknown as PortalClient);
  jest.mocked(onOtherTabInvalidation).mockImplementation((callback) => {
    invalidate = callback;
    return jest.fn();
  });
});
afterEach(() => {
  if (mediaDescriptor) Object.defineProperty(window, 'matchMedia', mediaDescriptor);
  else Reflect.deleteProperty(window, 'matchMedia');
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.useRealTimers();
});

describe('compact account navigation', () => {
  it.each([
    ['en', 'Account navigation', 'Current section: Sessions', 'Sessions', 'Admin', 'Sign out'],
    ['fa-IR', 'ناوبری حساب', 'بخش فعلی: نشست‌ها', 'نشست‌ها', 'مدیریت', 'خروج'],
  ] as const)(
    'labels the current section and preserves one ordered destination set in %s',
    async (locale, navLabel, currentSection, sessions, admin, signOut) => {
      mockPathname = '/dashboard/sessions';
      render(
        <PortalProvider><PrivateContent /></PortalProvider>,
        { locale }
      );
      await screen.findByTestId('portal-ready');
      const nav = within(screen.getByRole('navigation', { name: navLabel }));
      const toggle = nav.getByRole('button', { name: currentSection });
      const links = document.getElementById(toggle.getAttribute('aria-controls') as string) as HTMLElement;
      expect(toggle.getAttribute('aria-expanded')).toBe('false');
      expect(toggle.className).toContain('lg:hidden');
      expect(links.classList.contains('hidden')).toBe(true);
      expect(links.className).toContain('lg:block');
      expect(within(links).getAllByRole('link').map((link) => link.getAttribute('href'))).toEqual([
        '/dashboard', '/dashboard/profile', '/dashboard/security', '/dashboard/sessions', '/dashboard/privacy',
      ]);
      expect(nav.getByRole('link', { name: sessions }).getAttribute('aria-current')).toBe('page');
      expect(links.contains(nav.getByRole('link', { name: admin }))).toBe(false);
      expect(screen.getByRole('button', { name: signOut })).toBeTruthy();
      const clears = jest.mocked(clearSensitiveViews).mock.calls.length;
      fireEvent.click(toggle);
      expect(toggle.getAttribute('aria-expanded')).toBe('true');
      expect(links.classList.contains('hidden')).toBe(false);
      const current = nav.getByRole('link', { name: sessions });
      current.addEventListener('click', (event) => event.preventDefault());
      fireEvent.click(current);
      expect(toggle.getAttribute('aria-expanded')).toBe('false');
      expect(links.classList.contains('hidden')).toBe(true);
      expect(clearSensitiveViews).toHaveBeenCalledTimes(clears);
      expect(api.bootstrap).toHaveBeenCalledTimes(1);
      expect(api.logout).not.toHaveBeenCalled();
    }
  );

  it.each([false, true])('restores navigation after breakpoint changes with CSS body fallback %s without rebootstrap or draft loss', async (bodyFallback) => {
    let desktop = false;
    const listeners = new Set<() => void>();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: (query: string) => ({
        media: query,
        get matches() { return query === '(min-width: 1024px)' && desktop; },
        addEventListener: (_type: string, listener: () => void) => {
          if (query === '(min-width: 1024px)') listeners.add(listener);
        },
        removeEventListener: (_type: string, listener: () => void) => listeners.delete(listener),
      }),
    });
    mockPathname = '/dashboard/profile';
    render(
      <PortalProvider>
        <PrivateContent />
        <input aria-label="Private draft" defaultValue="" />
      </PortalProvider>
    );
    await screen.findByTestId('portal-ready');
    const draft = screen.getByLabelText<HTMLInputElement>('Private draft');
    fireEvent.change(draft, { target: { value: 'Draft kept in memory' } });
    const toggle = screen.getByRole('button', { name: 'Current section: Profile' });
    fireEvent.click(toggle);
    toggle.focus();
    const current = screen.getByRole('link', { name: 'Profile' });
    if (bodyFallback) toggle.blur();
    act(() => { desktop = true; listeners.forEach((listener) => listener()); });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(current);
    if (bodyFallback) current.blur();
    act(() => { desktop = false; listeners.forEach((listener) => listener()); });
    expect(document.activeElement).toBe(toggle);
    draft.focus();
    act(() => { desktop = true; listeners.forEach((listener) => listener()); });
    act(() => { desktop = false; listeners.forEach((listener) => listener()); });
    expect(document.activeElement).toBe(draft);
    expect(screen.getByLabelText('Private draft')).toBe(draft);
    expect(draft.value).toBe('Draft kept in memory');
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(PortalClient).toHaveBeenCalledTimes(1);
    expect(api.dispose).not.toHaveBeenCalled();
  });
});

describe('protected portal bootstrap', () => {
  it.each(['en', 'fa-IR'] as const)('withdraws private authority after concurrent401 but lets a deferred decoded security outcome win in %s', async (locale) => {
    jest.useFakeTimers();
    api.profile = { ...profile(), session: { id: 'session-id', expires_at: new Date(Date.now() + 1000).toISOString() } };
    api.bootstrap.mockResolvedValueOnce(api.profile);
    const body = deferred<unknown>();
    const content = (language: 'en' | 'fa-IR') => (
      <I18nTestProvider locale={language}><PortalProvider><PrivateContent /></PortalProvider></I18nTestProvider>
    );
    const view = render(content(locale));
    await screen.findByText('private@example.test');
    const pending = body.promise.then((value) => {
      passkeyResponse(value);
      api.onSecurityChange?.('passkeyAdded');
    });
    // Transport withdraws the shared profile before notifying the provider.
    api.profile = undefined;
    act(() => api.onSessionLoss?.(new PortalError('session_required', 401), true));
    expect(screen.queryByTestId('portal-ready')).toBeNull();
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByTestId('security-outcome')).toBeNull();
    expect(screen.queryByRole('link', { name: locale === 'en' ? 'Sign in with a passkey' : 'ورود با کلید عبور' })).toBeNull();
    expect(screen.queryByRole('button', { name: locale === 'en' ? 'Check current session' : 'بررسی نشست فعلی' })).toBeNull();
    expect(screen.getByText(locale === 'en' ? 'Applying the confirmed action...' : 'در حال اعمال عملیات تأییدشده...')).toBeTruthy();
    expect(api.dispose).not.toHaveBeenCalled();
    act(() => {
      invalidate();
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
      jest.advanceTimersByTime(1001);
    });
    const other = locale === 'en' ? 'fa-IR' : 'en';
    view.rerender(content(other));
    expect(api.dispose).not.toHaveBeenCalled();
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    await act(async () => {
      body.resolve({ id: 'key-id', name: 'Device', created_at: '2026-01-01T00:00:00Z', user_verified: true, backup_eligible: false, backup_state: false });
      await pending;
    });
    const outcome = screen.getByTestId('security-outcome');
    expect(outcome.getAttribute('data-outcome')).toBe('passkeyAdded');
    expect(within(outcome).getByRole('heading', { name: other === 'en' ? 'Security change saved' : 'تغییر امنیتی ذخیره شد' })).toBe(document.activeElement);
    expect(within(outcome).getByRole('status').textContent).toBe(other === 'en'
      ? 'Your passkey was added. Existing sessions, including this browser session, are no longer valid. Sign in again to continue.'
      : 'کلید عبور شما اضافه شد. نشست‌های موجود، از جمله نشست این مرورگر، دیگر معتبر نیستند. برای ادامه دوباره وارد شوید.');
    const login = within(outcome).getAllByRole('link', { name: other === 'en' ? 'Return to sign in' : 'بازگشت به ورود' });
    expect(login).toHaveLength(1);
    expect(login[0].getAttribute('href')).toBe('/login');
    expect(api.dispose).toHaveBeenCalledTimes(1);
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  });

  it.each(['en', 'fa-IR'] as const)('falls back to localized session loss in %s only after a deferred security body fails strict decoding', async (locale) => {
    const body = deferred<unknown>();
    const failure = new PortalError('session_required', 401);
    render(<PortalProvider><PrivateContent /></PortalProvider>, { locale });
    await screen.findByText('private@example.test');
    const pending = body.promise.then((value) => {
      try {
        passkeyResponse(value);
        api.onSecurityChange?.('passkeyAdded');
      } catch {
        api.onSessionLoss?.(failure);
      }
    });
    api.profile = undefined;
    act(() => api.onSessionLoss?.(failure, true));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(api.dispose).not.toHaveBeenCalled();
    await act(async () => { body.resolve({}); await pending; });
    expect(screen.queryByTestId('security-outcome')).toBeNull();
    expect(screen.queryByTestId('portal-ready')).toBeNull();
    expect(screen.getByRole('alert').textContent).toBe(locale === 'en'
      ? 'Your session is no longer available. Sign in again to continue.'
      : 'نشست شما دیگر در دسترس نیست. برای ادامه دوباره وارد شوید.');
    expect(screen.getByRole('link', { name: locale === 'en' ? 'Sign in with a passkey' : 'ورود با کلید عبور' })).toBeTruthy();
    expect(api.dispose).toHaveBeenCalledTimes(1);
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  });

  it.each(['en', 'fa-IR'] as const)('keeps a committed security outcome visible in %s before one explicit login return', async (locale) => {
    const content = (language: 'en' | 'fa-IR') => (
      <I18nTestProvider locale={language}><PortalProvider><PrivateContent /></PortalProvider></I18nTestProvider>
    );
    const view = render(content(locale));
    await screen.findByText('private@example.test');
    act(() => api.onSecurityChange?.('passkeyAdded'));
    expect(screen.getByTestId('security-outcome').getAttribute('data-outcome')).toBe('passkeyAdded');
    expect(screen.getByRole('heading', { name: locale === 'en' ? 'Security change saved' : 'تغییر امنیتی ذخیره شد' })).toBe(document.activeElement);
    expect(within(screen.getByTestId('security-outcome')).getByRole('status').textContent).toBe(locale === 'en'
      ? 'Your passkey was added. Existing sessions, including this browser session, are no longer valid. Sign in again to continue.'
      : 'کلید عبور شما اضافه شد. نشست‌های موجود، از جمله نشست این مرورگر، دیگر معتبر نیستند. برای ادامه دوباره وارد شوید.');
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(screen.queryByTestId('portal-ready')).toBeNull();
    act(() => {
      api.onSessionLoss?.(new PortalError('session_required', 401));
      invalidate();
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    const otherLocale = locale === 'en' ? 'fa-IR' : 'en';
    view.rerender(content(otherLocale));
    expect(screen.getByRole('heading', { name: otherLocale === 'en' ? 'Security change saved' : 'تغییر امنیتی ذخیره شد' })).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    expect(api.revokeSession).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
    const login = screen.getByRole('link', { name: otherLocale === 'en' ? 'Return to sign in' : 'بازگشت به ورود' });
    expect(login.getAttribute('href')).toBe('/login');
    expect(screen.getAllByRole('link', { name: otherLocale === 'en' ? 'Return to sign in' : 'بازگشت به ورود' })).toHaveLength(1);
  });

  it('server-renders only a non-sensitive shell and does not instantiate an API client', () => {
    const html = renderToStaticMarkup(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    expect(html).toContain('Checking your secure browser session');
    expect(html).not.toContain('private@example.test');
    expect(html).not.toContain('Private account');
    expect(PortalClient).not.toHaveBeenCalled();
  });

  it('does not expose children until bootstrap and clears on detected session loss', async () => {
    let finish!: (value: Profile) => void;
    api.bootstrap.mockReturnValueOnce(
      new Promise((resolve) => {
        finish = resolve;
      })
    );
    render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    expect(screen.queryByTestId('portal-ready')).toBeNull();
    expect(screen.queryByText('private@example.test')).toBeNull();
    await act(async () => finish(profile()));
    expect(screen.getByTestId('portal-ready')).toBeTruthy();
    expect(screen.getByText('private@example.test')).toBeTruthy();
    act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(api.dispose).toHaveBeenCalled();
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('alert').textContent).toContain('Sign in again');
  });

  it('drops late bootstrap replies after tab invalidation rather than mixing sessions', async () => {
    let finish!: (value: Profile) => void;
    api.bootstrap.mockReturnValueOnce(
      new Promise((resolve) => {
        finish = resolve;
      })
    );
    const old = api;
    render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    api = makeClient();
    api.bootstrap.mockResolvedValue({
      ...profile(),
      email: 'new@example.test',
      session: { ...profile().session, id: 'new-session' },
    });
    act(() => invalidate());
    await screen.findByText('new@example.test');
    await act(async () => finish(profile()));
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(old.dispose).toHaveBeenCalled();
    expect(invalidateOtherTabs).not.toHaveBeenCalled();
  });

  it('clears hidden and bfcache views without background polling, rechecking only on return', async () => {
    render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    await screen.findByText('private@example.test');
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    fireEvent(document, new Event('visibilitychange'));
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    fireEvent(document, new Event('visibilitychange'));
    await screen.findByText('private@example.test');
    expect(api.bootstrap).toHaveBeenCalledTimes(2);
    fireEvent(window, new Event('pagehide'));
    expect(screen.queryByText('private@example.test')).toBeNull();
    fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
    await screen.findByText('private@example.test');
    expect(api.bootstrap).toHaveBeenCalledTimes(3);
  });

  it('clears at absolute expiry and does not invent a usable session during dependency outages', async () => {
    jest.useFakeTimers();
    api.bootstrap.mockResolvedValueOnce({
      ...profile(),
      session: { ...profile().session, expires_at: new Date(Date.now() + 1000).toISOString() },
    });
    const view = render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    await act(async () => undefined);
    expect(screen.getByText('private@example.test')).toBeTruthy();
    act(() => jest.advanceTimersByTime(1001));
    expect(screen.queryByText('private@example.test')).toBeNull();
    view.unmount();
    jest.useRealTimers();
    api = makeClient();
    api.bootstrap.mockRejectedValueOnce(new PortalError('temporarily_unavailable', 503));
    render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    expect((await screen.findByRole('alert')).textContent).toContain('temporarily unavailable');
    expect(screen.queryByText('private@example.test')).toBeNull();
  });

  it('clears data before logout and never reports successful revocation on a lost response', async () => {
    api.logout.mockRejectedValueOnce(new PortalError('network_error', 0, true));
    render(
      <PortalProvider>
        <PrivateContent />
      </PortalProvider>
    );
    await screen.findByText('private@example.test');
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(screen.queryByText('private@example.test')).toBeNull();
    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toContain('Sign-out could not be confirmed')
    );
    expect(replace).not.toHaveBeenCalled();
    expect(api.logout).toHaveBeenCalledTimes(1);
  });
});

describe('display preferences preserve session authority', () => {
  it('keeps the same bootstrap, private draft, client and expiry timer across language changes', async () => {
    jest.useFakeTimers();
    const value = api.profile;
    if (!value) throw new Error('Expected fixture profile');
    function view(locale: 'en' | 'fa-IR') {
      return (
        <I18nTestProvider locale={locale}>
          <PortalProvider>
            <PrivateContent />
            <input aria-label="Private draft" defaultValue="" />
          </PortalProvider>
        </I18nTestProvider>
      );
    }
    const result = render(view('en'));
    await act(async () => undefined);
    const navigation = screen.getByRole('button', { name: 'Current section: Overview' });
    fireEvent.click(navigation);
    expect(navigation.getAttribute('aria-expanded')).toBe('true');
    const draft = screen.getByRole<HTMLInputElement>('textbox', { name: 'Private draft' });
    fireEvent.change(draft, { target: { value: 'نام خصوصی ۱۲۳' } });
    const calls = jest.mocked(PortalClient).mock.calls.length;
    act(() => jest.advanceTimersByTime(59000));
    result.rerender(view('fa-IR'));
    expect(screen.getByRole('navigation', { name: 'ناوبری حساب' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'بخش فعلی: نمای کلی' })).toBe(navigation);
    expect(navigation.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('textbox', { name: 'Private draft' })).toBe(draft);
    expect(draft.value).toBe('نام خصوصی ۱۲۳');
    expect(jest.mocked(PortalClient)).toHaveBeenCalledTimes(calls);
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(api.dispose).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).not.toHaveBeenCalled();
    expect(api.profile?.session.expires_at).toBe(value.session.expires_at);
    act(() => jest.advanceTimersByTime(1001));
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(screen.getByRole('alert').textContent).toBe(
      'نشست شما دیگر در دسترس نیست. برای ادامه دوباره وارد شوید.'
    );
  });
});
