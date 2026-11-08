jest.mock('next-intl/server', () => ({
  getTranslations: (...args: unknown[]) =>
    jest.requireActual('../i18n/testing').getTestTranslations(...args),
}));

import { act, fireEvent, render, screen, waitFor } from '../i18n/testing';
import { renderToStaticMarkup as renderStatic } from 'react-dom/server';
import type { ReactElement } from 'react';
import { I18nTestProvider } from '../i18n/testing';
const renderToStaticMarkup = (element: ReactElement) =>
  renderStatic(<I18nTestProvider>{element}</I18nTestProvider>);
import { PortalProvider, usePortal } from '../app/dashboard/_components/portal-provider';
import { PortalClient } from '../app/_lib/portal/client';
import type { Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { invalidateOtherTabs, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';

const replace = jest.fn();
jest.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
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
    profile: value,
    onSessionLoss: undefined as ((error: PortalError) => void) | undefined,
  };
}
function PrivateContent() {
  return <p>{usePortal().profile.email}</p>;
}
let api: ReturnType<typeof makeClient>;
let invalidate: () => void;
let visibility: PropertyDescriptor | undefined;
beforeEach(() => {
  jest.clearAllMocks();
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
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.useRealTimers();
});

describe('protected portal bootstrap', () => {
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
    const expiry = Date.parse(value.session.expires_at);
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
    const draft = screen.getByRole<HTMLInputElement>('textbox', { name: 'Private draft' });
    fireEvent.change(draft, { target: { value: 'نام خصوصی ۱۲۳' } });
    const calls = jest.mocked(PortalClient).mock.calls.length;
    act(() => jest.advanceTimersByTime(59000));
    result.rerender(view('fa-IR'));
    expect(screen.getByRole('navigation', { name: 'ناوبری حساب' })).toBeTruthy();
    expect(screen.getByRole('textbox', { name: 'Private draft' })).toBe(draft);
    expect(draft.value).toBe('نام خصوصی ۱۲۳');
    expect(jest.mocked(PortalClient)).toHaveBeenCalledTimes(calls);
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(api.dispose).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).not.toHaveBeenCalled();
    expect(Date.parse(api.profile.session.expires_at)).toBe(expiry);
    act(() => jest.advanceTimersByTime(1001));
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(screen.getByRole('alert').textContent).toBe(
      'نشست شما دیگر در دسترس نیست. برای ادامه دوباره وارد شوید.'
    );
  });
});
