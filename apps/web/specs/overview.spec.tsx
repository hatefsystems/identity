import { act, fireEvent, render, screen, waitFor, I18nTestProvider } from '../i18n/testing';
import { Overview } from '../app/dashboard/_components/overview';
import { usePortal } from '../app/dashboard/_components/portal-provider';
import { PortalError } from '../app/_lib/portal/errors';

jest.mock('../app/dashboard/_components/portal-provider', () => ({ usePortal: jest.fn() }));
const client = {
  keys: jest.fn(), sessions: jest.fn(), recoveryStatus: jest.fn(), username: jest.fn(),
};
beforeEach(() => {
  jest.resetAllMocks();
  client.keys.mockResolvedValue([]);
  client.sessions.mockResolvedValue([]);
  client.recoveryStatus.mockResolvedValue({ remaining: 2, low: true });
  client.username.mockResolvedValue(null);
  jest.mocked(usePortal).mockReturnValue({
    client,
    profile: { email: 'private@example.test', display_name: '', status: 'active', session: { expires_at: new Date(Date.now() + 3600000).toISOString() } },
  } as unknown as ReturnType<typeof usePortal>);
});

it.each(['en', 'fa-IR'] as const)('shows truly unclaimed account state with no claim or rename UI in %s', async (locale) => {
  const { container } = render(<Overview />, { locale });
  await screen.findByText(locale === 'en' ? 'No username is assigned to this account.' : 'نام کاربری به این حساب اختصاص داده نشده است.');
  expect(client.username).toHaveBeenCalledTimes(1);
  expect(container.querySelector('input[name="username"], form')).toBeNull();
  expect(screen.queryByRole('button')).toBeNull();
});

it('keeps the unchanged server display read-only across language changes without refetch or bootstrap', async () => {
  const display = '\u0639\u0644\u064a.\u0645\u0624\u0645\u0646\u064a';
  client.username.mockResolvedValueOnce({ display });
  const view = (locale: 'en' | 'fa-IR') => <I18nTestProvider locale={locale}><Overview /></I18nTestProvider>;
  const { container, rerender } = render(view('en'));
  await screen.findByText(display);
  const privateRegion = container.querySelector('[data-username-private]');
  expect(privateRegion?.querySelector('bdi')?.dir).toBe('auto');
  rerender(view('fa-IR'));
  expect(screen.getByText('نام کاربری')).toBeTruthy();
  expect(container.querySelector('[data-username-private]')).toBe(privateRegion);
  expect(privateRegion?.textContent).toBe(display);
  for (const request of Object.values(client)) expect(request).toHaveBeenCalledTimes(1);
  expect(container.querySelector('input[name="username"], form')).toBeNull();
});

it('does not call a failed read unclaimed and retries only after explicit refresh', async () => {
  client.username.mockRejectedValueOnce(new PortalError('temporarily_unavailable', 503));
  render(<Overview />);
  await screen.findByRole('alert');
  expect(screen.getByText('Username has not been loaded.')).toBeTruthy();
  expect(screen.queryByText('No username is assigned to this account.')).toBeNull();
  expect(client.username).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh overview' }));
  await screen.findByText('No username is assigned to this account.');
  expect(client.username).toHaveBeenCalledTimes(2);
});

it.each([
  ['en', new PortalError('not_found', 404)],
  ['fa-IR', new PortalError('not_found', 404)],
  ['en', new PortalError('temporarily_unavailable', 503)],
  ['fa-IR', new PortalError('network_error')],
] as const)('keeps existing summaries and truthful unknown username after a username failure in %s', async (locale, failure) => {
  client.username.mockRejectedValueOnce(failure);
  const view = (language: 'en' | 'fa-IR') => <I18nTestProvider locale={language}><Overview /></I18nTestProvider>;
  const { rerender } = render(view(locale));
  await screen.findByRole('alert');
  const headings = locale === 'en' ? ['Passkeys', 'Sessions', 'Recovery codes'] : ['کلیدهای عبور', 'نشست‌ها', 'کدهای بازیابی'];
  for (const name of headings) expect(await screen.findByRole('heading', { name })).toBeTruthy();
  expect(screen.getByText(locale === 'en' ? 'Username has not been loaded.' : 'نام کاربری هنوز دریافت نشده است.')).toBeTruthy();
  expect(screen.queryByText(locale === 'en' ? 'No username is assigned to this account.' : 'نام کاربری به این حساب اختصاص داده نشده است.')).toBeNull();
  rerender(view(locale === 'en' ? 'fa-IR' : 'en'));
  for (const request of Object.values(client)) expect(request).toHaveBeenCalledTimes(1);
});

it('loads existing summaries without waiting for the independent username read', async () => {
  let finish!: (result: { display: string }) => void;
  client.username.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
  render(<Overview />);
  for (const name of ['Passkeys', 'Sessions', 'Recovery codes'])
    expect(await screen.findByRole('heading', { name })).toBeTruthy();
  expect(screen.getByText('Username has not been loaded.')).toBeTruthy();
  await act(async () => finish({ display: 'private' }));
  expect(screen.getByText('private')).toBeTruthy();
  for (const request of Object.values(client)) expect(request).toHaveBeenCalledTimes(1);
});

it('reports username session expiration through the existing error handling rather than treating it as absence', async () => {
  client.username.mockRejectedValueOnce(new PortalError('session_expired', 401));
  render(<Overview />);
  expect((await screen.findByRole('alert')).textContent).toBe('Your session is no longer available. Sign in again to continue.');
  expect(screen.getByText('Username has not been loaded.')).toBeTruthy();
  expect(screen.queryByText('No username is assigned to this account.')).toBeNull();
  expect(client.username).toHaveBeenCalledTimes(1);
});

it('aborts a private read on unmount and ignores a late username', async () => {
  let finish!: (result: { display: string }) => void;
  client.username.mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
  const { unmount } = render(<Overview />);
  await waitFor(() => expect(client.username).toHaveBeenCalledTimes(1));
  const signal = client.username.mock.calls[0][0] as AbortSignal;
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => finish({ display: 'private' }));
  expect(screen.queryByText('private')).toBeNull();
});
