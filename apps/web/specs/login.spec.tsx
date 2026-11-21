import { TextEncoder } from 'node:util';
import { act, fireEvent, I18nTestProvider, render, screen, waitFor } from '../i18n/testing';
import { Login } from '../app/_components/login';
import { PortalClient } from '../app/_lib/portal/client';
import { browserKey } from '../app/_lib/portal/dpop';
import { PortalError } from '../app/_lib/portal/errors';
import { invalidateOtherTabs } from '../app/_lib/portal/invalidation';

const replace = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ replace }) }));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/portal/dpop', () => ({ browserKey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({ invalidateOtherTabs: jest.fn() }));

const api = { request: jest.fn(), bootstrap: jest.fn(), dispose: jest.fn() };
const copy = {
  en: {
    username: 'Username', password: 'Password', passwordForm: 'Password sign in',
    contact: 'Username and delivered code', request: 'Request a sign-in code', channel: 'Delivery channel',
    delivered: 'Delivered sign-in code', verifyDelivered: 'Delivered sign-in code verification',
    totp: 'Authenticator code', verifyTotp: 'Authenticator verification', restart: 'Start a new sign-in',
  },
  'fa-IR': {
    username: 'نام کاربری', password: 'گذرواژه', passwordForm: 'ورود با گذرواژه',
    contact: 'نام کاربری و کد ارسال‌شده', request: 'درخواست کد ورود', channel: 'راه ارسال',
    delivered: 'کد ارسال‌شدهٔ ورود', verifyDelivered: 'تأیید کد ارسال‌شدهٔ ورود',
    totp: 'کد رمزساز', verifyTotp: 'تأیید با رمزساز', restart: 'آغاز ورود جدید',
  },
};
function answer(value: unknown, status: number) {
  api.request.mockImplementationOnce(async (_path, decode) => decode(value, status));
}
function enter(label: string, value: string) {
  const input = screen.getByLabelText<HTMLInputElement>(label);
  fireEvent.change(input, { target: { value } });
  return input;
}
beforeEach(() => {
  Object.assign(globalThis, { TextEncoder });
  jest.resetAllMocks();
  jest.mocked(PortalClient).mockImplementation(() => api as unknown as PortalClient);
  jest.mocked(browserKey).mockResolvedValue({} as Awaited<ReturnType<typeof browserKey>>);
  api.bootstrap.mockResolvedValue({ session: { id: 'session' } });
  window.history.replaceState(null, '', '/login');
});
afterEach(() => jest.restoreAllMocks());

it.each(['en', 'fa-IR'] as const)('does no work on mount and bootstraps once before navigating after exact password sign-in in %s', async (locale) => {
  const labels = copy[locale];
  const storage = [jest.spyOn(window, 'localStorage', 'get'), jest.spyOn(window, 'sessionStorage', 'get')];
  render(<Login />, { locale });
  expect(browserKey).not.toHaveBeenCalled();
  expect(PortalClient).not.toHaveBeenCalled();
  expect(api.request).not.toHaveBeenCalled();
  expect(screen.queryByLabelText('Email address')).toBeNull();
  const username = enter(labels.username, 'هاتف۱۲');
  const password = enter(labels.password, '  گذرواژه۱۲۳\u200c\u202e  ');
  expect(username.autocomplete).toBe('username');
  expect(username.dir).toBe('auto');
  expect(password.dir).toBe('ltr');
  answer(undefined, 204);
  let finish!: () => void;
  api.bootstrap.mockImplementationOnce(() => new Promise<void>((resolve) => { finish = resolve; }));
  const form = screen.getByRole('form', { name: labels.passwordForm });
  act(() => { fireEvent.submit(form); fireEvent.submit(form); });
  await waitFor(() => expect(api.bootstrap).toHaveBeenCalledTimes(1));
  expect(api.request).toHaveBeenCalledTimes(1);
  expect(api.request.mock.calls[0][0]).toBe('/api/v1/auth/login');
  expect(api.request.mock.calls[0][2]).toMatchObject({ anonymous: true, body: { username: 'هاتف۱۲', password: '  گذرواژه۱۲۳\u200c\u202e  ' } });
  expect(screen.queryByLabelText(labels.password)).toBeNull();
  expect(replace).not.toHaveBeenCalled();
  await act(async () => finish());
  expect(replace).toHaveBeenCalledWith('/dashboard');
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  storage.forEach((spy) => expect(spy).not.toHaveBeenCalled());
});

it.each(['email', 'sms'] as const)('preserves %s delivery state, original expiry and control identity across locale switches; completes converted codes in place', async (channel) => {
  const view = (locale: 'en' | 'fa-IR') => <I18nTestProvider locale={locale}><Login /></I18nTestProvider>;
  const result = render(view('en'));
  fireEvent.click(screen.getByRole('button', { name: copy.en.contact }));
  enter(copy.en.username, 'username');
  fireEvent.change(screen.getByLabelText(copy.en.channel), { target: { value: channel } });
  const expiry = new Date(Date.now() + 180000).toISOString();
  answer({ status: 'code_requested', challenge: 'private-challenge', expires_at: expiry }, 202);
  fireEvent.submit(screen.getByRole('form', { name: copy.en.request }));
  const input = await screen.findByLabelText<HTMLInputElement>(copy.en.delivered);
  expect(api.request.mock.calls[0][2].body).toEqual({ username: 'username', channel });
  expect(input.dir).toBe('ltr');
  expect(input.inputMode).toBe('numeric');
  expect(api.bootstrap).not.toHaveBeenCalled();
  enter(copy.en.delivered, '0۱٢۳4۵');
  result.rerender(view('fa-IR'));
  expect(screen.getByLabelText(copy['fa-IR'].delivered)).toBe(input);
  expect(input.value).toBe('012345');
  expect(api.request).toHaveBeenCalledTimes(1);
  expect(browserKey).toHaveBeenCalledTimes(1);
  expect(result.container.textContent).not.toContain('private-challenge');
  expect(result.container.innerHTML).not.toContain(expiry);
  expect(window.location.href).not.toContain('private-challenge');

  answer({ status: 'mfa_required', preauthentication: 'private-preauth', expires_at: new Date(Date.now() + 300000).toISOString() }, 200);
  fireEvent.submit(screen.getByRole('form', { name: copy['fa-IR'].verifyDelivered }));
  const totp = await screen.findByLabelText<HTMLInputElement>(copy['fa-IR'].totp);
  expect(api.request.mock.calls[1][2].body).toEqual({ challenge: 'private-challenge', code: '012345' });
  expect(screen.queryByLabelText(copy['fa-IR'].delivered)).toBeNull();
  expect(result.container.textContent).toContain('هنوز نشستی صادر نشده است');
  expect(result.container.innerHTML).not.toContain('private-preauth');
  expect(api.bootstrap).not.toHaveBeenCalled();
  expect(window.location.pathname).toBe('/login');
  result.rerender(view('en'));
  expect(screen.getByLabelText(copy.en.totp)).toBe(totp);
  expect(api.request).toHaveBeenCalledTimes(2);
  totp.value = '۰۱٢۳٤۵';
  answer(undefined, 204);
  fireEvent.submit(screen.getByRole('form', { name: copy.en.verifyTotp }));
  await waitFor(() => expect(replace).toHaveBeenCalledWith('/dashboard'));
  expect(api.request.mock.calls[2][2].body).toEqual({ preauthentication: 'private-preauth', code: '012345' });
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(browserKey).toHaveBeenCalledTimes(1);
});

it('treats unknown outcomes as terminal, translates the notice without replay, and restarts only on explicit action', async () => {
  const view = (locale: 'en' | 'fa-IR') => <I18nTestProvider locale={locale}><Login /></I18nTestProvider>;
  const result = render(view('en'));
  enter(copy.en.username, 'username');
  enter(copy.en.password, 'private password');
  api.request.mockRejectedValueOnce(new PortalError('outcome_unknown', 503, true));
  fireEvent.submit(screen.getByRole('form', { name: copy.en.passwordForm }));
  await waitFor(() => expect(result.container.textContent).toContain('The outcome of this sign-in step is not confirmed.'));
  expect(result.container.querySelector('input, form')).toBeNull();
  expect(result.container.textContent).not.toContain('private password');
  expect(api.bootstrap).not.toHaveBeenCalled();
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  result.rerender(view('fa-IR'));
  expect(result.container.textContent).toContain('نتیجهٔ این مرحلهٔ ورود تأیید نشده است');
  expect(api.request).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: copy['fa-IR'].restart }));
  expect(screen.getByLabelText<HTMLInputElement>(copy['fa-IR'].username).value).toBe('');
  expect(screen.getByLabelText<HTMLInputElement>(copy['fa-IR'].password).value).toBe('');
  expect(api.dispose).toHaveBeenCalledTimes(1);
  expect(api.request).toHaveBeenCalledTimes(1);
});

it('uses an explicit unconfirmed outcome when issued session bootstrap cannot be verified', async () => {
  answer(undefined, 204);
  api.bootstrap.mockRejectedValueOnce(new PortalError('network_error'));
  const { container } = render(<Login />);
  enter(copy.en.username, 'username');
  enter(copy.en.password, 'password');
  fireEvent.submit(screen.getByRole('form', { name: copy.en.passwordForm }));
  await waitFor(() => expect(container.textContent).toContain('The outcome of this sign-in step is not confirmed.'));
  expect(container.querySelector('input, form')).toBeNull();
  expect(api.request).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(replace).not.toHaveBeenCalled();
});

it('allows an explicit fresh flow after pagehide during an uncertain mutation and ignores late rejection', async () => {
  let reject!: (reason: unknown) => void;
  api.request.mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  const { container } = render(<Login />);
  enter(copy.en.username, 'username');
  enter(copy.en.password, 'password');
  fireEvent.submit(screen.getByRole('form', { name: copy.en.passwordForm }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(1));
  fireEvent(window, new Event('pagehide'));
  expect(container.textContent).toContain('The outcome of this sign-in step is not confirmed.');
  const restart = screen.getByRole<HTMLButtonElement>('button', { name: copy.en.restart });
  expect(restart.disabled).toBe(false);
  fireEvent.click(restart);
  expect(screen.getByLabelText<HTMLInputElement>(copy.en.username).value).toBe('');
  await act(async () => reject(new PortalError('network_error', 0, true)));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(api.request).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).not.toHaveBeenCalled();
});

it('checks original expiry after locale change and clears verification on pagehide without a request', async () => {
  const view = (locale: 'en' | 'fa-IR') => <I18nTestProvider locale={locale}><Login /></I18nTestProvider>;
  const result = render(view('en'));
  enter(copy.en.username, 'username');
  enter(copy.en.password, 'password');
  const expiry = Date.now() + 2000;
  answer({ status: 'mfa_required', preauthentication: 'private-preauth', expires_at: new Date(expiry).toISOString() }, 200);
  fireEvent.submit(screen.getByRole('form', { name: copy.en.passwordForm }));
  await screen.findByLabelText(copy.en.totp);
  result.rerender(view('fa-IR'));
  jest.spyOn(Date, 'now').mockReturnValue(expiry + 1);
  fireEvent.focus(window);
  expect(screen.queryByLabelText(copy['fa-IR'].totp)).toBeNull();
  expect(result.container.textContent).toContain('این تأیید دیگر قابل استفاده نیست');
  expect(api.request).toHaveBeenCalledTimes(1);
  fireEvent(window, new Event('pagehide'));
  expect(result.container.textContent).toContain('این صفحه تأیید ورود را پاک کرده است');
  expect(api.dispose).toHaveBeenCalledTimes(1);
});

it('ignores a late response after unmount and never logs, stores or navigates with handles', async () => {
  let resolve!: (value: unknown) => void;
  api.request.mockImplementationOnce(async (_path, decode) => decode(await new Promise((finish) => {
    resolve = finish;
  }), 200));
  const privacy = [jest.spyOn(console, 'log'), jest.spyOn(console, 'warn'), jest.spyOn(console, 'error'),
    jest.spyOn(window, 'localStorage', 'get'), jest.spyOn(window, 'sessionStorage', 'get'),
    jest.spyOn(document, 'cookie', 'set')];
  const originalUrl = window.location.href;
  const result = render(<Login />);
  enter(copy.en.username, 'username');
  enter(copy.en.password, 'password');
  fireEvent.submit(screen.getByRole('form', { name: copy.en.passwordForm }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(1));
  result.unmount();
  await act(async () => {
    resolve({ status: 'mfa_required', preauthentication: 'private-preauth', expires_at: new Date(Date.now() + 300000).toISOString() });
  });
  expect(window.location.href).toBe(originalUrl);
  expect(api.bootstrap).not.toHaveBeenCalled();
  expect(replace).not.toHaveBeenCalled();
  privacy.forEach((spy) => expect(spy).not.toHaveBeenCalled());
});
