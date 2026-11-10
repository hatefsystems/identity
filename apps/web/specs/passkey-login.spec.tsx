import { act, fireEvent, I18nTestProvider, render, screen, waitFor } from '../i18n/testing';
import { PasskeyLogin } from '../app/_components/passkey-login';
import { PortalClient } from '../app/_lib/portal/client';
import { browserKey } from '../app/_lib/portal/dpop';
import { PortalError } from '../app/_lib/portal/errors';
import { invalidateOtherTabs } from '../app/_lib/portal/invalidation';
import { requireWebAuthn, usePasskey } from '../app/_lib/portal/webauthn';

const replace = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ replace }) }));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/portal/dpop', () => ({ browserKey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({ invalidateOtherTabs: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({
  requireWebAuthn: jest.fn(),
  usePasskey: jest.fn(),
}));

const api = {
  loginOptions: jest.fn(),
  loginVerify: jest.fn(),
  bootstrap: jest.fn(),
  dispose: jest.fn(),
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (failure: unknown) => void;
  const promise = new Promise<T>((finish, fail) => {
    resolve = finish;
    reject = fail;
  });
  return { promise, resolve, reject };
}

const labels = {
  en: {
    use: 'Use a passkey', cancel: 'Cancel sign in',
    cancelled: 'Sign-in cancelled here before passkey verification was sent.',
    notCompleted: 'Sign-in was not completed.', unconfirmed: 'Sign-in outcome not confirmed.',
  },
  'fa-IR': {
    use: 'استفاده از کلید عبور', cancel: 'لغو ورود',
    cancelled: 'ورود در این صفحه پیش از ارسال تأیید کلید عبور لغو شد.',
    notCompleted: 'ورود کامل نشد.', unconfirmed: 'نتیجهٔ ورود تأیید نشده است.',
  },
};

beforeEach(() => {
  jest.clearAllMocks();
  jest.mocked(PortalClient).mockImplementation(() => api as unknown as PortalClient);
  jest.mocked(browserKey).mockResolvedValue({} as Awaited<ReturnType<typeof browserKey>>);
  jest.mocked(requireWebAuthn).mockImplementation(() => undefined);
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ response: 'binary-adapted-assertion' } as unknown as Awaited<
      ReturnType<typeof usePasskey>
    >);
  api.loginOptions.mockResolvedValue({ publicKey: { challenge: 'test-challenge' } });
  api.loginVerify.mockResolvedValue(undefined);
  api.bootstrap.mockResolvedValue({ session: { id: 'public-session' } });
  window.history.replaceState({}, '', '/login');
});

describe('live discoverable passkey entry', () => {
  it('does not initialize storage or contact APIs/authenticators until a user action, then bootstraps before navigation', async () => {
    const persistent = [
      jest.spyOn(window, 'localStorage', 'get'),
      jest.spyOn(window, 'sessionStorage', 'get'),
    ];
    render(<PasskeyLogin />);
    expect(browserKey).not.toHaveBeenCalled();
    expect(PortalClient).not.toHaveBeenCalled();
    expect(usePasskey).not.toHaveBeenCalled();
    let complete!: () => void;
    api.bootstrap.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          complete = resolve;
        })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
    await waitFor(() => expect(api.bootstrap).toHaveBeenCalledTimes(1));
    expect(browserKey).toHaveBeenCalledWith(true, expect.any(AbortSignal));
    expect(api.loginOptions).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(api.loginVerify).toHaveBeenCalledWith(
      { response: 'binary-adapted-assertion' },
      expect.any(AbortSignal)
    );
    expect(replace).not.toHaveBeenCalled();
    await act(async () => complete());
    expect(replace).toHaveBeenCalledWith('/dashboard');
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
    for (const spy of persistent) {
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it('blocks duplicate clicks, ignores late authenticator completion after cancel and allows a new ceremony', async () => {
    let complete!: (value: Awaited<ReturnType<typeof usePasskey>>) => void;
    jest.mocked(usePasskey).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          complete = resolve;
        })
    );
    render(<PasskeyLogin />);
    const button = screen.getByRole('button', { name: 'Use a passkey' });
    act(() => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
    await waitFor(() => expect(usePasskey).toHaveBeenCalledTimes(1));
    expect(api.loginOptions).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel sign in' }));
    await act(async () => complete({} as Awaited<ReturnType<typeof usePasskey>>));
    expect(api.bootstrap).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Use a passkey' }).disabled).toBe(
      false
    );
    fireEvent.click(button);
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/dashboard'));
    expect(api.loginOptions).toHaveBeenCalledTimes(2);
  });

  it('does not claim success on failed bootstrap or unsupported WebAuthn', async () => {
    api.bootstrap.mockRejectedValueOnce(new PortalError('session_required', 401));
    const view = render(<PasskeyLogin />);
    fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Sign in again');
    expect(replace).not.toHaveBeenCalled();
    view.unmount();
    jest.clearAllMocks();
    jest.mocked(requireWebAuthn).mockImplementationOnce(() => {
      throw new PortalError('unsupported');
    });
    render(<PasskeyLogin />);
    fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
    expect((await screen.findByRole('alert')).textContent).toContain('supported browser');
    expect(browserKey).not.toHaveBeenCalled();
    expect(api.loginOptions).not.toHaveBeenCalled();
  });

  it('notifies other tabs after uncertain cookie issuance but does not replay it', async () => {
    api.loginVerify.mockRejectedValueOnce(new PortalError('network_error', 0, true));
    render(<PasskeyLogin />);
    fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain('Sign-in outcome not confirmed')
    );
    expect(screen.queryByRole('alert')).toBeNull();
    expect(api.loginVerify).toHaveBeenCalledTimes(1);
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
    expect(api.bootstrap).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  });

  it.each(['/dashboard/profile', 'https://evil.example/', '/oauth2/authorize'])(
    'restricts returnTo=%s to portal destinations',
    async (path) => {
      window.history.replaceState({}, '', `/login?returnTo=${encodeURIComponent(path)}`);
      render(<PasskeyLogin />);
      fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
      await waitFor(() =>
        expect(replace).toHaveBeenCalledWith(path === '/dashboard/profile' ? path : '/dashboard')
      );
    }
  );
});

describe.each(['en', 'fa-IR'] as const)('passkey interruption feedback in %s', (locale) => {
  it.each(['key', 'options', 'prompt'] as const)(
    'uses neutral explicit cancellation before verification during %s and ignores late work',
    async (stage) => {
      const pending = deferred<unknown>();
      const blocked = stage === 'key' ? browserKey : stage === 'options' ? api.loginOptions : usePasskey;
      jest.mocked(blocked).mockImplementationOnce(() => pending.promise as never);
      render(<PasskeyLogin />, { locale });
      fireEvent.click(screen.getByRole('button', { name: labels[locale].use }));
      await waitFor(() => expect(blocked).toHaveBeenCalledTimes(1));
      fireEvent.click(screen.getByRole('button', { name: labels[locale].cancel }));
      expect(screen.getByRole('status').textContent).toContain(labels[locale].cancelled);
      expect(screen.queryByRole('alert')).toBeNull();
      expect(document.activeElement).toBe(screen.getByRole('button', { name: labels[locale].use }));
      await act(async () => pending.resolve({}));
      expect(api.loginVerify).not.toHaveBeenCalled();
      expect(api.bootstrap).not.toHaveBeenCalled();
      expect(invalidateOtherTabs).not.toHaveBeenCalled();
      expect(replace).not.toHaveBeenCalled();
      expect(browserKey).toHaveBeenCalledTimes(1);
      expect(screen.getByRole('status').textContent).toContain(labels[locale].cancelled);
    }
  );

  it('treats the adapter cancelled outcome (including NotAllowedError) as incomplete, not voluntary cancellation', async () => {
    jest.mocked(usePasskey).mockRejectedValueOnce(new PortalError('cancelled'));
    const view = (language: 'en' | 'fa-IR') => (
      <I18nTestProvider locale={language}><PasskeyLogin /></I18nTestProvider>
    );
    const result = render(view(locale));
    fireEvent.click(screen.getByRole('button', { name: labels[locale].use }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain(labels[locale].notCompleted)
    );
    expect(screen.queryByRole('alert')).toBeNull();
    const otherLocale = locale === 'en' ? 'fa-IR' : 'en';
    result.rerender(view(otherLocale));
    expect(screen.getByRole('status').textContent).toContain(labels[otherLocale].notCompleted);
    expect(api.loginOptions).toHaveBeenCalledTimes(1);
    expect(usePasskey).toHaveBeenCalledTimes(1);
    expect(api.loginVerify).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  });

  it.each(['loginVerify', 'bootstrap'] as const)(
    'reports app cancellation during %s as unconfirmed without replay or accepting late success',
    async (stage) => {
      const pending = deferred<void>();
      api[stage].mockReturnValueOnce(pending.promise);
      render(<PasskeyLogin />, { locale });
      fireEvent.click(screen.getByRole('button', { name: labels[locale].use }));
      await waitFor(() => expect(api[stage]).toHaveBeenCalledTimes(1));
      const signal = api[stage].mock.calls[0][stage === 'loginVerify' ? 1 : 0] as AbortSignal;
      fireEvent.click(screen.getByRole('button', { name: labels[locale].cancel }));
      expect(signal.aborted).toBe(true);
      expect(screen.getByRole('status').textContent).toContain(labels[locale].unconfirmed);
      expect(screen.queryByRole('alert')).toBeNull();
      await act(async () => pending.resolve());
      expect(screen.getByRole('status').textContent).toContain(labels[locale].unconfirmed);
      expect(api.loginVerify).toHaveBeenCalledTimes(1);
      expect(api.bootstrap).toHaveBeenCalledTimes(stage === 'loginVerify' ? 0 : 1);
      expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
      expect(replace).not.toHaveBeenCalled();
      // Only another deliberate click starts a new ceremony.
      fireEvent.click(screen.getByRole('button', { name: labels[locale].use }));
      await waitFor(() => expect(replace).toHaveBeenCalledWith('/dashboard'));
      expect(api.loginOptions).toHaveBeenCalledTimes(2);
      expect(api.loginVerify).toHaveBeenCalledTimes(2);
    }
  );
});

it('renders an actual NotAllowedError through the unchanged WebAuthn cancelled contract as neutral incompletion', async () => {
  const actual = jest.requireActual<typeof import('../app/_lib/portal/webauthn')>('../app/_lib/portal/webauthn');
  const get = jest.fn().mockRejectedValue(new DOMException('Not disclosed', 'NotAllowedError'));
  const properties = [
    [globalThis, 'isSecureContext', true],
    [globalThis, 'PublicKeyCredential', class {}],
    [navigator, 'credentials', { get, create: jest.fn() }],
  ] as const;
  const originals = properties.map(([owner, key]) => Object.getOwnPropertyDescriptor(owner, key));
  try {
    for (const [owner, key, value] of properties)
      Object.defineProperty(owner, key, { configurable: true, value });
    api.loginOptions.mockResolvedValueOnce({ publicKey: { challenge: 'AQ' } });
    jest.mocked(usePasskey).mockImplementationOnce(actual.usePasskey);
    render(<PasskeyLogin />);
    fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain('Sign-in was not completed.')
    );
    expect(get).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(api.loginVerify).not.toHaveBeenCalled();
    expect(api.bootstrap).not.toHaveBeenCalled();
    expect(invalidateOtherTabs).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  } finally {
    properties.forEach(([owner, key], index) => {
      const original = originals[index];
      if (original) Object.defineProperty(owner, key, original);
      else Reflect.deleteProperty(owner, key);
    });
  }
});

it.each([
  ['loginVerify', new PortalError('invalid_response')],
  ['loginVerify', new DOMException('Interrupted', 'AbortError')],
  ['bootstrap', new PortalError('network_error')],
  ['bootstrap', new PortalError('cancelled')],
  ['bootstrap', new DOMException('Interrupted', 'AbortError')],
] as const)('reports ambiguous %s failures as unconfirmed and never retries them', async (stage, failure) => {
  api[stage].mockRejectedValueOnce(failure);
  render(<PasskeyLogin />);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  await waitFor(() =>
    expect(screen.getByRole('status').textContent).toContain('Sign-in outcome not confirmed')
  );
  expect(screen.queryByRole('alert')).toBeNull();
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(stage === 'loginVerify' ? 0 : 1);
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  expect(replace).not.toHaveBeenCalled();
});

it('keeps definitive verification and authenticator-policy failures as errors', async () => {
  api.loginVerify.mockRejectedValueOnce(new PortalError('verification_failed', 401));
  const result = render(<PasskeyLogin />);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  expect((await screen.findByRole('alert')).textContent).toContain('ceremony expired or could not be verified');
  expect(screen.getByRole('status').textContent).not.toContain('not confirmed');
  expect(api.bootstrap).not.toHaveBeenCalled();
  result.unmount();
  jest.mocked(usePasskey).mockRejectedValueOnce(new PortalError('authenticator_security'));
  render(<PasskeyLogin />);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  expect((await screen.findByRole('alert')).textContent).toContain('could not be used on this origin');
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(replace).not.toHaveBeenCalled();
});

it('does not let a late cancelled verification failure replace a new active ceremony', async () => {
  const oldVerify = deferred<void>();
  const newPrompt = deferred<Awaited<ReturnType<typeof usePasskey>>>();
  api.loginVerify.mockReturnValueOnce(oldVerify.promise);
  const result = render(<PasskeyLogin />);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  await waitFor(() => expect(api.loginVerify).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel sign in' }));
  jest.mocked(usePasskey).mockReturnValueOnce(newPrompt.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  await waitFor(() => expect(usePasskey).toHaveBeenCalledTimes(2));
  await act(async () => oldVerify.reject(new PortalError('network_error', 0, true)));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByRole('status').textContent).toContain('Complete the passkey prompt');
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Verifying passkey...' }).disabled).toBe(true);
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  result.unmount();
  expect(jest.mocked(usePasskey).mock.calls[1][1]?.aborted).toBe(true);
  await act(async () => newPrompt.resolve({} as Awaited<ReturnType<typeof usePasskey>>));
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).not.toHaveBeenCalled();
  expect(replace).not.toHaveBeenCalled();
});

it.each(['loginVerify', 'bootstrap'] as const)('preserves unmount abort and late-response rules during %s', async (stage) => {
  const pending = deferred<void>();
  api[stage].mockReturnValueOnce(pending.promise);
  const result = render(<PasskeyLogin />);
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  await waitFor(() => expect(api[stage]).toHaveBeenCalledTimes(1));
  const signal = api[stage].mock.calls[0][stage === 'loginVerify' ? 1 : 0] as AbortSignal;
  result.unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve());
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(stage === 'loginVerify' ? 0 : 1);
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  expect(replace).not.toHaveBeenCalled();
});

it('translates an active passkey ceremony without rotating the key, aborting or replaying API work', async () => {
  let resolve!: (value: Awaited<ReturnType<typeof usePasskey>>) => void;
  jest.mocked(usePasskey).mockImplementationOnce(
    () =>
      new Promise((finish) => {
        resolve = finish;
      })
  );
  const view = (locale: 'en' | 'fa-IR') => (
    <I18nTestProvider locale={locale}>
      <PasskeyLogin />
    </I18nTestProvider>
  );
  const result = render(view('en'));
  fireEvent.click(screen.getByRole('button', { name: 'Use a passkey' }));
  await waitFor(() => expect(usePasskey).toHaveBeenCalledTimes(1));
  const signal = jest.mocked(usePasskey).mock.calls[0][1];
  result.rerender(view('fa-IR'));
  expect(screen.getByRole('button', { name: 'لغو ورود' })).toBeTruthy();
  expect(signal?.aborted).toBe(false);
  expect(browserKey).toHaveBeenCalledTimes(1);
  expect(PortalClient).toHaveBeenCalledTimes(1);
  expect(api.loginOptions).toHaveBeenCalledTimes(1);
  expect(api.loginVerify).not.toHaveBeenCalled();
  await act(async () =>
    resolve({ response: 'binary-adapted-assertion' } as unknown as Awaited<
      ReturnType<typeof usePasskey>
    >)
  );
  expect(api.loginVerify).toHaveBeenCalledTimes(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(replace).toHaveBeenCalledWith('/dashboard');
});
