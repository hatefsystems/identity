import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import AuthLayout from '../app/(auth)/layout';
import RecoverAccountPage, { metadata } from '../app/(auth)/recover-account/page';
import {
  ReclaimClient,
  type ReclaimOptions,
  type ReclaimProof,
} from '../app/_lib/portal/reclaim-client';
import { PortalError } from '../app/_lib/portal/errors';
import { usePasskey } from '../app/_lib/portal/webauthn';

jest.mock('../app/_lib/portal/reclaim-client', () => ({
  ...jest.requireActual('../app/_lib/portal/reclaim-client'),
  ReclaimClient: jest.fn(),
}));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));

const token = 'A'.repeat(43);
const assertion = { id: 'credential-id', response: { signature: 'AA' } } as unknown as Awaited<
  ReturnType<typeof usePasskey>
>;
const api = {
  options: jest.fn<Promise<ReclaimOptions>, [string, AbortSignal]>(),
  complete: jest.fn<Promise<void>, [ReclaimProof, AbortSignal, (() => void)?]>(),
};
let originalVisibility: PropertyDescriptor | undefined;
beforeEach(() => {
  jest.resetAllMocks();
  window.history.replaceState(null, '', `/recover-account#token=${token}`);
  originalVisibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  jest.mocked(ReclaimClient).mockImplementation(() => api as unknown as ReclaimClient);
  api.options.mockResolvedValue({ factor: 'totp' });
  api.complete.mockImplementation(async (_proof, _signal, sent) => {
    sent?.();
  });
  jest.mocked(usePasskey).mockResolvedValue(assertion);
});
afterEach(() => {
  if (originalVisibility) Object.defineProperty(document, 'visibilityState', originalVisibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.restoreAllMocks();
  jest.useRealTimers();
  window.history.replaceState(null, '', '/');
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((finish) => {
    resolve = finish;
  });
  return { promise, resolve };
}
function page() {
  return (
    <AuthLayout>
      <RecoverAccountPage />
    </AuthLayout>
  );
}
function start() {
  fireEvent.click(screen.getByRole('button', { name: 'Start account recovery' }));
}
async function totp() {
  start();
  return screen.findByLabelText<HTMLInputElement>('Authenticator code');
}
async function submitTotp() {
  const input = await totp();
  fireEvent.change(input, { target: { value: '012345' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Account recovery verification' }));
  await waitFor(() => expect(api.complete).toHaveBeenCalledTimes(1));
  return input;
}
function hide() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
}
function show() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
}

describe('recovery link capture', () => {
  it('server-renders a noindex, nonsensitive, non-submitting auth shell without accessing the fragment', () => {
    const html = renderToStaticMarkup(page());
    const document = new DOMParser().parseFromString(html, 'text/html');
    expect(metadata.robots).toEqual({ index: false, follow: false });
    expect(document.querySelector('h1')?.textContent).toBe('Recover your account');
    expect(document.querySelector<HTMLButtonElement>('button')?.disabled).toBe(true);
    expect(document.querySelector<HTMLButtonElement>('button')?.type).toBe('button');
    expect(document.forms).toHaveLength(0);
    expect(document.querySelector('style, script, [style], [onclick], [formaction]')).toBeNull();
    expect(html).toContain('No recovery request is submitted without it');
    expect(html).not.toContain(token);
    expect(window.location.hash).toBe(`#token=${token}`);
    expect(ReclaimClient).not.toHaveBeenCalled();
  });

  it('captures and scrubs exactly once through StrictMode without auto-redemption or any persistent secret writes', async () => {
    const history = jest.spyOn(window.history, 'replaceState');
    const storage = jest.spyOn(Storage.prototype, 'setItem');
    const cookie = jest.spyOn(document, 'cookie', 'set');
    const errors = jest.spyOn(console, 'error');
    const logs = jest.spyOn(console, 'log');
    const view = render(<StrictMode>{page()}</StrictMode>);
    await act(async () => undefined);
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('');
    expect(history).toHaveBeenCalledTimes(1);
    expect(history).toHaveBeenCalledWith(null, '', '/recover-account');
    expect(JSON.stringify(window.history.state)).not.toContain(token);
    expect(view.container.innerHTML).not.toContain(token);
    expect(storage).not.toHaveBeenCalled();
    expect(cookie).not.toHaveBeenCalled();
    expect(errors).not.toHaveBeenCalled();
    expect(logs).not.toHaveBeenCalled();
    expect(api.options).not.toHaveBeenCalled();
    expect(api.complete).not.toHaveBeenCalled();
    expect(usePasskey).not.toHaveBeenCalled();
    start();
    await screen.findByLabelText('Authenticator code');
    expect(api.options).toHaveBeenCalledTimes(1);
    expect(api.options).toHaveBeenCalledWith(token, expect.any(AbortSignal));
    expect(api.complete).not.toHaveBeenCalled();
  });

  it.each([
    '',
    '#token=',
    `#token=${token}=`,
    `#token=${'A'.repeat(42)}B`,
    `#token=${token}&token=${token}`,
    `#token=${token}&other=1`,
    `#access_token=${token}`,
    `#%74oken=${token}`,
    `#token=%41${token.slice(1)}`,
    `?token=${token}`,
    `?tracking=1#token=${token}`,
  ])(
    'rejects missing, malformed, duplicate, encoded or query token input and scrubs it: %s',
    async (fragment) => {
      window.history.replaceState(null, '', `/recover-account${fragment}`);
      const view = render(page());
      await screen.findByRole('alert');
      expect(window.location.hash).toBe('');
      expect(window.location.search).toBe('');
      expect(
        screen.getByRole<HTMLButtonElement>('button', { name: 'Start account recovery' }).disabled
      ).toBe(true);
      expect(view.container.innerHTML).not.toContain(token);
      start();
      expect(api.options).not.toHaveBeenCalled();
      expect(api.complete).not.toHaveBeenCalled();
    }
  );

  it('fails closed if address-bar scrubbing is refused without displaying or logging the thrown secret', () => {
    jest.spyOn(window.history, 'replaceState').mockImplementationOnce(() => {
      throw new Error(token);
    });
    const errors = jest.spyOn(console, 'error');
    const view = render(page());
    expect(
      screen.getByRole<HTMLButtonElement>('button', { name: 'Start account recovery' }).disabled
    ).toBe(true);
    expect(view.container.innerHTML).not.toContain(token);
    expect(errors).not.toHaveBeenCalled();
    expect(api.options).not.toHaveBeenCalled();
  });

  it('never replaces the captured token from a later hash change', () => {
    render(page());
    window.history.replaceState(null, '', `/recover-account#token=${'B'.repeat(42)}A`);
    fireEvent(window, new Event('hashchange'));
    expect(window.location.hash).toBe('');
    start();
    expect(api.options).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toContain('Reopen the link');
  });
});

describe('explicit factor verification', () => {
  it('accepts whole six-digit text codes with leading zeroes, prevents duplicate submits and offers only fresh login after 204', async () => {
    const completed = deferred<void>();
    api.complete.mockImplementationOnce((_proof, _signal, sent) => {
      sent?.();
      return completed.promise;
    });
    render(page());
    const input = await totp();
    expect(input.type).toBe('text');
    expect(input.inputMode).toBe('numeric');
    expect(input.autocomplete).toBe('one-time-code');
    expect(document.activeElement).toBe(input);
    const form = screen.getByRole('form', { name: 'Account recovery verification' });
    fireEvent.submit(form);
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(input);
    expect(api.complete).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: '012345' } });
    expect(api.complete).not.toHaveBeenCalled();
    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });
    expect(api.complete).toHaveBeenCalledTimes(1);
    expect(api.complete).toHaveBeenCalledWith(
      { token, factor: 'totp', code: '012345' },
      expect.any(AbortSignal),
      expect.any(Function)
    );
    expect(input.value).toBe('');
    expect(screen.queryByRole('link', { name: 'Sign in to your account' })).toBeNull();
    await act(async () => completed.resolve());
    const heading = screen.getByRole('heading', { name: 'Account recovered' });
    expect(document.activeElement).toBe(heading);
    expect(screen.getByRole('link', { name: 'Sign in to your account' }).getAttribute('href')).toBe(
      '/login'
    );
    expect(screen.getByTestId('reclaim-outcome').textContent).toContain(
      'old sessions remain invalid'
    );
    expect(screen.queryByRole('link', { name: /dashboard/i })).toBeNull();
    expect(api.options).toHaveBeenCalledTimes(1);
  });

  it('uses only server-selected WebAuthn with required UV and no TOTP fallback', async () => {
    const options = {
      factor: 'webauthn' as const,
      webauthn: { publicKey: { challenge: 'AA', userVerification: 'preferred' } },
    };
    api.options.mockResolvedValueOnce(options);
    render(page());
    start();
    const verify = await screen.findByRole('button', { name: 'Recover with a passkey' });
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    expect(screen.queryByRole('button', { name: /authenticator code/i })).toBeNull();
    expect(usePasskey).not.toHaveBeenCalled();
    fireEvent.click(verify);
    await screen.findByRole('heading', { name: 'Account recovered' });
    expect(usePasskey).toHaveBeenCalledWith(options.webauthn, expect.any(AbortSignal), false, true);
    expect(api.complete).toHaveBeenCalledWith(
      { token, factor: 'webauthn', assertion },
      expect.any(AbortSignal),
      expect.any(Function)
    );
  });

  it.each(['unsupported', 'cancelled', 'user_verification_required'])(
    'does not send a recovery proof or recommend another factor after %s',
    async (code) => {
      api.options.mockResolvedValueOnce({
        factor: 'webauthn',
        webauthn: { publicKey: { challenge: 'AA' } },
      });
      jest.mocked(usePasskey).mockRejectedValueOnce(new PortalError(code));
      render(page());
      start();
      fireEvent.click(await screen.findByRole('button', { name: 'Recover with a passkey' }));
      const error = (await screen.findByRole('alert')).textContent;
      expect(error).not.toMatch(/authenticator app|authenticator code|TOTP/);
      expect(screen.queryByLabelText('Authenticator code')).toBeNull();
      expect(api.complete).not.toHaveBeenCalled();
    }
  );

  it('keeps server invalid_token opaque for options and factor failure and requires explicit fresh options', async () => {
    api.options.mockRejectedValueOnce(new PortalError('invalid_token', 401));
    api.complete.mockRejectedValueOnce(new PortalError('invalid_token', 401));
    render(page());
    start();
    const first = (await screen.findByRole('alert')).textContent;
    expect(first).toContain('cannot identify the reason');
    await submitTotp();
    expect((await screen.findByRole('alert')).textContent).toBe(first);
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    expect(screen.queryByTestId('reclaim-outcome')).toBeNull();
    expect(api.options).toHaveBeenCalledTimes(2);
    expect(api.complete).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('link', { name: 'Sign in to your account' })).toBeNull();
  });

  it.each([429, 503])(
    'handles an options %i without auto retry or account-state claims',
    async (status) => {
      api.options.mockRejectedValueOnce(new PortalError('temporarily_unavailable', status));
      render(page());
      start();
      const message = (await screen.findByRole('alert')).textContent;
      expect(message).toContain(
        status === 429 ? 'Too many attempts' : 'service may be unavailable'
      );
      expect(api.options).toHaveBeenCalledTimes(1);
      expect(api.complete).not.toHaveBeenCalled();
      expect(screen.queryByTestId('reclaim-outcome')).toBeNull();
    }
  );
});

describe('bounded private-memory lifetime', () => {
  it('clears TOTP on app switching, retains only the bounded link and needs explicit fresh options without extending five minutes', async () => {
    jest.useFakeTimers();
    render(page());
    const oldInput = await totp();
    fireEvent.change(oldInput, { target: { value: '012345' } });
    act(() => jest.advanceTimersByTime(200000));
    hide();
    expect(oldInput.value).toBe('');
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    show();
    expect(api.options).toHaveBeenCalledTimes(1);
    const newInput = await totp();
    expect(newInput).not.toBe(oldInput);
    expect(newInput.value).toBe('');
    expect(api.options).toHaveBeenCalledTimes(2);
    expect(api.options.mock.calls[1][0]).toBe(token);
    act(() => jest.advanceTimersByTime(100001));
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    start();
    expect(api.options).toHaveBeenCalledTimes(2);
    expect(api.complete).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toContain('Reopen the link');
  });

  it('expires even if the wall clock rolls backward, and checks expiry again before an action after a forward jump', async () => {
    jest.useFakeTimers();
    const initial = Date.now();
    const first = render(page());
    jest.setSystemTime(initial - 3600000);
    act(() => jest.advanceTimersByTime(300001));
    start();
    expect(api.options).not.toHaveBeenCalled();
    first.unmount();
    window.history.replaceState(null, '', `/recover-account#token=${token}`);
    render(page());
    jest.setSystemTime(Date.now() + 300001);
    start();
    expect(api.options).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toContain('Reopen the link');
  });

  it('rechecks the memory deadline on foreground return even when background timers have not run', async () => {
    jest.useFakeTimers();
    render(page());
    await totp();
    hide();
    jest.setSystemTime(Date.now() + 300001);
    show();
    expect(
      screen.getByRole<HTMLButtonElement>('button', { name: 'Start account recovery' }).disabled
    ).toBe(true);
    expect(screen.getByRole('alert').textContent).toContain('Reopen the link');
    expect(api.options).toHaveBeenCalledTimes(1);
  });

  it('aborts pending options on hide, discards a late challenge and never resumes automatically', async () => {
    const prepared = deferred<ReclaimOptions>();
    api.options.mockReturnValueOnce(prepared.promise);
    render(page());
    start();
    const signal = api.options.mock.calls[0][1];
    hide();
    expect(signal.aborted).toBe(true);
    await act(async () => prepared.resolve({ factor: 'totp' }));
    show();
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    expect(api.options).toHaveBeenCalledTimes(1);
    expect(api.complete).not.toHaveBeenCalled();
    await totp();
    expect(api.options).toHaveBeenCalledTimes(2);
  });

  it('discards a passkey proof arriving after pre-send cancellation without claiming a mutation', async () => {
    const proof = deferred<Awaited<ReturnType<typeof usePasskey>>>();
    api.options.mockResolvedValueOnce({
      factor: 'webauthn',
      webauthn: { publicKey: { challenge: 'AA' } },
    });
    jest.mocked(usePasskey).mockReturnValueOnce(proof.promise);
    render(page());
    start();
    fireEvent.click(await screen.findByRole('button', { name: 'Recover with a passkey' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel recovery' }));
    expect(jest.mocked(usePasskey).mock.calls[0][1].aborted).toBe(true);
    await act(async () => proof.resolve(assertion));
    expect(api.complete).not.toHaveBeenCalled();
    expect(screen.queryByTestId('reclaim-outcome')).toBeNull();
  });

  it.each(['pagehide', 'popstate'])(
    'clears the link and code on %s and does not recover from bfcache',
    async (event) => {
      render(page());
      const input = await totp();
      fireEvent.change(input, { target: { value: '012345' } });
      fireEvent(window, new Event(event));
      expect(input.value).toBe('');
      fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
      start();
      expect(api.options).toHaveBeenCalledTimes(1);
      expect(api.complete).not.toHaveBeenCalled();
      expect(
        screen.getByRole<HTMLButtonElement>('button', { name: 'Start account recovery' }).disabled
      ).toBe(true);
    }
  );

  it('clears token and requests on a real unmount, so remounting the scrubbed URL cannot resume', async () => {
    const prepared = deferred<ReclaimOptions>();
    api.options.mockReturnValueOnce(prepared.promise);
    const view = render(page());
    start();
    view.unmount();
    expect(api.options.mock.calls[0][1].aborted).toBe(true);
    await act(async () => prepared.resolve({ factor: 'totp' }));
    render(page());
    start();
    expect(api.options).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
  });
});

describe('uncertain completion', () => {
  it('aborts a transmitted recovery on unmount and cannot resurrect its token or outcome on remount', async () => {
    const completed = deferred<void>();
    api.complete.mockImplementationOnce((_proof, _signal, sent) => {
      sent?.();
      return completed.promise;
    });
    const view = render(page());
    await submitTotp();
    view.unmount();
    expect(api.complete.mock.calls[0][1].aborted).toBe(true);
    await act(async () => completed.resolve());
    render(page());
    expect(screen.queryByTestId('reclaim-outcome')).toBeNull();
    expect(
      screen.getByRole<HTMLButtonElement>('button', { name: 'Start account recovery' }).disabled
    ).toBe(true);
    expect(api.complete).toHaveBeenCalledTimes(1);
    expect(api.options).toHaveBeenCalledTimes(1);
  });

  it.each(['cancel', 'hide', 'pagehide', 'expiry'] as const)(
    'records post-send %s as unconfirmed immediately, clears the link and ignores a late 204',
    async (reason) => {
      jest.useFakeTimers();
      const completed = deferred<void>();
      api.complete.mockImplementationOnce((_proof, _signal, sent) => {
        sent?.();
        return completed.promise;
      });
      render(page());
      const input = await submitTotp();
      if (reason === 'cancel')
        fireEvent.click(screen.getByRole('button', { name: 'Cancel recovery' }));
      else if (reason === 'hide') hide();
      else if (reason === 'pagehide') fireEvent(window, new Event('pagehide'));
      else act(() => jest.advanceTimersByTime(300001));
      expect(input.value).toBe('');
      expect(api.complete.mock.calls[0][1].aborted).toBe(true);
      expect(screen.getByTestId('reclaim-outcome').getAttribute('data-outcome')).toBe(
        'unconfirmed'
      );
      await act(async () => completed.resolve());
      show();
      expect(screen.getByRole('heading', { name: 'Recovery outcome unconfirmed' })).toBeTruthy();
      expect(screen.queryByRole('button', { name: 'Start account recovery' })).toBeNull();
      expect(screen.queryByRole('link', { name: 'Sign in to your account' })).toBeNull();
      expect(api.complete).toHaveBeenCalledTimes(1);
      expect(api.options).toHaveBeenCalledTimes(1);
    }
  );

  it.each([
    new PortalError('network_error', 0, true),
    new PortalError('temporarily_unavailable', 503, true),
  ])(
    'never replays a lost completion or treats an unavailable link as proof of success: %s',
    async (failure) => {
      api.complete.mockImplementationOnce(async (_proof, _signal, sent) => {
        sent?.();
        throw failure;
      });
      render(page());
      await submitTotp();
      await screen.findByRole('heading', { name: 'Recovery outcome unconfirmed' });
      expect(screen.getByTestId('reclaim-outcome').textContent).toContain(
        'unavailable link does not prove'
      );
      expect(screen.getByTestId('reclaim-outcome').textContent).toContain('has not been retried');
      expect(screen.queryByRole('link', { name: 'Sign in to your account' })).toBeNull();
      expect(api.complete).toHaveBeenCalledTimes(1);
    }
  );
});
