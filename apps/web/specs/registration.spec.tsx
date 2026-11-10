import { TextEncoder } from 'node:util';
import { act, fireEvent, render, screen, waitFor } from '../i18n/testing';
import { StrictMode, type ReactElement } from 'react';
import { I18nTestProvider } from '../i18n/testing';
import { renderToStaticMarkup as renderStatic } from 'react-dom/server';
const renderToStaticMarkup = (element: ReactElement) => renderStatic(<I18nTestProvider>{element}</I18nTestProvider>);
import { Registration, RegistrationEmailVerification } from '../app/_components/registration';
import { RegistrationClient } from '../app/_lib/portal/registration-client';
import { requireWebAuthn, usePasskey } from '../app/_lib/portal/webauthn';
import { onOtherTabInvalidation, sensitiveClearEvent } from '../app/_lib/portal/invalidation';
import { PortalError } from '../app/_lib/portal/errors';
jest.mock('../app/_lib/portal/registration-client', () => ({
  ...jest.requireActual('../app/_lib/portal/registration-client'),
  RegistrationClient: jest.fn(),
}));
jest.mock('../app/_lib/portal/webauthn', () => ({
  requireWebAuthn: jest.fn(),
  usePasskey: jest.fn(),
}));
jest.mock('../app/_lib/portal/invalidation', () => ({
  onOtherTabInvalidation: jest.fn(),
  sensitiveClearEvent: 'portal-sensitive-clear',
}));
const attemptID = '11111111-1111-4111-8111-111111111111';
const token = 'A'.repeat(43);
const canonical = '\u0647\u0627\u062a\u0641@example.test';
const api = {
  start: jest.fn(),
  verifyEmail: jest.fn(),
  result: jest.fn(),
  resendEmail: jest.fn(),
  sendPhone: jest.fn(),
  verifyPhone: jest.fn(),
  hasPhoneVerification: jest.fn(),
  passkeyOptions: jest.fn(),
  complete: jest.fn(),
  assertKey: jest.fn(),
  dispose: jest.fn(),
};
let invalidate: () => void;
let visibility: PropertyDescriptor | undefined;
const encoder = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder');
beforeAll(() =>
  Object.defineProperty(globalThis, 'TextEncoder', { configurable: true, value: TextEncoder })
);
afterAll(() => {
  if (encoder) Object.defineProperty(globalThis, 'TextEncoder', encoder);
  else Reflect.deleteProperty(globalThis, 'TextEncoder');
});
beforeEach(() => {
  jest.resetAllMocks();
  window.history.replaceState(null, '', '/register');
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  jest.mocked(RegistrationClient).mockImplementation(() => api as unknown as RegistrationClient);
  jest.mocked(onOtherTabInvalidation).mockImplementation((callback) => {
    invalidate = callback;
    return jest.fn();
  });
  api.start.mockResolvedValue({
    canonical_email: canonical,
    expires_at: new Date(Date.now() + 890000).toISOString(),
    email_sent: true,
  });
  api.verifyEmail.mockResolvedValue(undefined);
  api.resendEmail.mockResolvedValue(undefined);
  api.result.mockResolvedValue({
    state: 'pending',
    expires_at: new Date(Date.now() + 890000).toISOString(),
    email_verified: true,
    phone_verified: false,
  });
  api.sendPhone.mockResolvedValue(undefined);
  api.verifyPhone.mockResolvedValue(undefined);
  api.hasPhoneVerification.mockReturnValue(false);
  api.passkeyOptions.mockResolvedValue({ publicKey: { challenge: 'opaque' } });
  api.complete.mockResolvedValue({
    state: 'completed',
    next: 'login',
    email_verified: true,
    phone_verified: true,
    receipt_expires_at: new Date(Date.now() + 3599000).toISOString(),
  });
  api.assertKey.mockResolvedValue(undefined);
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ id: 'attestation' } as Awaited<ReturnType<typeof usePasskey>>);
});
afterEach(() => {
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.restoreAllMocks();
  jest.useRealTimers();
  window.history.replaceState(null, '', '/');
});
function enter(label: string, value: string) {
  const field = screen.getByLabelText<HTMLInputElement>(label);
  fireEvent.change(field, { target: { value } });
  return field;
}
function start() {
  enter('Email address', ` ${canonical.split('@')[0]}@EXAMPLE.test `);
  enter('Iranian mobile number', '+989123456789');
  fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
}
async function toPhone() {
  start();
  fireEvent.click(await screen.findByRole('button', { name: 'Check email verification' }));
  await screen.findByRole('button', { name: 'Send SMS code' });
}
async function toPasskey() {
  await toPhone();
  fireEvent.click(screen.getByRole('button', { name: 'Send SMS code' }));
  const field = await screen.findByLabelText('SMS verification code');
  fireEvent.change(field, { target: { value: '012345' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
  await screen.findByRole('button', { name: 'Create passkey and complete registration' });
}

it('renders safe inert no-JS registration and link pages without fake password signup or network', () => {
  for (const component of [<Registration />, <RegistrationEmailVerification />]) {
    const html = renderToStaticMarkup(component),
      doc = new DOMParser().parseFromString(html, 'text/html');
    expect(
      [...doc.querySelectorAll<HTMLButtonElement>('button')].every((button) => button.disabled)
    ).toBe(true);
    expect(
      doc.querySelector('input[type="password"], input[type="email"], [formaction], script')
    ).toBeNull();
    expect(html).toContain('JavaScript is required');
    expect(html).not.toContain(token);
    const form = doc.forms[0];
    if (form) {
      expect(form.getAttribute('action')).toBeNull();
      expect(
        [...form.querySelectorAll<HTMLInputElement>('input')].every((input) => input.disabled)
      ).toBe(true);
    }
  }
  expect(RegistrationClient).not.toHaveBeenCalled();
});

it('simulates the explicit full UI flow, canonical bidi display, leading-zero SMS and create=true passkey with no automatic delivery', async () => {
  const storage = jest.spyOn(Storage.prototype, 'setItem');
  const { container } = render(<Registration />);
  const email = screen.getByLabelText<HTMLInputElement>('Email address');
  expect(email.type).toBe('text');
  expect(email.inputMode).toBe('email');
  expect(email.dir).toBe('ltr');
  expect(email.autocomplete).toBe('email');
  expect(email.hasAttribute('maxlength')).toBe(false);
  expect(api.start).not.toHaveBeenCalled();
  expect(RegistrationClient).not.toHaveBeenCalled();
  start();
  await screen.findByRole('button', { name: 'Check email verification' });
  expect(api.start.mock.calls[0][0]).toEqual({
    email: ` ${canonical.split('@')[0]}@EXAMPLE.test `,
    phone: '+989123456789',
  });
  expect(container.querySelector('bdi')?.textContent).toBe(canonical);
  expect(container.querySelector('bdi')?.dir).toBe('ltr');
  expect(api.result).not.toHaveBeenCalled();
  expect(api.sendPhone).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Check email verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Send SMS code' }));
  const code = await screen.findByLabelText<HTMLInputElement>('SMS verification code');
  expect(document.activeElement).toBe(code);
  fireEvent.change(code, { target: { value: '012345' } });
  expect(api.verifyPhone).not.toHaveBeenCalled();
  fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
  expect(api.verifyPhone.mock.calls[0][0]).toBe('012345');
  expect(api.passkeyOptions).not.toHaveBeenCalled();
  fireEvent.click(
    await screen.findByRole('button', { name: 'Create passkey and complete registration' })
  );
  await screen.findByRole('link', { name: 'Sign in with your passkey' });
  expect(usePasskey).toHaveBeenCalledWith(
    { publicKey: { challenge: 'opaque' } },
    expect.any(AbortSignal),
    true
  );
  expect(api.complete).toHaveBeenCalledWith({ id: 'attestation' }, expect.any(AbortSignal));
  expect(api.dispose).toHaveBeenCalled();
  expect(container.querySelector('input, bdi')).toBeNull();
  expect(screen.getByRole('status').textContent).toContain('Registration did not sign you in');
  expect(document.activeElement?.textContent).toContain('Your account was created');
  expect(storage).not.toHaveBeenCalled();
});

it('captures and scrubs email fragment once in StrictMode before any network and verifies only on explicit action', async () => {
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${token}`
  );
  const history = jest.spyOn(window.history, 'replaceState'),
    storage = jest.spyOn(Storage.prototype, 'setItem');
  const { container } = render(
    <StrictMode>
      <RegistrationEmailVerification />
    </StrictMode>
  );
  expect(window.location.hash).toBe('');
  expect(history).toHaveBeenCalledTimes(1);
  expect(history).toHaveBeenCalledWith(null, '', '/register/verify-email');
  expect(api.verifyEmail).not.toHaveBeenCalled();
  expect(RegistrationClient).not.toHaveBeenCalled();
  expect(container.innerHTML).not.toContain(token);
  expect(storage).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Verify email ownership' }));
  await waitFor(() =>
    expect(api.verifyEmail).toHaveBeenCalledWith(
      { attempt_id: attemptID, token },
      expect.any(AbortSignal)
    )
  );
  expect((await screen.findByRole('heading', { name: 'Email verified', level: 1 })).textContent).toBe('Email verified');
  expect(screen.getByText('Return to the original registration tab and choose Check email verification there.')).toBeTruthy();
  expect(screen.getByRole('status').textContent).toContain('This did not create an account or sign you in');
  expect(screen.queryByRole('button', { name: 'Verify email ownership' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Restart registration' })).toBeNull();
  expect(api.start).not.toHaveBeenCalled();
  expect(api.sendPhone).not.toHaveBeenCalled();
});

it.each([
  '',
  `#token=${token}`,
  `#attempt_id=${attemptID}&token=${token}&token=${token}`,
  `#attempt_id=${attemptID}&token=%41${token.slice(1)}`,
  `?token=${token}`,
  `?tracking=1#attempt_id=${attemptID}&token=${token}`,
  `#attempt_id=00000000-0000-0000-0000-000000000000&token=${token}`,
])(
  'scrubs malformed, duplicate, encoded or query-bearing email links without any request',
  (suffix) => {
    window.history.replaceState(null, '', `/register/verify-email${suffix}`);
    render(<RegistrationEmailVerification />);
    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('');
    expect(
      screen.getByRole<HTMLButtonElement>('button', { name: 'Verify email ownership' }).disabled
    ).toBe(true);
    expect(screen.getByRole('alert').textContent).toContain('original browser');
    expect(RegistrationClient).not.toHaveBeenCalled();
  }
);

it('does not verify when fragment scrubbing fails', () => {
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${token}`
  );
  jest.spyOn(window.history, 'replaceState').mockImplementation(() => {
    throw new Error('Blocked');
  });
  render(<RegistrationEmailVerification />);
  expect(
    screen.getByRole<HTMLButtonElement>('button', { name: 'Verify email ownership' }).disabled
  ).toBe(true);
  expect(RegistrationClient).not.toHaveBeenCalled();
});

it('shows an opaque restart for a wrong-browser email proof without recovering signup capability or auto retrying', async () => {
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${token}`
  );
  api.verifyEmail.mockRejectedValue(new PortalError('invalid_registration', 401));
  render(<RegistrationEmailVerification />);
  fireEvent.click(screen.getByRole('button', { name: 'Verify email ownership' }));
  expect((await screen.findByRole('alert')).textContent).toContain('restart registration');
  expect(api.verifyEmail).toHaveBeenCalledTimes(1);
  expect(api.start).not.toHaveBeenCalled();
});

it('an email/SMS delivery failure is never ownership and never causes a billed automatic resend', async () => {
  api.start.mockResolvedValue({
    canonical_email: canonical,
    expires_at: new Date(Date.now() + 890000).toISOString(),
    email_sent: false,
  });
  render(<Registration />);
  start();
  await screen.findByText(/Email delivery was not confirmed/);
  expect(api.resendEmail).not.toHaveBeenCalled();
  expect(api.sendPhone).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Send another verification email' }));
  await waitFor(() => expect(api.resendEmail).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: 'Check email verification' }));
  api.sendPhone.mockRejectedValue(new PortalError('send_failed', 503));
  fireEvent.click(await screen.findByRole('button', { name: 'Send SMS code' }));
  expect((await screen.findByRole('alert')).textContent).toContain('Ownership is not verified');
  expect(api.sendPhone).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText('SMS verification code')).toBeNull();
  expect(api.verifyPhone).not.toHaveBeenCalled();
  expect(api.passkeyOptions).not.toHaveBeenCalled();
});

it('resolves a lost completion only by explicit result inspection with no creation replay', async () => {
  render(<Registration />);
  await toPasskey();
  api.complete.mockRejectedValueOnce(new PortalError('network_error', 0, true));
  fireEvent.click(screen.getByRole('button', { name: 'Create passkey and complete registration' }));
  await screen.findByRole('button', { name: 'Check registration result' });
  expect(api.result).toHaveBeenCalledTimes(1);
  expect(
    screen.queryByRole('button', { name: 'Create passkey and complete registration' })
  ).toBeNull();
  api.result.mockResolvedValue({
    state: 'completed',
    next: 'login',
    receipt_expires_at: new Date(Date.now() + 3599000).toISOString(),
    email_verified: true,
    phone_verified: true,
  });
  fireEvent.click(screen.getByRole('button', { name: 'Check registration result' }));
  await screen.findByRole('link', { name: 'Sign in with your passkey' });
  expect(api.complete).toHaveBeenCalledTimes(1);
  expect(usePasskey).toHaveBeenCalledTimes(1);
});

async function expiringCompletion() {
  jest.useFakeTimers();
  const timers = jest.spyOn(window, 'setTimeout');
  const expires_at = new Date(Date.now() + 1379).toISOString();
  api.start.mockResolvedValue({ canonical_email: canonical, expires_at, email_sent: true });
  api.result.mockResolvedValue({
    state: 'pending',
    expires_at,
    email_verified: true,
    phone_verified: true,
  });
  const view = render(<Registration />);
  start();
  await act(async () => undefined);
  fireEvent.click(screen.getByRole('button', { name: 'Check email verification' }));
  await act(async () => undefined);
  const oldTimer = timers.mock.calls.find(([, delay]) => delay === 1379)?.[0];
  return { view, expires_at, oldTimer };
}

it.each(['delayed OK', 'lost post-commit response'])(
  'retains completion authority past pending expiry for a %s without polling or creation replay',
  async (response) => {
    const { oldTimer } = await expiringCompletion();
    let finish!: (value: unknown) => void;
    let fail!: (error: unknown) => void;
    api.complete.mockImplementationOnce(
      () =>
        new Promise((resolve, reject) => {
          finish = resolve;
          fail = reject;
        })
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Create passkey and complete registration' })
    );
    await act(async () => undefined);
    const signal = api.complete.mock.calls[0][1] as AbortSignal;
    expect(typeof oldTimer).toBe('function');
    // Simulate an already queued callback that React's effect cleanup cannot cancel.
    act(() => {
      jest.advanceTimersByTime(1380);
      if (typeof oldTimer === 'function') oldTimer();
    });
    expect(signal.aborted).toBe(false);
    expect(api.dispose).not.toHaveBeenCalled();
    expect(screen.getByRole('status').textContent).toContain('Create a passkey');
    expect(api.result).toHaveBeenCalledTimes(1);
    const receipt = {
      state: 'completed',
      next: 'login',
      email_verified: true,
      phone_verified: true,
      receipt_expires_at: new Date(Date.now() + 3598000).toISOString(),
    };
    if (response === 'delayed OK') await act(async () => finish(receipt));
    else {
      await act(async () => fail(new PortalError('network_error', 0, true)));
      expect(screen.getByRole('button', { name: 'Check registration result' })).toBeTruthy();
      expect(api.result).toHaveBeenCalledTimes(1);
      api.result.mockResolvedValueOnce(receipt);
      fireEvent.click(screen.getByRole('button', { name: 'Check registration result' }));
      await act(async () => undefined);
    }
    expect(screen.getByRole('link', { name: 'Sign in with your passkey' })).toBeTruthy();
    expect(screen.getByRole('status').textContent).toContain('Registration did not sign you in');
    expect(api.complete).toHaveBeenCalledTimes(1);
    expect(usePasskey).toHaveBeenCalledTimes(1);
    expect(api.sendPhone).not.toHaveBeenCalled();
    expect(api.resendEmail).not.toHaveBeenCalled();
  }
);

it.each([
  'cancel',
  'unmount',
  'key invalidation',
  'pagehide',
  'popstate',
  'hashchange',
  'sensitive-clear',
])(
  'still disposes in-flight completion recovery on %s and suppresses late success',
  async (reason) => {
    const { view } = await expiringCompletion();
    let finish!: (value: unknown) => void;
    api.complete.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        })
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Create passkey and complete registration' })
    );
    await act(async () => undefined);
    act(() => jest.advanceTimersByTime(1380));
    const signal = api.complete.mock.calls[0][1] as AbortSignal;
    if (reason === 'cancel')
      fireEvent.click(screen.getByRole('button', { name: 'Cancel registration' }));
    else if (reason === 'unmount') view.unmount();
    else if (reason === 'key invalidation') act(() => invalidate());
    else fireEvent(window, new Event(reason === 'sensitive-clear' ? sensitiveClearEvent : reason));
    expect(signal.aborted).toBe(true);
    expect(api.dispose).toHaveBeenCalled();
    await act(async () => finish({ state: 'completed', next: 'login' }));
    expect(screen.queryByRole('link', { name: 'Sign in with your passkey' })).toBeNull();
  }
);

it.each([false, true])(
  'explicit pending result restores the original bounded proof deadline (already expired: %s)',
  async (expired) => {
    await expiringCompletion();
    api.complete.mockRejectedValueOnce(new PortalError('network_error', 0, true));
    fireEvent.click(
      screen.getByRole('button', { name: 'Create passkey and complete registration' })
    );
    await act(async () => undefined);
    act(() => jest.advanceTimersByTime(expired ? 1380 : 500));
    fireEvent.click(screen.getByRole('button', { name: 'Check registration result' }));
    await act(async () => undefined);
    if (!expired) {
      expect(
        screen.getByRole('button', { name: 'Create passkey and complete registration' })
      ).toBeTruthy();
      // A rolled-back wall clock cannot renew the original proof authority.
      jest.setSystemTime(Date.now() - 3600000);
      act(() => jest.advanceTimersByTime(880));
    }
    expect(screen.getByRole('button', { name: 'Start a new registration' })).toBeTruthy();
    expect(api.dispose).toHaveBeenCalled();
    expect(api.complete).toHaveBeenCalledTimes(1);
    expect(api.result).toHaveBeenCalledTimes(2);
  }
);

it('completion errors and result errors never restart the submission-anchored monotonic recovery hour', async () => {
  await expiringCompletion();
  let fail!: (error: unknown) => void;
  api.complete.mockImplementationOnce(
    () =>
      new Promise((_, reject) => {
        fail = reject;
      })
  );
  fireEvent.click(screen.getByRole('button', { name: 'Create passkey and complete registration' }));
  await act(async () => undefined);
  act(() => jest.advanceTimersByTime(3500000));
  await act(async () => fail(new PortalError('network_error', 0, true)));
  api.result.mockRejectedValueOnce(new PortalError('result_required', 503));
  fireEvent.click(screen.getByRole('button', { name: 'Check registration result' }));
  await act(async () => undefined);
  jest.setSystemTime(Date.now() - 3600000);
  act(() => jest.advanceTimersByTime(100001));
  expect(screen.getByRole('button', { name: 'Start a new registration' })).toBeTruthy();
  expect(api.dispose).toHaveBeenCalled();
  expect(api.complete).toHaveBeenCalledTimes(1);
  expect(api.result).toHaveBeenCalledTimes(2);
});

it('keeps an explicit OTP retry opportunity after incorrect code without billing another SMS or claiming phone proof', async () => {
  render(<Registration />);
  await toPhone();
  fireEvent.click(screen.getByRole('button', { name: 'Send SMS code' }));
  const field = await screen.findByLabelText<HTMLInputElement>('SMS verification code');
  api.verifyPhone.mockRejectedValueOnce(new PortalError('proof_required', 409));
  api.hasPhoneVerification.mockReturnValue(true);
  fireEvent.change(field, { target: { value: '000000' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
  await screen.findByRole('alert');
  expect(screen.getByLabelText<HTMLInputElement>('SMS verification code').value).toBe('');
  expect(
    screen.queryByRole('button', { name: 'Create passkey and complete registration' })
  ).toBeNull();
  expect(api.sendPhone).toHaveBeenCalledTimes(1);
  expect(api.result).toHaveBeenCalledTimes(1);
  enter('SMS verification code', '012345');
  expect(api.verifyPhone).toHaveBeenCalledTimes(1);
  fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
  await screen.findByRole('button', { name: 'Create passkey and complete registration' });
  expect(api.verifyPhone.mock.calls.map(([value]) => value)).toEqual(['000000', '012345']);
  expect(api.sendPhone).toHaveBeenCalledTimes(1);
  expect(api.resendEmail).not.toHaveBeenCalled();
});

it.each([
  new PortalError('rate_limited', 429),
  new PortalError('restart_phone_proof', 409),
  new PortalError('network_error'),
])(
  'discards non-retryable OTP input without automatic sends or authoritative proof claims',
  async (failure) => {
    render(<Registration />);
    await toPhone();
    fireEvent.click(screen.getByRole('button', { name: 'Send SMS code' }));
    const field = await screen.findByLabelText<HTMLInputElement>('SMS verification code');
    api.verifyPhone.mockRejectedValueOnce(failure);
    fireEvent.change(field, { target: { value: '012345' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
    await screen.findByRole('alert');
    expect(screen.queryByLabelText('SMS verification code')).toBeNull();
    expect(screen.getByRole('button', { name: 'Send SMS code' })).toBeTruthy();
    expect(api.sendPhone).toHaveBeenCalledTimes(1);
    expect(api.result).toHaveBeenCalledTimes(1);
    expect(api.passkeyOptions).not.toHaveBeenCalled();
    expect(api.complete).not.toHaveBeenCalled();
  }
);

it.each(['unsupported', 'cancelled', 'authenticator_security'])(
  'handles %s authenticators without account creation or automatic retry',
  async (error) => {
    render(<Registration />);
    await toPasskey();
    jest.mocked(usePasskey).mockRejectedValue(new PortalError(error));
    fireEvent.click(
      screen.getByRole('button', { name: 'Create passkey and complete registration' })
    );
    await screen.findByRole('alert');
    expect(api.complete).not.toHaveBeenCalled();
    expect(usePasskey).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole<HTMLButtonElement>('button', {
        name: 'Create passkey and complete registration',
      }).disabled
    ).toBe(false);
  }
);

it('an unsupported browser cannot allocate or send even the initial email', async () => {
  jest.mocked(requireWebAuthn).mockImplementation(() => {
    throw new PortalError('unsupported');
  });
  render(<Registration />);
  start();
  await screen.findByRole('alert');
  expect(api.start).not.toHaveBeenCalled();
  expect(api.sendPhone).not.toHaveBeenCalled();
});

it('focuses invalid Unicode/raw byte input without native ASCII email validity or contacting the service', () => {
  render(<Registration />);
  const email = enter('Email address', 'a\ud800@example.test');
  enter('Iranian mobile number', '+989123456789');
  fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
  expect(document.activeElement).toBe(email);
  expect(email.getAttribute('aria-invalid')).toBe('true');
  expect(api.start).not.toHaveBeenCalled();
  enter('Email address', '\u00e9'.repeat(512) + '@example.test');
  fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
  expect(api.start).not.toHaveBeenCalled();
});

it('announces Retry-After without scheduling delivery and clears authority on cross-tab key changes', async () => {
  render(<Registration />);
  start();
  await screen.findByRole('button', { name: 'Check email verification' });
  api.resendEmail.mockRejectedValue(new PortalError('rate_limited', 429, false, 60));
  fireEvent.click(screen.getByRole('button', { name: 'Send another verification email' }));
  expect((await screen.findByRole('alert')).textContent).toContain('Wait 60 seconds');
  expect(api.resendEmail).toHaveBeenCalledTimes(1);
  api.assertKey.mockRejectedValue(new PortalError('registration_key_changed'));
  fireEvent(document, new Event('visibilitychange'));
  await screen.findByRole('button', { name: 'Start a new registration' });
  expect(api.dispose).toHaveBeenCalled();
  expect(document.querySelector('bdi')).toBeNull();
});

it.each(['cancel', 'pagehide', 'popstate', 'invalidation', 'sensitive-clear'])(
  'clears authority and ignores late replies after %s',
  async (reason) => {
    let finish!: (value: unknown) => void;
    api.start.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        })
    );
    render(<Registration />);
    start();
    const signal = api.start.mock.calls[0][1] as AbortSignal;
    if (reason === 'cancel')
      fireEvent.click(screen.getByRole('button', { name: 'Cancel registration' }));
    else if (reason === 'invalidation') act(() => invalidate());
    else fireEvent(window, new Event(reason === 'sensitive-clear' ? sensitiveClearEvent : reason));
    expect(signal.aborted).toBe(true);
    expect(api.dispose).toHaveBeenCalled();
    await act(async () =>
      finish({
        canonical_email: canonical,
        expires_at: new Date(Date.now() + 890000).toISOString(),
        email_sent: true,
      })
    );
    expect(screen.getByRole('button', { name: 'Start a new registration' })).toBeTruthy();
    expect(document.querySelector('bdi')).toBeNull();
    expect(api.sendPhone).not.toHaveBeenCalled();
  }
);

it('retains idle signup authority across the email-tab handoff but clears OTP input and rechecks key without sending', async () => {
  render(<Registration />);
  await toPhone();
  fireEvent.click(screen.getByRole('button', { name: 'Send SMS code' }));
  const field = await screen.findByLabelText<HTMLInputElement>('SMS verification code');
  fireEvent.change(field, { target: { value: '012345' } });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
  expect(field.value).toBe('');
  expect(api.dispose).not.toHaveBeenCalled();
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
  await waitFor(() => expect(api.assertKey).toHaveBeenCalledTimes(1));
  expect(api.sendPhone).toHaveBeenCalledTimes(1);
  expect(api.result).toHaveBeenCalledTimes(1);
});

it('expires retained signup authority and the email fragment on absolute and monotonic deadlines without sends', async () => {
  jest.useFakeTimers();
  const view = render(<Registration />);
  start();
  await act(async () => undefined);
  expect(screen.getByRole('button', { name: 'Check email verification' })).toBeTruthy();
  const before = Date.now();
  jest.setSystemTime(before - 3600000);
  act(() => jest.advanceTimersByTime(890001));
  expect(screen.getByRole('button', { name: 'Start a new registration' })).toBeTruthy();
  expect(api.dispose).toHaveBeenCalled();
  expect(api.sendPhone).not.toHaveBeenCalled();
  expect(api.resendEmail).not.toHaveBeenCalled();
  view.unmount();
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${token}`
  );
  render(<RegistrationEmailVerification />);
  jest.setSystemTime(Date.now() + 600001);
  fireEvent.click(screen.getByRole('button', { name: 'Verify email ownership' }));
  expect(api.verifyEmail).not.toHaveBeenCalled();
  expect(screen.getByRole('alert').textContent).toContain('restart registration');
});

it('ignores an email hash replacement instead of redeeming a new fragment', () => {
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${token}`
  );
  render(<RegistrationEmailVerification />);
  window.history.replaceState(
    null,
    '',
    `/register/verify-email#attempt_id=${attemptID}&token=${'B'.repeat(42)}A`
  );
  fireEvent(window, new Event('hashchange'));
  expect(window.location.hash).toBe('');
  fireEvent.click(screen.getByRole('button', { name: 'Verify email ownership' }));
  expect(api.verifyEmail).not.toHaveBeenCalled();
});

it.each(['result', 'complete'] as const)(
  'cannot restore a late %s after cancellation even if a transport ignores abort',
  async (operation) => {
    let finish!: (value: unknown) => void;
    const view = render(<Registration />);
    if (operation === 'complete') await toPasskey();
    else {
      start();
      await screen.findByRole('button', { name: 'Check email verification' });
    }
    api[operation].mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        })
    );
    fireEvent.click(
      screen.getByRole('button', {
        name:
          operation === 'complete'
            ? 'Create passkey and complete registration'
            : 'Check email verification',
      })
    );
    await waitFor(() => expect(finish).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: 'Cancel registration' }));
    await act(async () =>
      finish({
        state: 'completed',
        next: 'login',
        receipt_expires_at: new Date(Date.now() + 3599000).toISOString(),
        email_verified: true,
        phone_verified: true,
      })
    );
    expect(screen.queryByRole('link', { name: 'Sign in with your passkey' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Start a new registration' })).toBeTruthy();
    view.unmount();
  }
);


test('language changes preserve the registration client, frozen deadline and pending ownership without sending', async () => {
  const { rerender, container } = render(<I18nTestProvider locale="en"><Registration /></I18nTestProvider>);
  const heading = screen.getByRole('heading', { level: 1 });
  const frame = heading.parentElement?.parentElement;
  start();
  await screen.findByRole('button', { name: 'Check email verification' });
  expect(screen.getByRole('heading', { name: 'Verify your email', level: 1 })).toBe(heading);
  const expiry = container.querySelector('time')?.dateTime;
  expect(expiry).toBeTruthy();
  const clients = jest.mocked(RegistrationClient).mock.calls.length;
  rerender(<I18nTestProvider locale="fa-IR"><Registration /></I18nTestProvider>);
  expect(screen.getByRole('button', { name: 'بررسی تأیید ایمیل' })).toBeTruthy();
  expect(screen.getByRole('heading', { name: 'ایمیل خود را تأیید کنید', level: 1 })).toBe(heading);
  expect(heading.parentElement?.parentElement).toBe(frame);
  expect(container.querySelector('time')?.dateTime).toBe(expiry);
  expect(container.textContent).toContain(canonical);
  expect(RegistrationClient).toHaveBeenCalledTimes(clients);
  expect(api.start).toHaveBeenCalledTimes(1);
  for (const action of [api.result, api.resendEmail, api.sendPhone, api.verifyPhone, api.complete]) expect(action).not.toHaveBeenCalled();
  expect(api.dispose).not.toHaveBeenCalled();
});

test('email-link presentation changes retain one proof and the scrubbed public URL without verification', async () => {
  window.history.replaceState(null, '', `/register/verify-email#attempt_id=${attemptID}&token=${token}`);
  const { rerender } = render(<I18nTestProvider locale="en"><RegistrationEmailVerification /></I18nTestProvider>);
  const heading = screen.getByRole('heading', { name: 'Verify your email ownership', level: 1 });
  await act(async () => { await Promise.resolve(); });
  expect(window.location.hash).toBe('');
  rerender(<I18nTestProvider locale="fa-IR"><RegistrationEmailVerification /></I18nTestProvider>);
  expect(screen.getByRole<HTMLButtonElement>('button', { name: 'تأیید مالکیت ایمیل' }).disabled).toBe(false);
  expect(screen.getByRole('heading', { name: 'مالکیت ایمیل خود را تأیید کنید', level: 1 })).toBe(heading);
  expect(window.location.pathname).toBe('/register/verify-email');
  expect(window.location.hash).toBe('');
  expect(api.verifyEmail).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'تأیید مالکیت ایمیل' }));
  await waitFor(() => expect(api.verifyEmail).toHaveBeenCalledTimes(1));
  expect(api.verifyEmail.mock.calls[0][0]).toEqual({ attempt_id: attemptID, token });
  await screen.findByRole('heading', { name: 'ایمیل تأیید شد', level: 1 });
  expect(screen.getByRole('heading', { level: 1 })).toBe(heading);
  expect(screen.getByText('به زبانهٔ اولیهٔ ثبت‌نام برگردید و «بررسی تأیید ایمیل» را در آنجا انتخاب کنید.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'تأیید مالکیت ایمیل' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'شروع دوبارهٔ ثبت‌نام' })).toBeNull();
});

it.each([
  ['+۹۸۹۱۲۳۴۵۶۷۸۹', '+989123456789'],
  ['۰۹۱۲۳۴۵۶۷۸۹', '09123456789'],
  ['٩٨٩١٢٣٤٥٦٧٨٩', '989123456789'],
  ['+98۹١۲3۴5۶7۸9', '+989123456789'],
])('normalizes typed/pasted phone %s while preserving email bytes and explicit delivery', async (raw, expected) => {
  render(<Registration />);
  const exactEmail = '  کاربر۱۲@EXAMPLE.test ';
  enter('Email address', exactEmail);
  const phone = enter('Iranian mobile number', raw);
  expect(phone.dir).toBe('ltr');
  expect(phone.value).toBe(expected);
  fireEvent.paste(phone, { clipboardData: { getData: () => raw } });
  fireEvent.input(phone, { target: { value: raw }, inputType: 'insertFromPaste' });
  expect(phone.value).toBe(expected);
  expect(api.start).not.toHaveBeenCalled();
  fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
  await screen.findByRole('button', { name: 'Check email verification' });
  expect(api.start.mock.calls[0][0]).toEqual({ email: exactEmail, phone: expected });
  expect(api.sendPhone).not.toHaveBeenCalled();
  expect(api.resendEmail).not.toHaveBeenCalled();
});

it('normalizes phone autofill at the submission boundary even without React change events', async () => {
  render(<Registration />);
  enter('Email address', 'person@example.test');
  const phone = screen.getByLabelText<HTMLInputElement>('Iranian mobile number');
  phone.value = '۰٩۱٢۳٤۵٦۷٨۹';
  fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
  await screen.findByRole('button', { name: 'Check email verification' });
  expect(api.start.mock.calls[0][0].phone).toBe('09123456789');
});

it.each(['０９１２３４５６７８９', '+98۹ 123456789', '+98912x456789', '0912345678', '091234567890', '\u202e09123456789'])(
  'rejects invalid phone %j after digit-only conversion without changing format rules or sending',
  (raw) => {
    render(<Registration />);
    enter('Email address', 'person@example.test');
    const phone = enter('Iranian mobile number', raw);
    fireEvent.submit(screen.getByRole('form', { name: 'Create an account' }));
    expect(phone.value).toBe(raw.replace('۹', '9'));
    expect(phone.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(phone);
    expect(api.start).not.toHaveBeenCalled();
    expect(RegistrationClient).not.toHaveBeenCalled();
  }
);

it.each(['en', 'fa-IR'] as const)('keeps one phase-heading frame and puts SMS verification before resend and technical details in %s', async (locale) => {
  const copy = locale === 'en' ? {
    headings: ['Create your account', 'Verify your email', 'Verify your mobile number', 'Create your passkey', 'Check registration outcome', 'Account created'],
    email: 'Email address', phone: 'Iranian mobile number', form: 'Create an account',
    check: 'Check email verification', send: 'Send SMS code', code: 'SMS verification code',
    verify: 'Verify phone', phoneForm: 'Verify registration phone', resend: 'Send a new SMS code', proofs: 'Check saved proofs',
    complete: 'Create passkey and complete registration', result: 'Check registration result', signIn: 'Sign in with your passkey',
  } : {
    headings: ['حساب خود را ایجاد کنید', 'ایمیل خود را تأیید کنید', 'شمارهٔ همراه خود را تأیید کنید', 'کلید عبور خود را بسازید', 'نتیجهٔ ثبت‌نام را بررسی کنید', 'حساب ساخته شد'],
    email: 'نشانی ایمیل', phone: 'شمارهٔ همراه ایران', form: 'ساخت حساب',
    check: 'بررسی تأیید ایمیل', send: 'ارسال کد پیامکی', code: 'کد تأیید پیامکی',
    verify: 'تأیید تلفن', phoneForm: 'تأیید تلفن ثبت‌نام', resend: 'ارسال کد پیامکی تازه', proofs: 'بررسی مدارک ذخیره‌شده',
    complete: 'ساخت کلید عبور و تکمیل ثبت‌نام', result: 'بررسی نتیجهٔ ثبت‌نام', signIn: 'ورود با کلید عبور',
  };
  const { container } = render(<Registration />, { locale });
  const heading = screen.getByRole('heading', { name: copy.headings[0], level: 1 });
  const frame = heading.parentElement?.parentElement;
  const expectHeading = (name: string) => {
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { name, level: 1 })).toBe(heading);
    expect(heading.parentElement?.parentElement).toBe(frame);
  };
  enter(copy.email, 'person@example.test');
  const phone = enter(copy.phone, '+۹۸۹۱۲۳۴۵۶۷۸۹');
  expect(phone.value).toBe('+989123456789');
  expect(phone.dir).toBe('ltr');
  fireEvent.submit(screen.getByRole('form', { name: copy.form }));
  await screen.findByRole('button', { name: copy.check });
  expectHeading(copy.headings[1]);
  fireEvent.click(screen.getByRole('button', { name: copy.check }));
  await screen.findByRole('button', { name: copy.send });
  expectHeading(copy.headings[2]);
  const expiry = container.querySelector('time')?.dateTime;
  fireEvent.click(screen.getByRole('button', { name: copy.send }));
  const code = await screen.findByLabelText<HTMLInputElement>(copy.code);
  const verify = screen.getByRole('button', { name: copy.verify });
  const resend = screen.getByRole('button', { name: copy.resend });
  const proofs = screen.getByRole('button', { name: copy.proofs });
  expect(code.dir).toBe('ltr');
  expect(code.compareDocumentPosition(verify) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(verify.compareDocumentPosition(resend) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(resend.compareDocumentPosition(container.querySelector('time') as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(resend.compareDocumentPosition(proofs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(container.querySelector('time')?.dateTime).toBe(expiry);
  for (const raw of ['۰۱۲۳۴۵', '٠١٢٣٤٥', '0۱٢۳4۵']) {
    fireEvent.change(code, { target: { value: raw } });
    expect(code.value).toBe('012345');
    expect(api.verifyPhone).not.toHaveBeenCalled();
  }
  fireEvent.paste(code, { clipboardData: { getData: () => '۰۱٢۳٤۵' } });
  fireEvent.input(code, { target: { value: '۰۱٢۳٤۵' }, inputType: 'insertFromPaste' });
  expect(code.value).toBe('012345');
  code.value = '۰۱٢۳٤۵';
  fireEvent.submit(screen.getByRole('form', { name: copy.phoneForm }));
  await screen.findByRole('button', { name: copy.complete });
  expectHeading(copy.headings[3]);
  expect(api.start.mock.calls[0][0].phone).toBe('+989123456789');
  expect(api.verifyPhone.mock.calls[0][0]).toBe('012345');
  api.complete.mockRejectedValueOnce(new PortalError('network_error', 0, true));
  fireEvent.click(screen.getByRole('button', { name: copy.complete }));
  await screen.findByRole('button', { name: copy.result });
  expectHeading(copy.headings[4]);
  api.result.mockResolvedValueOnce({ state: 'completed', next: 'login' });
  fireEvent.click(screen.getByRole('button', { name: copy.result }));
  await screen.findByRole('link', { name: copy.signIn });
  expectHeading(copy.headings[5]);
  expect(RegistrationClient).toHaveBeenCalledTimes(1);
  expect(api.sendPhone).toHaveBeenCalledTimes(1);
  expect(api.resendEmail).not.toHaveBeenCalled();
  expect(api.complete).toHaveBeenCalledTimes(1);
  expect(container.querySelector('input, time')).toBeNull();
  expect(screen.queryByRole('button', { name: copy.complete })).toBeNull();
});

it.each(['０１２３４５', '۰۱۲۳۴', '۰۱۲۳۴۵۶', '0۱٢ ۳45', '0۱٢x45', '\u202e012345', '012345\u2069'])(
  'rejects invalid SMS %j without stripping junk, auto-verifying or resending',
  async (raw) => {
    render(<Registration />);
    await toPhone();
    fireEvent.click(screen.getByRole('button', { name: 'Send SMS code' }));
    const code = await screen.findByLabelText<HTMLInputElement>('SMS verification code');
    fireEvent.change(code, { target: { value: raw } });
    const normalized = code.value;
    fireEvent.submit(screen.getByRole('form', { name: 'Verify registration phone' }));
    expect(code.value).toBe(normalized);
    expect(code.getAttribute('aria-invalid')).toBe('true');
    expect(code.value.length).toBe(raw.length);
    expect(document.activeElement).toBe(code);
    expect(api.verifyPhone).not.toHaveBeenCalled();
    expect(api.sendPhone).toHaveBeenCalledTimes(1);
    expect(api.passkeyOptions).not.toHaveBeenCalled();
  }
);

it('confirmed email keeps the same heading frame and original-tab handoff after presentation changes and expiry', async () => {
  jest.useFakeTimers();
  window.history.replaceState(null, '', `/register/verify-email#attempt_id=${attemptID}&token=${token}`);
  const { rerender } = render(<I18nTestProvider locale="en"><RegistrationEmailVerification /></I18nTestProvider>);
  const heading = screen.getByRole('heading', { level: 1 });
  fireEvent.click(screen.getByRole('button', { name: 'Verify email ownership' }));
  expect(screen.getByRole('heading', { name: 'Verifying email ownership', level: 1 })).toBe(heading);
  await act(async () => undefined);
  expect(screen.getByRole('heading', { name: 'Email verified', level: 1 })).toBe(heading);
  act(() => jest.advanceTimersByTime(600001));
  rerender(<I18nTestProvider locale="fa-IR"><RegistrationEmailVerification /></I18nTestProvider>);
  expect(screen.getByRole('heading', { name: 'ایمیل تأیید شد', level: 1 })).toBe(heading);
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.queryByRole('button', { name: 'تأیید مالکیت ایمیل' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'شروع دوبارهٔ ثبت‌نام' })).toBeNull();
  expect(window.location.pathname).toBe('/register/verify-email');
  expect(window.location.hash).toBe('');
  expect(api.verifyEmail).toHaveBeenCalledTimes(1);
  expect(api.start).not.toHaveBeenCalled();
  expect(api.result).not.toHaveBeenCalled();
});

it.each(['en', 'fa-IR'] as const)('preserves RTL-first international mailbox selection, punctuation and exact submission bytes in %s', async (locale) => {
  const view = (language: 'en' | 'fa-IR') => <I18nTestProvider locale={language}><Registration /></I18nTestProvider>;
  const { rerender, container } = render(view(locale));
  const email = screen.getByLabelText<HTMLInputElement>(locale === 'en' ? 'Email address' : 'نشانی ایمیل');
  const raw = '  هاتف۱۲+news.!tag@BÜCHER.example  ';
  fireEvent.change(email, { target: { value: raw } });
  email.focus();
  const at = raw.indexOf('@');
  email.setSelectionRange(2, at, 'backward');
  const selected = email.value.slice(email.selectionStart ?? 0, email.selectionEnd ?? 0);
  expect(selected).toBe('هاتف۱۲+news.!tag');
  expect(fireEvent.copy(email)).toBe(true);
  const other = locale === 'en' ? 'fa-IR' : 'en';
  rerender(view(other));
  expect(screen.getByLabelText(other === 'en' ? 'Email address' : 'نشانی ایمیل')).toBe(email);
  expect(email.type).toBe('text');
  expect(email.inputMode).toBe('email');
  expect(email.dir).toBe('ltr');
  expect(email.value).toBe(raw);
  expect(email.selectionStart).toBe(2);
  expect(email.selectionEnd).toBe(at);
  expect(email.selectionDirection).toBe('backward');
  email.setSelectionRange(at, at);
  email.setRangeText('+paste', at, at, 'end');
  const exact = raw.slice(0, at) + '+paste' + raw.slice(at);
  fireEvent.input(email, { target: { value: exact }, inputType: 'insertFromPaste' });
  expect(email.value).toBe(exact);
  const canonicalEmail = 'هاتف۱۲+news.!tag+paste@xn--bcher-kva.example';
  api.start.mockResolvedValueOnce({ canonical_email: canonicalEmail, expires_at: new Date(Date.now() + 890000).toISOString(), email_sent: true });
  enter(other === 'en' ? 'Iranian mobile number' : 'شمارهٔ همراه ایران', '09123456789');
  expect(api.start).not.toHaveBeenCalled();
  fireEvent.submit(screen.getByRole('form', { name: other === 'en' ? 'Create an account' : 'ساخت حساب' }));
  await screen.findByRole('button', { name: other === 'en' ? 'Check email verification' : 'بررسی تأیید ایمیل' });
  expect(api.start.mock.calls[0][0].email).toBe(exact);
  expect(container.querySelector('bdi')?.textContent).toBe(canonicalEmail);
  expect(container.querySelector('bdi')?.dir).toBe('ltr');
  expect(api.start).toHaveBeenCalledTimes(1);
  expect(api.sendPhone).not.toHaveBeenCalled();
});

it.each([
  ['en', 'gregory', 'UTC', 'Nov 8, 2026, 9:00 PM'],
  ['en', 'gregory', 'Asia/Tehran', 'Nov 9, 2026, 12:30 AM'],
  ['en', 'persian', 'UTC', 'Aban 17, 1405 AP, 9:00 PM'],
  ['en', 'persian', 'Asia/Tehran', 'Aban 18, 1405 AP, 12:30 AM'],
  ['fa-IR', 'gregory', 'UTC', '۸ نوامبر ۲۰۲۶، ۲۱:۰۰'],
  ['fa-IR', 'gregory', 'Asia/Tehran', '۹ نوامبر ۲۰۲۶، ۰:۳۰'],
  ['fa-IR', 'persian', 'UTC', '۱۷ آبان ۱۴۰۵، ۲۱:۰۰'],
  ['fa-IR', 'persian', 'Asia/Tehran', '۱۸ آبان ۱۴۰۵، ۰:۳۰'],
] as const)('renders the registration deadline around 21:00 UTC correctly for %s/%s/%s without changing authority', async (locale, calendar, timeZone, expected) => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-11-08T20:45:10Z'));
  const expires_at = '2026-11-08T21:00:00Z';
  api.start.mockResolvedValueOnce({ canonical_email: canonical, expires_at, email_sent: true });
  const view = (displayCalendar: 'gregory' | 'persian', zone: string) => <I18nTestProvider locale={locale} preferences={{ calendar: displayCalendar, timeZone: zone }}><Registration /></I18nTestProvider>;
  const { rerender, container } = render(view('gregory', 'UTC'));
  enter(locale === 'en' ? 'Email address' : 'نشانی ایمیل', 'person@example.test');
  enter(locale === 'en' ? 'Iranian mobile number' : 'شمارهٔ همراه ایران', '09123456789');
  fireEvent.submit(screen.getByRole('form', { name: locale === 'en' ? 'Create an account' : 'ساخت حساب' }));
  await act(async () => undefined);
  const time = container.querySelector('time');
  const heading = screen.getByRole('heading', { level: 1 });
  expect(time?.dateTime).toBe(expires_at);
  rerender(view(calendar, timeZone));
  expect(container.querySelector('time')).toBe(time);
  expect(time?.textContent).toBe(expected);
  expect(time?.dateTime).toBe(expires_at);
  expect(screen.getByRole('heading', { level: 1 })).toBe(heading);
  expect(RegistrationClient).toHaveBeenCalledTimes(1);
  expect(api.start).toHaveBeenCalledTimes(1);
  expect(api.dispose).not.toHaveBeenCalled();
  for (const request of [api.result, api.resendEmail, api.sendPhone, api.verifyPhone, api.complete]) expect(request).not.toHaveBeenCalled();
  act(() => jest.advanceTimersByTime(890001));
  expect(screen.getByRole('heading', { name: locale === 'en' ? 'Registration needs a fresh start' : 'ثبت‌نام باید دوباره آغاز شود', level: 1 })).toBe(heading);
  expect(container.querySelector('time')).toBeNull();
  expect(api.dispose).toHaveBeenCalled();
  expect(api.start).toHaveBeenCalledTimes(1);
});
