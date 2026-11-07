import { TextEncoder } from 'node:util';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StrictMode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
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
  expect((await screen.findByText(/Email ownership is verified\. Return/)).textContent).toContain(
    'original registration tab'
  );
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
