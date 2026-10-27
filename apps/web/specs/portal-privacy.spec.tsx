import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PortalProvider, usePortal } from '../app/dashboard/_components/portal-provider';
import PrivacyPage from '../app/dashboard/privacy/page';
import { PortalClient } from '../app/_lib/portal/client';
import { type Profile, StepUpGrant } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import {
  clearSensitiveViews,
  invalidateOtherTabs,
  onOtherTabInvalidation,
} from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

const replace = jest.fn();
jest.mock('next/navigation', () => ({
  usePathname: () => '/dashboard/privacy',
  useRouter: () => ({ replace }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({
  ...jest.requireActual('../app/_lib/portal/invalidation'),
  invalidateOtherTabs: jest.fn(),
  onOtherTabInvalidation: jest.fn(),
}));

function makeClient() {
  const profile: Profile = {
    id: 'private-user',
    email: 'private@example.test',
    display_name: 'Private account',
    status: 'active',
    deletion_enabled: true,
    lifecycle_revision: '1',
    session: { id: 'private-session', expires_at: new Date(Date.now() + 3600000).toISOString() },
  };
  const api = {
    profile: profile as Profile | undefined,
    bootstrap: jest.fn().mockResolvedValue(profile),
    assertSession: jest.fn((): Profile => {
      if (!api.profile) throw new PortalError('session_required', 401);
      return api.profile;
    }),
    dispose: jest.fn((): void => {
      api.profile = undefined;
    }),
    stepUpChallenge: jest.fn().mockResolvedValue({
      methods: ['webauthn', 'totp'],
      webauthn: { publicKey: { challenge: 'AA' } },
    }),
    stepUpVerify: jest.fn(
      async () =>
        new StepUpGrant(
          { token: 'private-grant', token_type: 'StepUp', expires_in: 60 },
          profile.session.id,
          Date.now(),
          Date.now() + 60000
        )
    ),
    deleteAccount: jest.fn(async (grant: StepUpGrant, _signal: AbortSignal, sent: () => void) => {
      grant.take(profile.session.id);
      sent();
    }),
    logout: jest.fn(),
    onSessionLoss: undefined as ((error: PortalError) => void) | undefined,
  };
  return api;
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((finish) => {
    resolve = finish;
  });
  return { promise, resolve };
}

function Content() {
  return (
    <>
      <p>{usePortal().profile.email}</p>
      <PrivacyPage />
    </>
  );
}

let api: ReturnType<typeof makeClient>;
let invalidate: () => void;
let originalVisibility: PropertyDescriptor | undefined;
beforeAll(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true,
    value: function (this: HTMLDialogElement) {
      this.setAttribute('open', '');
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true,
    value: function (this: HTMLDialogElement) {
      this.removeAttribute('open');
    },
  });
});
beforeEach(() => {
  jest.clearAllMocks();
  originalVisibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  api = makeClient();
  jest.mocked(PortalClient).mockImplementation(() => api as unknown as PortalClient);
  jest.mocked(onOtherTabInvalidation).mockImplementation((callback) => {
    invalidate = callback;
    return jest.fn();
  });
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ id: 'assertion' } as Awaited<ReturnType<typeof usePasskey>>);
});
afterEach(() => {
  if (originalVisibility) Object.defineProperty(document, 'visibilityState', originalVisibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.restoreAllMocks();
});

function renderPrivacy() {
  return render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
}
async function confirm() {
  await screen.findByRole('button', { name: 'Delete my account' });
  fireEvent.click(
    screen.getByRole('checkbox', { name: /I understand the account-deletion consequences/ })
  );
  fireEvent.click(screen.getByRole('button', { name: 'Delete my account' }));
}
async function send() {
  await confirm();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
  await waitFor(() => expect(api.deleteAccount).toHaveBeenCalledTimes(1));
}

it('server-renders only the protected shell with a privacy deep link', () => {
  const html = renderToStaticMarkup(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  expect(html).toContain('href="/dashboard/privacy"');
  expect(html).not.toContain('private@example.test');
  expect(html).not.toContain('Delete my account');
  expect(PortalClient).not.toHaveBeenCalled();
});

it('disables unavailable deletion capability and describes retention without a full-erasure promise', async () => {
  if (api.profile) api.profile.deletion_enabled = false;
  const { container } = renderPrivacy();
  const button = await screen.findByRole<HTMLButtonElement>('button', {
    name: 'Delete my account',
  });
  expect(button.disabled).toBe(true);
  expect(screen.getByRole<HTMLInputElement>('checkbox').disabled).toBe(true);
  expect(screen.getByRole('link', { name: 'Privacy' }).getAttribute('aria-current')).toBe('page');
  expect(screen.getByText(/Account deletion is currently unavailable/)).toBeTruthy();
  expect(screen.getByText(/Pseudonymized security and audit records/).textContent).toContain(
    'Backups'
  );
  expect(container.textContent).toContain('not a promise of complete erasure');
  fireEvent.click(button);
  expect(api.stepUpChallenge).not.toHaveBeenCalled();
  expect(api.deleteAccount).not.toHaveBeenCalled();
});

it('requires acknowledgement, permits pre-send cancellation and requires a new acknowledgement afterward', async () => {
  renderPrivacy();
  const button = await screen.findByRole<HTMLButtonElement>('button', {
    name: 'Delete my account',
  });
  expect(button.disabled).toBe(true);
  await confirm();
  expect(screen.getByRole('dialog').textContent).toContain('Once the request is sent');
  expect(api.stepUpChallenge).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.getByRole<HTMLInputElement>('checkbox').checked).toBe(false);
  expect(button.disabled).toBe(true);
  expect(api.deleteAccount).not.toHaveBeenCalled();
  expect(screen.getByText('private@example.test')).toBeTruthy();
});

it('confirms exactly once outside private children, clears authority and never logs out or clears shared key storage', async () => {
  const remove = jest.spyOn(Storage.prototype, 'removeItem');
  const clear = jest.spyOn(Storage.prototype, 'clear');
  renderPrivacy();
  await send();
  const heading = await screen.findByRole('heading', { name: 'Account deletion requested' });
  expect(document.activeElement).toBe(heading);
  expect(screen.queryByTestId('portal-ready')).toBeNull();
  expect(screen.queryByText('private@example.test')).toBeNull();
  expect(screen.getByTestId('deletion-outcome').textContent).toContain('notification is queued');
  expect(screen.getByTestId('deletion-outcome').textContent).toContain(
    'does not confirm inbox delivery'
  );
  expect(api.profile).toBeUndefined();
  expect(api.dispose).toHaveBeenCalled();
  expect(api.logout).not.toHaveBeenCalled();
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  expect(replace).not.toHaveBeenCalled();
  expect(remove).not.toHaveBeenCalled();
  expect(clear).not.toHaveBeenCalled();
  act(() => invalidate());
  act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
  fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
  expect(screen.getByRole('heading', { name: 'Account deletion requested' })).toBeTruthy();
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
});

it.each([
  new PortalError('network_error', 0, true),
  new PortalError('temporarily_unavailable', 503, true),
  new PortalError('invalid_response', 200, true),
])(
  'retains an unconfirmed terminal outcome after %s without replay or inferring success from 401',
  async (failure) => {
    api.deleteAccount.mockImplementationOnce(async (_grant, _signal, sent) => {
      sent();
      throw failure;
    });
    renderPrivacy();
    await send();
    await screen.findByRole('heading', { name: 'Deletion outcome unconfirmed' });
    expect(screen.queryByText('private@example.test')).toBeNull();
    expect(screen.getByTestId('deletion-outcome').textContent).toContain('has not been retried');
    expect(screen.getByTestId('deletion-outcome').textContent).not.toContain(
      'notification is queued'
    );
    act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
    act(() => invalidate());
    expect(screen.getByTestId('deletion-outcome').getAttribute('data-outcome')).toBe('unconfirmed');
    expect(api.deleteAccount).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  }
);

it.each([
  'cancel',
  'hide',
  'pagehide',
  'navigation',
  'peer',
  'session loss',
  'route unmount',
] as const)(
  'treats post-send %s immediately as uncertain, ignores late success and never restarts the action',
  async (reason) => {
    const pending = deferred();
    api.deleteAccount.mockImplementationOnce((_grant, _signal, sent) => {
      sent();
      return pending.promise;
    });
    const view = renderPrivacy();
    await send();
    const signal = api.deleteAccount.mock.calls[0][1];
    if (reason === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    else if (reason === 'hide') {
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
      fireEvent(document, new Event('visibilitychange'));
    } else if (reason === 'pagehide') fireEvent(window, new Event('pagehide'));
    else if (reason === 'navigation') act(() => clearSensitiveViews());
    else if (reason === 'peer') act(() => invalidate());
    else if (reason === 'session loss')
      act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
    else
      view.rerender(
        <PortalProvider>
          <p>Other page</p>
        </PortalProvider>
      );
    expect(signal.aborted).toBe(true);
    expect(screen.getByTestId('deletion-outcome').getAttribute('data-outcome')).toBe('unconfirmed');
    expect(screen.queryByText('private@example.test')).toBeNull();
    await act(async () => pending.resolve());
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    fireEvent(document, new Event('visibilitychange'));
    fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
    act(() => invalidate());
    expect(screen.getByRole('heading', { name: 'Deletion outcome unconfirmed' })).toBeTruthy();
    expect(api.deleteAccount).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    expect(api.bootstrap).toHaveBeenCalledTimes(1);
    expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  }
);

it('invalidates peers on post-send provider unmount without a redundant logout or a late success upgrade', async () => {
  const pending = deferred();
  api.deleteAccount.mockImplementationOnce((_grant, _signal, sent) => {
    sent();
    return pending.promise;
  });
  const view = renderPrivacy();
  await send();
  view.unmount();
  expect(api.deleteAccount.mock.calls[0][1].aborted).toBe(true);
  expect(api.profile).toBeUndefined();
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve());
  expect(invalidateOtherTabs).toHaveBeenCalledTimes(1);
  expect(api.logout).not.toHaveBeenCalled();
});

it('does not report uncertain deletion on cancellation before transmission and never uses a late grant', async () => {
  let resolve!: (value: StepUpGrant) => void;
  api.stepUpVerify.mockReturnValueOnce(
    new Promise((finish) => {
      resolve = finish;
    })
  );
  renderPrivacy();
  await confirm();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
  await waitFor(() => expect(api.stepUpVerify).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  const grant = new StepUpGrant(
    { token: 'late-grant', token_type: 'StepUp', expires_in: 60 },
    'private-session',
    Date.now(),
    Date.now() + 60000
  );
  await act(async () => resolve(grant));
  expect(() => grant.take('private-session')).toThrow('grant_expired');
  expect(api.deleteAccount).not.toHaveBeenCalled();
  expect(screen.queryByTestId('deletion-outcome')).toBeNull();
  expect(screen.getByText('private@example.test')).toBeTruthy();
});

it('keeps cancellation during request preparation nonterminal when onSend has not fired', async () => {
  const pending = deferred();
  api.deleteAccount.mockReturnValueOnce(pending.promise);
  renderPrivacy();
  await send();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(api.deleteAccount.mock.calls[0][1].aborted).toBe(true);
  expect(screen.queryByTestId('deletion-outcome')).toBeNull();
  await act(async () => pending.resolve());
  expect(screen.queryByTestId('deletion-outcome')).toBeNull();
  expect(screen.getByText('private@example.test')).toBeTruthy();
  expect(invalidateOtherTabs).not.toHaveBeenCalled();
});

it('leaves a definitive authorization denial in the UV-only dialog without claiming deletion', async () => {
  api.deleteAccount.mockImplementationOnce(async (_grant, _signal, sent) => {
    sent();
    throw new PortalError('insufficient_user_authentication', 403);
  });
  renderPrivacy();
  await send();
  expect((await screen.findByRole('alert')).textContent).toContain(
    'Fresh verification is required'
  );
  expect(screen.queryByTestId('deletion-outcome')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Use authenticator code' })).toBeNull();
  expect(screen.getByText('private@example.test')).toBeTruthy();
  expect(invalidateOtherTabs).not.toHaveBeenCalled();
});
