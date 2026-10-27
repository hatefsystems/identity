import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PortalProvider, usePortal } from '../app/dashboard/_components/portal-provider';
import { PasskeysPanel } from '../app/dashboard/_components/passkeys-panel';
import { RecoveryPanel } from '../app/dashboard/_components/recovery-panel';
import { PortalClient } from '../app/_lib/portal/client';
import { StepUpGrant, type Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { clearSensitiveViews, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

jest.mock('next/navigation', () => ({
  usePathname: () => '/dashboard/security',
  useRouter: () => ({ replace: jest.fn() }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({
  ...jest.requireActual('../app/_lib/portal/invalidation'),
  onOtherTabInvalidation: jest.fn(),
}));

const profile = (): Profile => ({
  id: 'user-id',
  email: 'private@example.test',
  display_name: 'Private profile',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '1',
  session: { id: 'session-id', expires_at: new Date(Date.now() + 3600000).toISOString() },
});
const key = {
  id: 'first-key',
  name: 'My key',
  created_at: '2026-01-01T00:00:00Z',
  user_verified: true,
  backup_eligible: true,
  backup_state: true,
};
const codes = ['ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567-89', '12345-6789A-BCDEF-GHJKM-NPQRS-TVWXY-Z0'];
let nextBootstrap: () => Promise<Profile>;
let invalidated: () => void;
let clients: ReturnType<typeof makeClient>[];
let visibility: PropertyDescriptor | undefined;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((finish) => {
    resolve = finish;
  });
  return { promise, resolve };
}

function makeClient() {
  const bootstrap = nextBootstrap;
  const api = {
    profile: undefined as Profile | undefined,
    bootstrap: jest.fn(),
    dispose: jest.fn(),
    assertSession: jest.fn(),
    keys: jest.fn().mockResolvedValue([key, { ...key, id: 'second-key', name: 'Backup' }]),
    recoveryStatus: jest.fn().mockResolvedValue({ remaining: 2, low: true }),
    stepUpChallenge: jest.fn().mockResolvedValue({
      methods: ['webauthn', 'totp'],
      webauthn: { publicKey: { challenge: 'AA' } },
    }),
    stepUpVerify: jest.fn(),
    renameKey: jest.fn(),
    registerOptions: jest.fn(),
    registerVerify: jest.fn(),
    removeKey: jest.fn(),
    generateRecovery: jest.fn().mockResolvedValue({ codes, count: codes.length }),
  };
  api.bootstrap.mockImplementation(async () => {
    const value = await bootstrap();
    api.profile = value;
    return value;
  });
  api.dispose.mockImplementation(() => {
    api.profile = undefined;
  });
  api.assertSession.mockImplementation(() => {
    if (!api.profile) throw new PortalError('session_required', 401);
    return api.profile;
  });
  api.stepUpVerify.mockImplementation(
    async () =>
      new StepUpGrant(
        { token: 'transient-grant', token_type: 'StepUp', expires_in: 60 },
        'session-id',
        Date.now(),
        Date.now() + 60000
      )
  );
  api.renameKey.mockImplementation(
    async (
      _id: string,
      name: string,
      _grant: StepUpGrant,
      _signal: AbortSignal,
      onSend: () => void
    ) => {
      onSend();
      return { ...key, name };
    }
  );
  return api;
}

function Content() {
  return (
    <>
      <p>{usePortal().profile.email}</p>
      <PasskeysPanel />
      <RecoveryPanel />
    </>
  );
}

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
  clients = [];
  nextBootstrap = async () => profile();
  jest.mocked(PortalClient).mockImplementation(() => {
    const api = makeClient();
    clients.push(api);
    return api as unknown as PortalClient;
  });
  jest.mocked(onOtherTabInvalidation).mockImplementation((listener) => {
    invalidated = listener;
    return jest.fn();
  });
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ response: 'adapted-credential' } as unknown as Awaited<
      ReturnType<typeof usePasskey>
    >);
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => {
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
});

function hide() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
}
function show() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
}
async function prepareTotp(kind: 'rename' | 'recovery' = 'rename') {
  await screen.findByRole('heading', { name: 'My key' });
  if (kind === 'rename') {
    fireEvent.click(screen.getByRole('button', { name: 'Rename My key' }));
    fireEvent.change(screen.getByLabelText('Passkey name'), {
      target: { value: 'Intended label' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Rename passkey' }));
  } else fireEvent.click(screen.getByRole('button', { name: 'Generate new recovery codes' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
  const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(code, { target: { value: '012345' } });
  return code;
}

it('retains only a pinned waiting TOTP intent, clears entered code/private views, and restores after fresh same-session bootstrap and explicit challenge', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  const oldInput = await prepareTotp();
  const oldClient = clients[0];
  hide();
  expect(oldInput.value).toBe('');
  expect(oldClient.dispose).toHaveBeenCalled();
  expect(oldClient.profile).toBeUndefined();
  expect(screen.queryByTestId('portal-ready')).toBeNull();
  expect(screen.queryByText('private@example.test')).toBeNull();
  expect(screen.queryByText('My key')).toBeNull();
  expect(clients).toHaveLength(1);
  const bootstrap = deferred<Profile>();
  nextBootstrap = () => bootstrap.promise;
  show();
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.queryByTestId('portal-ready')).toBeNull();
  await act(async () => bootstrap.resolve(profile()));
  const dialog = await screen.findByRole('dialog', { name: 'Rename passkey' });
  expect(dialog.textContent).toContain('Intended label');
  expect(dialog.textContent).toContain('no previous code or grant was retained');
  const fresh = clients[1];
  expect(fresh.stepUpChallenge).not.toHaveBeenCalled();
  expect(fresh.stepUpVerify).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  const code = await screen.findByLabelText<HTMLInputElement>('Authenticator code');
  expect(code.value).toBe('');
  expect(screen.queryByRole('button', { name: 'Use authenticator code' })).toBeNull();
  fireEvent.change(code, { target: { value: '654321' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  await waitFor(() => expect(fresh.renameKey).toHaveBeenCalledTimes(1));
  expect(fresh.stepUpVerify).toHaveBeenCalledWith(
    { method: 'totp', code: '654321' },
    expect.any(AbortSignal)
  );
  expect(fresh.renameKey).toHaveBeenCalledWith(
    'first-key',
    'Intended label',
    expect.any(StepUpGrant),
    expect.any(AbortSignal),
    expect.any(Function)
  );
  expect(oldClient.stepUpVerify).not.toHaveBeenCalled();
  expect(oldClient.renameKey).not.toHaveBeenCalled();
});

it('restores a waiting recovery action through fresh TOTP without retaining or automatically generating plaintext', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp('recovery');
  hide();
  show();
  await screen.findByRole('dialog', { name: 'Replace recovery codes' });
  expect(screen.queryByTestId('recovery-viewer')).toBeNull();
  expect(clients[1].generateRecovery).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  const input = await screen.findByLabelText<HTMLInputElement>('Authenticator code');
  expect(input.value).toBe('');
  fireEvent.change(input, { target: { value: '654321' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  await screen.findByTestId('recovery-viewer');
  expect(clients[1].generateRecovery).toHaveBeenCalledTimes(1);
  expect(clients[0].generateRecovery).not.toHaveBeenCalled();
  hide();
  show();
  await screen.findByTestId('portal-ready');
  expect(screen.queryByTestId('recovery-viewer')).toBeNull();
  expect(screen.queryByText(codes[0])).toBeNull();
  expect(screen.queryByRole('dialog')).toBeNull();
});

it('discards pending action parameters when the cookie resolves to a different session', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp();
  hide();
  nextBootstrap = async () => ({
    ...profile(),
    id: 'other-user',
    email: 'other@example.test',
    session: { ...profile().session, id: 'other-session' },
  });
  show();
  await screen.findByText('other@example.test');
  await screen.findByRole('heading', { name: 'My key' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.queryByText(/Intended label/)).toBeNull();
  expect(clients[1].stepUpChallenge).not.toHaveBeenCalled();
  expect(clients[1].renameKey).not.toHaveBeenCalled();
});

it('uses freshly advertised factors instead of restoring a TOTP factor that is no longer available', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp();
  hide();
  show();
  await screen.findByRole('dialog', { name: 'Rename passkey' });
  clients[1].stepUpChallenge.mockResolvedValueOnce({
    methods: ['webauthn'],
    webauthn: { publicKey: { challenge: 'AQ' } },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  await screen.findByRole('button', { name: 'Verify with a passkey' });
  expect(screen.queryByLabelText('Authenticator code')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Use authenticator code' })).toBeNull();
  expect(clients[1].stepUpVerify).not.toHaveBeenCalled();
});

it('discards pending action after failed revalidation even if a later explicit check succeeds for the old session', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp();
  hide();
  nextBootstrap = async () => {
    throw new PortalError('session_required', 401);
  };
  show();
  await screen.findByRole('alert');
  expect(screen.queryByRole('dialog')).toBeNull();
  nextBootstrap = async () => profile();
  fireEvent.click(screen.getByRole('button', { name: 'Check current session' }));
  await screen.findByRole('heading', { name: 'My key' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.queryByText(/Intended label/)).toBeNull();
});

it.each(['navigation', 'pagehide', 'peer invalidation'] as const)(
  'does not preserve a waiting TOTP intent across %s',
  async (reason) => {
    render(
      <PortalProvider>
        <Content />
      </PortalProvider>
    );
    await prepareTotp();
    hide();
    if (reason === 'navigation') act(() => clearSensitiveViews());
    else if (reason === 'pagehide') fireEvent(window, new Event('pagehide'));
    else act(() => invalidated());
    show();
    await screen.findByRole('heading', { name: 'My key' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText(/Intended label/)).toBeNull();
    expect(clients[1].stepUpChallenge).not.toHaveBeenCalled();
  }
);

it('discards a late grant from submitted TOTP rather than resuming or applying the mutation', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp();
  const pending = deferred<StepUpGrant>();
  clients[0].stepUpVerify.mockReturnValueOnce(pending.promise);
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  await waitFor(() => expect(clients[0].stepUpVerify).toHaveBeenCalledTimes(1));
  hide();
  show();
  await screen.findByRole('heading', { name: 'My key' });
  expect(screen.queryByRole('dialog')).toBeNull();
  const grant = new StepUpGrant(
    { token: 'late-grant', token_type: 'StepUp', expires_in: 60 },
    'session-id',
    Date.now(),
    Date.now() + 60000
  );
  await act(async () => pending.resolve(grant));
  expect(() => grant.take('session-id')).toThrow('grant_expired');
  expect(clients[0].renameKey).not.toHaveBeenCalled();
  expect(clients[1].renameKey).not.toHaveBeenCalled();
});

it('clears minted authority immediately on suspension during a mutation, never restoring that action', async () => {
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await prepareTotp();
  const pending = deferred<unknown>();
  clients[0].renameKey.mockImplementationOnce(
    (_id: string, _name: string, _grant: StepUpGrant, _signal: AbortSignal, sent: () => void) => {
      sent();
      return pending.promise;
    }
  );
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  await waitFor(() => expect(clients[0].renameKey).toHaveBeenCalledTimes(1));
  const grant = (await clients[0].stepUpVerify.mock.results[0].value) as StepUpGrant;
  hide();
  expect(() => grant.take('session-id')).toThrow('grant_expired');
  show();
  await screen.findByRole('heading', { name: 'My key' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.getByText(/If a change was interrupted/).textContent).toContain(
    'may have completed'
  );
  await act(async () => pending.resolve({ ...key, name: 'Intended label' }));
  expect(screen.queryByRole('heading', { name: 'Intended label' })).toBeNull();
  expect(clients[1].renameKey).not.toHaveBeenCalled();
});
