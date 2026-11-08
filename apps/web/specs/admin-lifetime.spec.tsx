import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TextEncoder } from 'node:util';
import { I18nTestProvider, render } from '../i18n/testing';
import { PortalProvider, usePortal } from '../app/_components/portal-provider';
import { UserDetailView } from '../app/admin/_components/user-detail-view';
import { UsersView } from '../app/admin/_components/users-view';
import { AdminOverview } from '../app/admin/_components/admin-overview';
import { AdminClient } from '../app/_lib/admin/client';
import type {
  AdminCapabilities,
  AdminModerationStatus,
  AdminUser,
  AdminUsersPage,
  AdminUsersQuery,
} from '../app/_lib/admin/contracts';
import { PortalClient } from '../app/_lib/portal/client';
import { StepUpGrant, type Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { clearSensitiveViews, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

const mockTargetID = '00000000-0000-0000-0000-000000000002';
let mockCurrentTargetID = mockTargetID;
let mockPathname = `/admin/users/${mockTargetID}`;
jest.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useParams: () => ({ id: mockCurrentTargetID }),
  useRouter: () => ({ replace: jest.fn() }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/admin/client', () => ({ AdminClient: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({
  ...jest.requireActual('../app/_lib/portal/invalidation'),
  onOtherTabInvalidation: jest.fn(),
}));

const profile = (): Profile => ({
  id: '00000000-0000-0000-0000-000000000001',
  email: 'operator@example.test',
  display_name: 'Operator',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '1',
  session: { id: 'session-id', expires_at: new Date(Date.now() + 3600000).toISOString() },
});
const permissions = (): AdminCapabilities => ({
  capabilities: {
    users_read: true,
    users_pii: true,
    users_lookup: true,
    users_status_write: true,
    audit_logs_read: false,
    audit_chain_verify: false,
    ledger_verify: false,
    legal_holds_read: false,
    legal_holds_apply: false,
    legal_holds_release: false,
    preservation_requests_create: false,
    legal_inquiry_lookup: false,
  },
  limits: {
    page_size_default: 20,
    page_size_max: 100,
    audit_max_window_seconds: 86400,
    chain_verify_max_limit: 1000,
  },
});
let serverUser: AdminUser;
let clients: ReturnType<typeof makeClient>[];
let nextBootstrap: () => Promise<Profile>;
let nextCapabilities: () => Promise<AdminCapabilities>;
let grantSeconds: number;
let grants: StepUpGrant[];
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
    assertSession: jest.fn(),
    dispose: jest.fn(),
    logout: jest.fn(),
    onSessionLoss: undefined as ((failure: PortalError) => void) | undefined,
    stepUpChallenge: jest.fn().mockResolvedValue({
      methods: ['webauthn', 'totp'],
      webauthn: { publicKey: { challenge: 'AA' } },
    }),
    stepUpVerify: jest.fn(),
    admin: {
      capabilities: jest.fn(nextCapabilities),
      user: jest.fn(async (_id: string, _signal: AbortSignal) => ({ ...serverUser })),
      users: jest.fn(async (_query: AdminUsersQuery, _signal: AbortSignal) => ({
        items: [{ ...serverUser }],
        total: 1,
        limit: 20,
        offset: 0,
      })),
      updateStatus: jest.fn(
        async (
          _id: string,
          body: { status: AdminModerationStatus; reason: string; expected_revision: string },
          grant: StepUpGrant,
          _signal: AbortSignal,
          sent: () => void
        ) => {
          grant.take(api.assertSession().session.id);
          sent();
          serverUser = {
            ...serverUser,
            status: body.status,
            lifecycle_revision: String(BigInt(serverUser.lifecycle_revision) + 1n),
          };
        }
      ),
    },
  };
  api.bootstrap.mockImplementation(async () => {
    const current = await bootstrap();
    api.profile = current;
    return current;
  });
  api.assertSession.mockImplementation(() => {
    if (!api.profile) throw new PortalError('session_required', 401);
    return api.profile;
  });
  api.dispose.mockImplementation(() => {
    api.profile = undefined;
  });
  api.stepUpVerify.mockImplementation(async () => {
    const current = api.assertSession();
    const grant = new StepUpGrant(
      { token: 'transient-authority', token_type: 'StepUp', expires_in: grantSeconds },
      current.session.id,
      Date.now(),
      Date.parse(current.session.expires_at)
    );
    grants.push(grant);
    return grant;
  });
  return api;
}

beforeAll(() => {
  Object.defineProperty(globalThis, 'TextEncoder', { configurable: true, value: TextEncoder });
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
  mockCurrentTargetID = mockTargetID;
  mockPathname = `/admin/users/${mockTargetID}`;
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  clients = [];
  grants = [];
  grantSeconds = 60;
  nextBootstrap = async () => profile();
  nextCapabilities = async () => permissions();
  serverUser = {
    id: mockTargetID,
    email: 'target@example.test',
    status: 'active',
    is_mfa_enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    deleted_at: null,
    lifecycle_revision: '9007199254740993',
  };
  jest.mocked(PortalClient).mockImplementation(() => {
    const api = makeClient();
    clients.push(api);
    return api as unknown as PortalClient;
  });
  jest
    .mocked(AdminClient)
    .mockImplementation(
      (client) =>
        (client as unknown as ReturnType<typeof makeClient>).admin as unknown as AdminClient
    );
  jest.mocked(onOtherTabInvalidation).mockReturnValue(jest.fn());
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ id: 'assertion' } as Awaited<ReturnType<typeof usePasskey>>);
});
afterEach(() => {
  window.history.replaceState(null, '', '/');
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  jest.useRealTimers();
});

function renderDetail() {
  return render(
    <PortalProvider surface="admin">
      <UserDetailView />
    </PortalProvider>
  );
}
function hide() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
}
function show() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
}
async function startAction(name = 'Suspend') {
  fireEvent.click(await screen.findByRole('button', { name }));
  await screen.findByRole('dialog', { name: `${name} account` });
  expect(screen.queryByLabelText('Moderation reason')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  await screen.findByRole('button', { name: 'Verify with a passkey' });
}
async function finalForm(name = 'Suspend') {
  await startAction(name);
  fireEvent.click(screen.getByRole('button', { name: 'Verify with a passkey' }));
  return screen.findByLabelText<HTMLTextAreaElement>('Moderation reason');
}
function submit(reason = '  Verified abuse report  ') {
  fireEvent.change(screen.getByLabelText('Moderation reason'), { target: { value: reason } });
  fireEvent.click(screen.getByRole('checkbox', { name: /I reviewed the account/ }));
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm account status change' }));
}

it('server-renders a non-sensitive admin shell without private values, forms or clients', () => {
  const html = renderToStaticMarkup(
    <I18nTestProvider>
      <PortalProvider surface="admin">
        <UserDetailView />
      </PortalProvider>
    </I18nTestProvider>
  );
  expect(html).toContain('Checking your secure browser session and administrative access');
  expect(html).not.toContain(serverUser.id);
  expect(html).not.toContain(serverUser.email);
  expect(html).not.toContain('Moderation reason');
  expect(PortalClient).not.toHaveBeenCalled();
});

it('waits for capabilities after normal-session bootstrap before disclosing children', async () => {
  const pending = deferred<AdminCapabilities>();
  nextCapabilities = () => pending.promise;
  renderDetail();
  await waitFor(() => expect(clients[0].admin.capabilities).toHaveBeenCalledTimes(1));
  expect(clients[0].admin.user).not.toHaveBeenCalled();
  expect(screen.queryByTestId('admin-ready')).toBeNull();
  await act(async () => pending.resolve(permissions()));
  await screen.findByText(serverUser.email as string);
});

it('offers a neutral account-shell Admin entry without any capabilities request', async () => {
  function Content() {
    return <p>{usePortal().profile.email}</p>;
  }
  mockPathname = '/dashboard';
  render(
    <PortalProvider>
      <Content />
    </PortalProvider>
  );
  await screen.findByText('operator@example.test');
  expect(screen.getByRole('link', { name: 'Admin' }).getAttribute('href')).toBe('/admin');
  expect(AdminClient).not.toHaveBeenCalled();
});

it.each([
  [403, 'forbidden', /no access/],
  [404, 'not_found', /not available on this deployment/],
  [503, 'audit_unavailable', /unavailable/],
] as const)(
  'distinguishes denied/disabled/unavailable bootstrap (%s) without logout or private reads',
  async (status, code, message) => {
    nextCapabilities = async () => {
      throw new PortalError(code, status);
    };
    renderDetail();
    expect((await screen.findByRole('alert')).textContent).toMatch(message);
    expect(clients[0].admin.user).not.toHaveBeenCalled();
    expect(clients[0].logout).not.toHaveBeenCalled();
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    const href = screen.getByRole('link', { name: 'Sign in with a passkey' }).getAttribute('href');
    expect(href).toBe('/login?returnTo=%2Fadmin%2Fusers');
    expect(href).not.toContain(mockTargetID);
  }
);

it('verification-only capabilities show integrity without fetching accounts or payloads', async () => {
  nextCapabilities = async () => ({
    ...permissions(),
    capabilities: {
      users_read: false,
      users_pii: false,
      users_lookup: false,
      users_status_write: false,
      audit_logs_read: false,
      audit_chain_verify: true,
      ledger_verify: true,
      legal_holds_read: false,
      legal_holds_apply: false,
      legal_holds_release: false,
      preservation_requests_create: false,
      legal_inquiry_lookup: false,
    },
  });
  mockPathname = '/admin';
  render(
    <PortalProvider surface="admin">
      <AdminOverview />
    </PortalProvider>
  );
  await screen.findByTestId('admin-ready');
  expect(screen.queryByRole('link', { name: 'Accounts' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Audit logs' })).toBeNull();
  expect(clients[0].admin.user).not.toHaveBeenCalled();
});

it('support metadata has no email or moderation controls even if an unexpected DTO email is present', async () => {
  nextCapabilities = async () => ({
    ...permissions(),
    capabilities: {
      ...permissions().capabilities,
      users_pii: false,
      users_lookup: false,
      users_status_write: false,
    },
  });
  renderDetail();
  await screen.findByText(serverUser.lifecycle_revision);
  expect(screen.queryByText(serverUser.email as string)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Suspend' })).toBeNull();
});

it('rechecks the pinned revision after step-up, then confirms one reasoned single-use action and refreshes', async () => {
  renderDetail();
  const reason = await finalForm();
  expect(document.activeElement).toBe(reason);
  const api = clients[0];
  expect(api.admin.user).toHaveBeenCalledTimes(3);
  expect(api.admin.updateStatus).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Reactivate' })).toBeNull();
  submit();
  await screen.findByText('Status change confirmed. Current account state loaded.');
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
  expect(api.admin.updateStatus.mock.calls[0].slice(0, 2)).toEqual([
    mockTargetID,
    { status: 'suspended', reason: 'Verified abuse report', expected_revision: '9007199254740993' },
  ]);
  expect(screen.getByText('9007199254740994')).toBeTruthy();
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(reason.value).toBe('');
});

it('announces the current checking, final confirmation, and submitting stages reactively', async () => {
  renderDetail();
  await startAction();
  const checking = deferred<AdminUser>();
  const sending = deferred<void>();
  const api = clients[0];
  api.admin.user.mockReturnValueOnce(checking.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Verify with a passkey' }));
  const dialog = within(screen.getByRole('dialog'));
  await waitFor(() =>
    expect(dialog.getByRole('status').textContent).toContain('Checking the pinned account')
  );
  expect(screen.queryByLabelText('Moderation reason')).toBeNull();
  await act(async () => checking.resolve({ ...serverUser }));
  await screen.findByLabelText('Moderation reason');
  expect(dialog.getByRole('status').textContent).toContain(
    'Enter a reason and review the final confirmation'
  );
  api.admin.updateStatus.mockImplementationOnce((_id, _body, grant, _signal, sent) => {
    grant.take('session-id');
    sent();
    return sending.promise;
  });
  submit();
  expect(dialog.getByRole('status').textContent).toBe(
    'Sending status change. Do not submit again.'
  );
  await act(async () => sending.resolve());
  await screen.findByText('Status change confirmed. Current account state loaded.');
});

it('restores the action opener after the pre-verification read and cancellation', async () => {
  renderDetail();
  const opener = await screen.findByRole('button', { name: 'Suspend' });
  await finalForm();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(document.activeElement).toBe(opener);
  expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
});

it.each(['', 'é'.repeat(1001)])(
  'rejects empty and excessive UTF-8 byte reasons after verification',
  async (reason) => {
    renderDetail();
    await finalForm();
    submit(reason);
    expect((await screen.findByRole('alert')).textContent).toContain('2,000 UTF-8 bytes');
    expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
  }
);

it('blocks a profile/revision or ABA status change during step-up rather than replacing the pin', async () => {
  renderDetail();
  await startAction();
  serverUser = { ...serverUser, lifecycle_revision: '9007199254740995' };
  fireEvent.click(screen.getByRole('button', { name: 'Verify with a passkey' }));
  expect((await screen.findByRole('alert')).textContent).toContain('account changed');
  expect(screen.queryByLabelText('Moderation reason')).toBeNull();
  expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  fireEvent.click(screen.getByRole('button', { name: 'Read current state' }));
  await screen.findByText('9007199254740995');
  expect(clients[0].stepUpVerify).toHaveBeenCalledTimes(1);
});

it('clears reason and grant on real expiry while entering the final form', async () => {
  jest.useFakeTimers();
  grantSeconds = 1;
  renderDetail();
  const input = await finalForm();
  fireEvent.change(input, { target: { value: 'private long draft' } });
  act(() => jest.advanceTimersByTime(1001));
  expect(screen.getByRole('alert').textContent).toContain('Verification expired');
  expect(input.value).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
});

it('allows only waiting TOTP desired status to resume after session/capability/target revalidation', async () => {
  renderDetail();
  await startAction();
  fireEvent.click(screen.getByRole('button', { name: 'Use authenticator code' }));
  const oldCode = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(oldCode, { target: { value: '123456' } });
  hide();
  expect(oldCode.value).toBe('');
  expect(screen.queryByTestId('admin-ready')).toBeNull();
  expect(clients[0].profile).toBeUndefined();
  serverUser = { ...serverUser, lifecycle_revision: '9007199254740994' };
  show();
  await screen.findByRole('dialog', { name: 'Suspend account' });
  expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
  expect(clients[1].admin.user).toHaveBeenCalledTimes(1);
  expect(clients[1].stepUpChallenge).not.toHaveBeenCalled();
  expect(clients[0].stepUpVerify).not.toHaveBeenCalled();
  expect(grants).toHaveLength(0);
  expect(screen.queryByText('9007199254740993')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  const code = await screen.findByLabelText<HTMLInputElement>('Authenticator code');
  expect(code.value).toBe('');
  expect(screen.queryByLabelText('Moderation reason')).toBeNull();
  fireEvent.change(code, { target: { value: '654321' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  const reason = await screen.findByLabelText<HTMLTextAreaElement>('Moderation reason');
  expect(reason.value).toBe('');
  expect(clients[1].stepUpChallenge).toHaveBeenCalledTimes(1);
  expect(clients[1].stepUpVerify).toHaveBeenCalledTimes(1);
  expect(clients[1].stepUpVerify).toHaveBeenCalledWith(
    { method: 'totp', code: '654321' },
    expect.any(AbortSignal)
  );
  expect(clients[1].admin.user).toHaveBeenCalledTimes(2);
  expect(clients[1].admin.updateStatus).not.toHaveBeenCalled();
  expect(grants).toHaveLength(1);
  submit('Fresh review after TOTP resume');
  await screen.findByText('Status change confirmed. Current account state loaded.');
  expect(clients[1].admin.updateStatus).toHaveBeenCalledTimes(1);
  expect(clients[1].admin.updateStatus).toHaveBeenCalledWith(
    mockTargetID,
    {
      status: 'suspended',
      reason: 'Fresh review after TOTP resume',
      expected_revision: '9007199254740994',
    },
    grants[0],
    expect.any(AbortSignal),
    expect.any(Function)
  );
  expect(screen.getByText('9007199254740995')).toBeTruthy();
  expect(clients[0].stepUpVerify).not.toHaveBeenCalled();
  expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
  expect(usePasskey).not.toHaveBeenCalled();
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  expect(reason.value).toBe('');
});

it.each(['background', 'pagehide', 'navigation'] as const)(
  'clears final draft and grant on %s without resuming authority',
  async (kind) => {
    renderDetail();
    const input = await finalForm();
    fireEvent.change(input, { target: { value: 'private moderation narrative' } });
    if (kind === 'background') hide();
    else if (kind === 'pagehide') fireEvent(window, new Event('pagehide'));
    else act(() => clearSensitiveViews());
    expect(input.value).toBe('');
    expect(() => grants[0].take('session-id')).toThrow('grant_expired');
    expect(screen.queryByText('private moderation narrative')).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
    if (kind === 'navigation') await screen.findByTestId('admin-ready');
  }
);

it.each(['capabilities', 'session'] as const)(
  'drops a waiting action when %s alone changes on return',
  async (changed) => {
    renderDetail();
    await startAction();
    fireEvent.click(screen.getByRole('button', { name: 'Use authenticator code' }));
    hide();
    if (changed === 'capabilities')
      nextCapabilities = async () => ({
        ...permissions(),
        capabilities: { ...permissions().capabilities, users_status_write: false },
      });
    else
      nextBootstrap = async () => ({
        ...profile(),
        session: { ...profile().session, id: 'replacement-session' },
      });
    show();
    await screen.findByText(serverUser.email as string);
    expect(screen.queryByRole('dialog')).toBeNull();
    if (changed === 'capabilities')
      expect(screen.queryByRole('button', { name: 'Suspend' })).toBeNull();
    else expect(screen.getByRole('button', { name: 'Suspend' })).toBeTruthy();
    expect(clients[1].stepUpVerify).not.toHaveBeenCalled();
  }
);

it('discards a waiting TOTP marker when the target route changes while backgrounded', async () => {
  const view = renderDetail();
  await startAction();
  fireEvent.click(screen.getByRole('button', { name: 'Use authenticator code' }));
  const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(code, { target: { value: '123456' } });
  hide();
  mockCurrentTargetID = '00000000-0000-0000-0000-000000000003';
  mockPathname = `/admin/users/${mockCurrentTargetID}`;
  serverUser = { ...serverUser, id: mockCurrentTargetID, email: 'different@example.test' };
  view.rerender(
    <PortalProvider surface="admin">
      <UserDetailView />
    </PortalProvider>
  );
  show();
  await screen.findByText('different@example.test');
  expect(code.value).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.queryByText(mockTargetID)).toBeNull();
  expect(clients[1].admin.user).toHaveBeenCalledWith(mockCurrentTargetID, expect.any(AbortSignal));
  expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
  expect(clients[1].stepUpChallenge).not.toHaveBeenCalled();
  expect(clients.every((api) => api.stepUpVerify.mock.calls.length === 0)).toBe(true);
});

it.each(['same-path history', 'skip link', 'modifier click', 'sensitive clear'] as const)(
  'revalidates once after %s, withholding old query data and allowing a new explicit query',
  async (navigation) => {
    mockPathname = '/admin/users';
    window.history.replaceState(null, '', mockPathname);
    render(
      <PortalProvider surface="admin">
        <UsersView />
      </PortalProvider>
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Apply filters' }));
    await screen.findByText(serverUser.email as string);
    const session = deferred<Profile>();
    const capabilities = deferred<AdminCapabilities>();
    nextBootstrap = () => session.promise;
    nextCapabilities = () => capabilities.promise;
    if (navigation === 'same-path history') fireEvent(window, new PopStateEvent('popstate'));
    else if (navigation === 'sensitive clear') act(() => clearSensitiveViews());
    else {
      const link = screen.getByRole('link', {
        name: navigation === 'skip link' ? 'Skip to admin content' : `View account ${mockTargetID}`,
      });
      // JSDOM does not implement browser navigation. Dispatch the link event,
      // then the same-document popstate emitted by fragment/history navigation.
      const preventNavigation = (event: Event) => event.preventDefault();
      link.addEventListener('click', preventNavigation);
      fireEvent.click(link, { ctrlKey: navigation === 'modifier click' });
      link.removeEventListener('click', preventNavigation);
      if (navigation === 'skip link') {
        window.history.pushState(null, '', '#portal-content');
        fireEvent(window, new PopStateEvent('popstate'));
      }
    }
    expect(screen.queryByText(serverUser.email as string)).toBeNull();
    expect(screen.queryByRole('form', { name: 'Filter accounts' })).toBeNull();
    expect(clients[0].dispose).toHaveBeenCalled();
    await waitFor(() => expect(clients).toHaveLength(2));
    expect(clients[1].bootstrap).toHaveBeenCalledTimes(1);
    expect(clients[1].admin.capabilities).not.toHaveBeenCalled();
    await act(async () => session.resolve(profile()));
    expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    await act(async () => capabilities.resolve(permissions()));
    const apply = await screen.findByRole('button', { name: 'Apply filters' });
    expect(clients[1].admin.users).not.toHaveBeenCalled();
    expect(screen.queryByText(serverUser.email as string)).toBeNull();
    fireEvent.click(apply);
    await screen.findByText(serverUser.email as string);
    expect(clients[1].admin.users).toHaveBeenCalledTimes(1);
    expect(clients).toHaveLength(2);
    expect(clients.every((api) => api.logout.mock.calls.length === 0)).toBe(true);
  }
);

it('does not double-submit and keeps confirmed mutation separate from failed refresh', async () => {
  renderDetail();
  await finalForm();
  const api = clients[0];
  const pending = deferred<void>();
  api.admin.updateStatus.mockImplementationOnce((_id, _body, grant, _signal, sent) => {
    grant.take('session-id');
    sent();
    return pending.promise;
  });
  submit();
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm account status change' }));
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
  api.admin.user.mockRejectedValueOnce(new PortalError('service_unavailable', 503));
  await act(async () => pending.resolve());
  await screen.findByText('Status change confirmed, but refreshing the current account failed.');
  expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
});

it.each([
  'lost response',
  'cancel after send',
  'background after send',
  'expiry after send',
] as const)(
  'treats %s as uncertain, never replaying or implicitly reading current state',
  async (kind) => {
    if (kind === 'expiry after send') {
      jest.useFakeTimers();
      grantSeconds = 1;
    }
    renderDetail();
    await finalForm();
    const api = clients[0];
    const pending = deferred<void>();
    api.admin.updateStatus.mockImplementationOnce(async (_id, body, grant, _signal, sent) => {
      grant.take('session-id');
      sent();
      serverUser = { ...serverUser, status: body.status, lifecycle_revision: '9007199254740994' };
      if (kind === 'lost response') throw new PortalError('network_error', 0, true);
      return pending.promise;
    });
    submit();
    await waitFor(() => expect(api.admin.updateStatus).toHaveBeenCalledTimes(1));
    if (kind === 'cancel after send')
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    if (kind === 'background after send') hide();
    if (kind === 'expiry after send') act(() => jest.advanceTimersByTime(1001));
    await screen.findByText(/Outcome unconfirmed; the action was not retried/);
    const calls = api.admin.user.mock.calls.length;
    await act(async () => pending.resolve());
    if (kind === 'background after send') {
      show();
      await screen.findByTestId('admin-ready');
      expect(clients[1].admin.user).not.toHaveBeenCalled();
      expect(clients[1].admin.updateStatus).not.toHaveBeenCalled();
    }
    expect(api.admin.user).toHaveBeenCalledTimes(calls);
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Read current state' }));
    await screen.findByText('9007199254740994');
    expect(screen.getByText(/matching status proves only current state/)).toBeTruthy();
    expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
  }
);

it.each(['cancel', 'expiry'] as const)(
  'does not claim an uncertain outcome when %s precedes transmission',
  async (kind) => {
    if (kind === 'expiry') {
      jest.useFakeTimers();
      grantSeconds = 1;
    }
    renderDetail();
    const input = await finalForm();
    const preparing = deferred<void>();
    const transmitted = jest.fn();
    const api = clients[0];
    api.admin.updateStatus.mockImplementationOnce(async (_id, _body, grant, signal, sent) => {
      grant.take('session-id');
      await preparing.promise;
      if (signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      sent();
      transmitted();
    });
    submit('draft cleared before send');
    if (kind === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    else act(() => jest.advanceTimersByTime(1001));
    expect(input.value).toBe('');
    expect(screen.queryByRole('dialog')).toBeNull();
    if (kind === 'expiry')
      expect(screen.getByRole('alert').textContent).toContain('Verification expired');
    expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
    await act(async () => preparing.resolve());
    expect(transmitted).not.toHaveBeenCalled();
    expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
    expect(api.admin.user).toHaveBeenCalledTimes(3);
    expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  }
);

it('handles server conflicts after final confirmation with a fresh review and no replay', async () => {
  renderDetail();
  await finalForm();
  clients[0].admin.updateStatus.mockImplementationOnce(async (_id, _body, grant, _signal, sent) => {
    grant.take('session-id');
    sent();
    throw new PortalError('account_conflict', 409);
  });
  submit();
  expect((await screen.findByRole('alert')).textContent).toContain('account changed');
  expect(screen.queryByLabelText('Moderation reason')).toBeNull();
  expect(screen.queryByText(serverUser.email as string)).toBeNull();
  expect(clients[0].admin.updateStatus).toHaveBeenCalledTimes(1);
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
});

it.each(['forbidden', 'invalid_response', 'request_failed', 'network_error', 'account_conflict'])(
  'a protected-target 403 with %s stays generic, rechecks own capability, and does not sign out the normal session',
  async (code) => {
    renderDetail();
    await finalForm();
    clients[0].admin.updateStatus.mockImplementationOnce(
      async (_id, _body, grant, _signal, sent) => {
        grant.take('session-id');
        sent();
        throw new PortalError(code, 403, code === 'network_error');
      }
    );
    submit();
    expect((await screen.findByRole('alert')).textContent).toBe(
      'The status change was not permitted. No change was confirmed.'
    );
    expect(clients[0].admin.capabilities).toHaveBeenCalledTimes(2);
    expect(clients[0].logout).not.toHaveBeenCalled();
    expect(screen.getByTestId('admin-ready')).toBeTruthy();
  }
);

it.each([
  new PortalError('invalid_response', 200),
  new PortalError('audit_unavailable', 503),
  new PortalError('network_error'),
  new PortalError('forbidden', 403),
])('clears access when the post-403 capability reread fails with %s', async (failure) => {
  renderDetail();
  const input = await finalForm();
  const api = clients[0];
  api.admin.capabilities.mockRejectedValueOnce(failure);
  api.admin.updateStatus.mockImplementationOnce(async (_id, _body, grant, _signal, sent) => {
    grant.take('session-id');
    sent();
    throw new PortalError('invalid_response', 403);
  });
  submit('private denied draft');
  expect((await screen.findByRole('alert')).textContent).toContain(
    'Private data and pending actions were cleared'
  );
  expect(screen.queryByTestId('admin-ready')).toBeNull();
  expect(screen.queryByText(serverUser.email as string)).toBeNull();
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
  expect(input.value).toBe('');
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  expect(api.admin.capabilities).toHaveBeenCalledTimes(2);
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
  expect(api.dispose).toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Check access again' }));
  await screen.findByText(serverUser.email as string);
  expect(clients).toHaveLength(2);
  expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
  expect(clients[1].admin.updateStatus).not.toHaveBeenCalled();
  expect(clients.every((client) => client.logout.mock.calls.length === 0)).toBe(true);
});

it.each(['cancel', 'expiry', 'background', 'session loss'] as const)(
  'clears and revalidates on %s during the post-403 reread without claiming an uncertain PATCH',
  async (kind) => {
    if (kind === 'expiry') {
      jest.useFakeTimers();
      grantSeconds = 1;
    }
    renderDetail();
    const input = await finalForm();
    const api = clients[0];
    const reread = deferred<AdminCapabilities>();
    api.admin.capabilities.mockReturnValueOnce(reread.promise);
    api.admin.updateStatus.mockImplementationOnce(async (_id, _body, grant, _signal, sent) => {
      grant.take('session-id');
      sent();
      throw new PortalError('invalid_response', 403);
    });
    submit('private denied draft');
    await waitFor(() => expect(api.admin.capabilities).toHaveBeenCalledTimes(2));
    const signal = api.admin.updateStatus.mock.calls[0][3];
    expect(api.admin.capabilities).toHaveBeenLastCalledWith(signal);
    expect(screen.getByRole('dialog')).toBeTruthy();
    if (kind === 'cancel') fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    else if (kind === 'expiry') act(() => jest.advanceTimersByTime(1001));
    else if (kind === 'background') hide();
    else act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
    expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    expect(screen.queryByText(serverUser.email as string)).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(input.value).toBe('');
    expect(() => grants[0].take('session-id')).toThrow('grant_expired');
    await waitFor(() => expect(signal.aborted).toBe(true));
    expect(api.profile).toBeUndefined();
    // A transport that ignores abort must not restore the old permissions.
    await act(async () => reread.resolve(permissions()));
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
    expect(clients).toHaveLength(1);
    expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
    expect(api.logout).not.toHaveBeenCalled();
    if (kind === 'session loss') {
      expect(screen.getByRole('alert').textContent).toContain(
        'Your session is no longer available'
      );
      return;
    }
    const session = deferred<Profile>();
    const capabilities = deferred<AdminCapabilities>();
    nextBootstrap = () => session.promise;
    nextCapabilities = () => capabilities.promise;
    if (kind === 'background') show();
    else {
      expect(screen.getByRole('alert').textContent).toContain(
        'Private data and pending actions were cleared'
      );
      fireEvent.click(screen.getByRole('button', { name: 'Check access again' }));
    }
    await waitFor(() => expect(clients).toHaveLength(2));
    expect(clients[1].bootstrap).toHaveBeenCalledTimes(1);
    expect(clients[1].admin.capabilities).not.toHaveBeenCalled();
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    await act(async () => session.resolve(profile()));
    expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    const current = permissions();
    current.capabilities.users_pii = false;
    current.capabilities.users_lookup = false;
    await act(async () => capabilities.resolve(current));
    await screen.findByText(serverUser.lifecycle_revision);
    expect(screen.queryByText(serverUser.email as string)).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
    expect(clients[1].admin.user).toHaveBeenCalledTimes(1);
    expect(clients[1].admin.updateStatus).not.toHaveBeenCalled();
    expect(clients.every((client) => client.logout.mock.calls.length === 0)).toBe(true);
  }
);

it.each(['PII', 'lookup', 'status write'] as const)(
  'clears all private views and grants when a 403 recheck detects independent %s loss',
  async (lost) => {
    render(
      <PortalProvider surface="admin">
        <UsersView />
        <UserDetailView />
      </PortalProvider>
    );
    const lookup = await screen.findByLabelText('Exact email');
    fireEvent.change(lookup, { target: { value: 'private-lookup@example.test' } });
    const input = await finalForm();
    const api = clients[0];
    const current = permissions();
    if (lost === 'PII') {
      current.capabilities.users_pii = false;
      current.capabilities.users_lookup = false;
    } else if (lost === 'lookup') current.capabilities.users_lookup = false;
    else current.capabilities.users_status_write = false;
    api.admin.capabilities.mockResolvedValueOnce(current);
    api.admin.updateStatus.mockImplementationOnce(async (_id, _body, grant, _signal, sent) => {
      grant.take('session-id');
      sent();
      throw new PortalError('invalid_response', 403);
    });
    submit('private reason');
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Private data and pending actions were cleared'
    );
    expect(screen.queryByTestId('admin-ready')).toBeNull();
    expect(screen.queryByText(serverUser.email as string)).toBeNull();
    expect(screen.queryByLabelText('Exact email')).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText(/Outcome unconfirmed/)).toBeNull();
    expect(input.value).toBe('');
    expect(() => grants[0].take('session-id')).toThrow('grant_expired');
    expect(api.admin.capabilities).toHaveBeenCalledTimes(2);
    expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
    nextCapabilities = async () => current;
    fireEvent.click(screen.getByRole('button', { name: 'Check access again' }));
    await screen.findByTestId('admin-ready');
    await screen.findByText(serverUser.lifecycle_revision);
    if (lost === 'PII') expect(screen.queryByText(serverUser.email as string)).toBeNull();
    if (lost !== 'status write') expect(screen.queryByLabelText('Exact email')).toBeNull();
    else expect(screen.queryByRole('button', { name: 'Suspend' })).toBeNull();
    expect(clients).toHaveLength(2);
    expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
    expect(clients.every((client) => client.logout.mock.calls.length === 0)).toBe(true);
  }
);

it.each([
  ['en', 'Available workspaces', 'Accounts', 'Audit logs', 'Integrity', 'DPO and Legal'],
  [
    'fa-IR',
    'بخش‌های در دسترس',
    'حساب‌ها',
    'سوابق ممیزی',
    'تمامیت داده‌ها',
    'حفاظت از داده‌ها و امور حقوقی',
  ],
] as const)(
  'localizes the overview in %s while retaining only the capability-approved workspace links',
  async (locale, workspaces, accounts, audit, integrity, legal) => {
    mockPathname = '/admin';
    nextCapabilities = async () => ({
      ...permissions(),
      capabilities: {
        ...permissions().capabilities,
        audit_logs_read: true,
        ledger_verify: true,
        legal_holds_read: true,
      },
    });
    render(
      <I18nTestProvider locale={locale}>
        <PortalProvider surface="admin">
          <AdminOverview />
        </PortalProvider>
      </I18nTestProvider>
    );
    const region = within(await screen.findByRole('region', { name: workspaces }));
    for (const [name, href] of [
      [accounts, '/admin/users'],
      [audit, '/admin/audit-logs'],
      [integrity, '/admin/integrity'],
      [legal, '/admin/legal'],
    ]) {
      expect(region.getByRole('link', { name }).getAttribute('href')).toBe(href);
    }
    expect(clients[0].admin.user).not.toHaveBeenCalled();
    expect(clients[0].admin.users).not.toHaveBeenCalled();
  }
);

it.each([
  ['en', 'Account directory', 'Apply filters', 'Account status', 'Exact email', 'Active'],
  ['fa-IR', 'فهرست حساب‌ها', 'اعمال فیلترها', 'وضعیت حساب', 'ایمیل دقیق', 'فعال'],
] as const)(
  'localizes the account directory in %s without changing references, email or exact UTC time',
  async (locale, heading, apply, status, email, active) => {
    mockPathname = '/admin/users';
    serverUser.created_at = '2026-01-01T00:00:00.123456789Z';
    render(
      <I18nTestProvider locale={locale}>
        <PortalProvider surface="admin">
          <UsersView />
        </PortalProvider>
      </I18nTestProvider>
    );
    await screen.findByRole('heading', { name: heading });
    expect(screen.getByLabelText(status)).toBeTruthy();
    expect(screen.getByLabelText(email).getAttribute('dir')).toBe('ltr');
    expect(clients[0].admin.users).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: apply }));
    const row = within(await screen.findByTestId('admin-account-row'));
    expect(row.getByText(active)).toBeTruthy();
    expect(row.getByText(mockTargetID).getAttribute('dir')).toBe('ltr');
    expect(row.getByText(serverUser.email as string).getAttribute('dir')).toBe('ltr');
    const timestamp = row.getByText('2026-01-01 00:00:00.123456789 UTC');
    expect(timestamp.closest('time')?.getAttribute('dateTime')).toBe(serverUser.created_at);
    expect(clients[0].admin.users).toHaveBeenCalledTimes(1);
    expect(clients[0].admin.users).toHaveBeenCalledWith(
      { limit: 20, offset: 0 },
      expect.any(AbortSignal)
    );
  }
);

it('translates account validation and a pending query without refetching or resetting inputs', async () => {
  mockPathname = '/admin/users';
  const content = (locale: 'en' | 'fa-IR') => (
    <I18nTestProvider locale={locale}>
      <PortalProvider surface="admin">
        <UsersView />
      </PortalProvider>
    </I18nTestProvider>
  );
  const view = render(content('en'));
  const size = await screen.findByLabelText<HTMLInputElement>('Page size');
  fireEvent.change(size, { target: { value: '101' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  expect(screen.getByRole('alert').textContent).toBe('Enter a whole page size from 1 to 100.');
  view.rerender(content('fa-IR'));
  expect(screen.getByRole('alert').textContent).toContain('تعداد حساب‌های هر صفحه');
  expect(screen.getByLabelText('تعداد در هر صفحه')).toBe(size);
  expect(size.value).toBe('101');
  expect(clients[0].admin.users).not.toHaveBeenCalled();
  fireEvent.change(size, { target: { value: '20' } });
  const pending = deferred<AdminUsersPage>();
  const api = clients[0];
  api.admin.users.mockReturnValueOnce(pending.promise);
  fireEvent.click(screen.getByRole('button', { name: 'اعمال فیلترها' }));
  expect(within(screen.getByRole('main')).getByRole('status').textContent).toBe(
    'در حال بارگیری حساب‌ها...'
  );
  const signal = api.admin.users.mock.calls[0][1];
  view.rerender(content('en'));
  expect(within(screen.getByRole('main')).getByRole('status').textContent).toBe(
    'Loading accounts...'
  );
  expect(signal.aborted).toBe(false);
  expect(clients).toHaveLength(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(api.dispose).not.toHaveBeenCalled();
  expect(api.admin.capabilities).toHaveBeenCalledTimes(1);
  expect(api.admin.users).toHaveBeenCalledTimes(1);
  await act(async () =>
    pending.resolve({ items: [{ ...serverUser }], total: 1, limit: 20, offset: 0 })
  );
  expect(within(screen.getByRole('main')).getByRole('status').textContent).toBe(
    '1 account on this page loaded.'
  );
  view.rerender(content('fa-IR'));
  expect(within(screen.getByRole('main')).getByRole('status').textContent).toBe(
    '۱ حساب در این صفحه بارگیری شد.'
  );
  expect(api.admin.users).toHaveBeenCalledTimes(1);
});

function localizedDetail(locale: 'en' | 'fa-IR') {
  return (
    <I18nTestProvider locale={locale}>
      <PortalProvider surface="admin">
        <UserDetailView />
      </PortalProvider>
    </I18nTestProvider>
  );
}

it('preserves a pending moderation read, one-use grant, final draft and in-flight write across languages', async () => {
  const view = render(localizedDetail('en'));
  await startAction();
  const checking = deferred<AdminUser>();
  const sending = deferred<void>();
  const api = clients[0];
  api.admin.user.mockReturnValueOnce(checking.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Verify with a passkey' }));
  await waitFor(() => expect(api.admin.user).toHaveBeenCalledTimes(3));
  const grant = grants[0];
  const deadline = grant.deadline;
  const clear = jest.spyOn(grant, 'clear');
  const signal = api.admin.user.mock.calls[2][1];
  view.rerender(localizedDetail('fa-IR'));
  let dialog = within(screen.getByRole('dialog', { name: 'تعلیق حساب' }));
  expect(dialog.getByRole('status').textContent).toBe(
    'تأیید هویت انجام شد. در حال بررسی حساب تثبیت‌شده پیش از تأیید نهایی.'
  );
  expect(signal.aborted).toBe(false);
  expect(api.admin.user).toHaveBeenCalledTimes(3);
  await act(async () => checking.resolve({ ...serverUser }));
  const input = await screen.findByLabelText<HTMLTextAreaElement>('دلیل اقدام مدیریتی');
  expect(input.getAttribute('dir')).toBe('auto');
  fireEvent.click(
    screen.getByRole('checkbox', {
      name: 'حساب، وضعیت فعلی، وضعیت جدید و پیامدهای این اقدام را بررسی کرده‌ام.',
    })
  );
  fireEvent.submit(screen.getByRole('form', { name: 'تأیید تغییر وضعیت حساب' }));
  expect(screen.getByRole('alert').textContent).toBe('دلیلی با حداکثر ۲٬۰۰۰ بایت UTF-8 وارد کنید.');
  view.rerender(localizedDetail('en'));
  expect(screen.getByRole('alert').textContent).toBe(
    'Enter a reason using no more than 2,000 UTF-8 bytes.'
  );
  const reason = '  گزارش بررسی‌شده ABC-123  ';
  fireEvent.change(input, { target: { value: reason } });
  view.rerender(localizedDetail('fa-IR'));
  expect(screen.getByLabelText('دلیل اقدام مدیریتی')).toBe(input);
  expect(input.value).toBe(reason);
  expect(screen.getByRole<HTMLInputElement>('checkbox').checked).toBe(true);
  expect(grant.deadline).toBe(deadline);
  expect(clear).not.toHaveBeenCalled();
  expect(grants).toHaveLength(1);
  api.admin.updateStatus.mockImplementationOnce((_id, body, authority, _signal, sent) => {
    authority.take('session-id');
    sent();
    serverUser = { ...serverUser, status: body.status, lifecycle_revision: '9007199254740994' };
    return sending.promise;
  });
  fireEvent.submit(screen.getByRole('form', { name: 'تأیید تغییر وضعیت حساب' }));
  view.rerender(localizedDetail('en'));
  dialog = within(screen.getByRole('dialog', { name: 'Suspend account' }));
  expect(dialog.getByRole('status').textContent).toBe(
    'Sending status change. Do not submit again.'
  );
  expect(
    dialog.getByRole<HTMLButtonElement>('button', { name: 'Submitting status change...' }).disabled
  ).toBe(true);
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm account status change' }));
  view.rerender(localizedDetail('fa-IR'));
  dialog = within(screen.getByRole('dialog', { name: 'تعلیق حساب' }));
  expect(dialog.getByRole('status').textContent).toBe(
    'در حال ارسال تغییر وضعیت. دوباره ارسال نکنید.'
  );
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
  expect(api.admin.updateStatus).toHaveBeenCalledWith(
    mockTargetID,
    { status: 'suspended', reason: reason.trim(), expected_revision: '9007199254740993' },
    grant,
    expect.any(AbortSignal),
    expect.any(Function)
  );
  expect(api.admin.updateStatus.mock.calls[0][3].aborted).toBe(false);
  expect(clients).toHaveLength(1);
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(api.dispose).not.toHaveBeenCalled();
  expect(api.admin.capabilities).toHaveBeenCalledTimes(1);
  expect(api.stepUpChallenge).toHaveBeenCalledTimes(1);
  expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
  expect(api.admin.user).toHaveBeenCalledTimes(3);
  await act(async () => sending.resolve());
  await screen.findByText('تغییر وضعیت تأیید شد. وضعیت فعلی حساب بارگیری شد.');
  expect(input.value).toBe('');
  expect(() => grant.take('session-id')).toThrow('grant_expired');
  expect(api.admin.updateStatus).toHaveBeenCalledTimes(1);
});

it('does not extend the confirmation deadline or retain a reason after expiry on a language change', async () => {
  jest.useFakeTimers();
  grantSeconds = 1;
  const view = render(localizedDetail('en'));
  const input = await finalForm();
  fireEvent.change(input, { target: { value: 'پیش‌نویس خصوصی' } });
  const deadline = grants[0].deadline;
  act(() => jest.advanceTimersByTime(400));
  view.rerender(localizedDetail('fa-IR'));
  expect(screen.getByLabelText('دلیل اقدام مدیریتی')).toBe(input);
  expect(input.value).toBe('پیش‌نویس خصوصی');
  expect(grants).toHaveLength(1);
  expect(grants[0].deadline).toBe(deadline);
  act(() => jest.advanceTimersByTime(601));
  expect(screen.getByRole('alert').textContent).toBe(
    'اعتبار تأیید هویت منقضی شد. دلیل واردشده پاک شد. با تأیید هویت مجدد اقدام تازه‌ای را آغاز کنید.'
  );
  expect(input.value).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(() => grants[0].take('session-id')).toThrow('grant_expired');
  expect(clients[0].stepUpVerify).toHaveBeenCalledTimes(1);
  expect(clients[0].admin.updateStatus).not.toHaveBeenCalled();
});

it('does not restart a waiting TOTP ceremony or normalize its code when presentation changes', async () => {
  const view = render(localizedDetail('en'));
  await startAction();
  fireEvent.click(screen.getByRole('button', { name: 'Use authenticator code' }));
  const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(code, { target: { value: '001234' } });
  view.rerender(localizedDetail('fa-IR'));
  expect(screen.getByRole('dialog', { name: 'تعلیق حساب' })).toBeTruthy();
  expect(code.isConnected).toBe(true);
  expect(code.value).toBe('001234');
  view.rerender(localizedDetail('en'));
  expect(screen.getByLabelText('Authenticator code')).toBe(code);
  expect(code.value).toBe('001234');
  expect(clients).toHaveLength(1);
  expect(clients[0].bootstrap).toHaveBeenCalledTimes(1);
  expect(clients[0].stepUpChallenge).toHaveBeenCalledTimes(1);
  expect(clients[0].stepUpVerify).not.toHaveBeenCalled();
  expect(grants).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(code.value).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
});
