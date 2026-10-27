import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ProfileEditor } from '../app/dashboard/_components/profile-editor';
import { PasskeysPanel } from '../app/dashboard/_components/passkeys-panel';
import { SessionsView } from '../app/dashboard/_components/sessions-view';
import { StepUpDialog } from '../app/dashboard/_components/step-up-dialog';
import { usePortal } from '../app/dashboard/_components/portal-provider';
import { StepUpGrant, type Profile } from '../app/_lib/portal/contracts';
import { PortalClient } from '../app/_lib/portal/client';
import { PortalError } from '../app/_lib/portal/errors';
import { usePasskey } from '../app/_lib/portal/webauthn';

jest.mock('../app/dashboard/_components/portal-provider', () => ({ usePortal: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));

const profile: Profile = {
  id: 'user-id',
  email: 'person@example.test',
  display_name: 'Original',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '9007199254740993',
  session: { id: 'session-id', expires_at: '2030-01-01T00:00:00Z' },
};
const firstKey = {
  id: 'first-key',
  name: 'My key',
  created_at: '2026-01-01T00:00:00Z',
  user_verified: true,
  backup_eligible: true,
  backup_state: true,
};
const secondKey = { ...firstKey, id: 'second-key', name: 'Backup' };
const api = {
  saveProfile: jest.fn(),
  bootstrap: jest.fn(),
  assertSession: jest.fn(),
  stepUpChallenge: jest.fn(),
  stepUpVerify: jest.fn(),
  keys: jest.fn(),
  registerOptions: jest.fn(),
  registerVerify: jest.fn(),
  renameKey: jest.fn(),
  removeKey: jest.fn(),
  sessions: jest.fn(),
  revokeSession: jest.fn(),
};
const updateProfile = jest.fn();
const signOut = jest.fn();
const grant = () =>
  new StepUpGrant(
    { token: 'single-use-grant', token_type: 'StepUp', expires_in: 60 },
    profile.session.id,
    Date.now(),
    Date.now() + 60000
  );

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((finish) => {
    resolve = finish;
  });
  return { promise, resolve };
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
  jest.resetAllMocks();
  jest.mocked(usePortal).mockReturnValue({
    profile,
    client: api as unknown as PortalClient,
    updateProfile,
    signOut,
    deleteAccount: jest.fn(),
    rememberStepUp: jest.fn(),
  });
  api.assertSession.mockReturnValue(profile);
  api.bootstrap.mockResolvedValue(profile);
  api.keys.mockResolvedValue([firstKey, secondKey]);
  api.stepUpChallenge.mockResolvedValue({
    methods: ['webauthn', 'totp'],
    webauthn: { publicKey: { challenge: 'AA' } },
  });
  api.stepUpVerify.mockImplementation(async () => grant());
  api.registerOptions.mockResolvedValue({ publicKey: { challenge: 'AQ' } });
  api.registerVerify.mockResolvedValue({ ...firstKey, id: 'new-key', name: 'New key' });
  api.removeKey.mockResolvedValue(undefined);
  api.revokeSession.mockResolvedValue(undefined);
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ response: 'adapted-credential' } as unknown as Awaited<
      ReturnType<typeof usePasskey>
    >);
});

async function verifyPasskey() {
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
}

describe('repeated profile edits and conflicts', () => {
  it('blocks duplicates, preserves exact revision strings and permits repeated successful saves', async () => {
    const first = deferred<Profile>();
    api.saveProfile.mockReturnValueOnce(first.promise).mockResolvedValueOnce({
      ...profile,
      display_name: 'Second',
      lifecycle_revision: '9007199254740995',
    });
    render(<ProfileEditor />);
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: ' First ' } });
    const form = screen.getByRole('form', { name: 'Edit profile' });
    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });
    expect(api.saveProfile).toHaveBeenCalledTimes(1);
    expect(api.saveProfile).toHaveBeenCalledWith(
      'First',
      '9007199254740993',
      expect.any(AbortSignal)
    );
    await act(async () =>
      first.resolve({ ...profile, display_name: 'First', lifecycle_revision: '9007199254740994' })
    );
    expect(screen.getByRole('status').textContent).toBe('Profile saved.');
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Second' } });
    fireEvent.submit(form);
    await waitFor(() =>
      expect(api.saveProfile).toHaveBeenLastCalledWith(
        'Second',
        '9007199254740994',
        expect.any(AbortSignal)
      )
    );
    expect(updateProfile).toHaveBeenCalledTimes(2);
    expect(screen.getByLabelText<HTMLInputElement>('Display name').value).toBe('Second');
  });

  it('keeps an unsaved draft on conflict and refresh, then saves against the newly read revision', async () => {
    api.saveProfile
      .mockRejectedValueOnce(new PortalError('profile_conflict', 409))
      .mockResolvedValueOnce({
        ...profile,
        display_name: 'My draft',
        lifecycle_revision: '9007199254740996',
      });
    api.bootstrap.mockResolvedValueOnce({
      ...profile,
      display_name: 'Another tab',
      lifecycle_revision: '9007199254740995',
    });
    render(<ProfileEditor />);
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'My draft' } });
    fireEvent.submit(screen.getByRole('form'));
    expect((await screen.findByRole('alert')).textContent).toContain('saved profile changed');
    expect(screen.getByLabelText<HTMLInputElement>('Display name').value).toBe('My draft');
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Save profile' }).disabled).toBe(
      true
    );
    fireEvent.click(screen.getByRole('button', { name: 'Refresh saved profile' }));
    await waitFor(() =>
      expect(screen.getByTestId('saved-display-name').textContent).toBe('Another tab')
    );
    expect(screen.getByLabelText<HTMLInputElement>('Display name').value).toBe('My draft');
    fireEvent.submit(screen.getByRole('form'));
    await waitFor(() =>
      expect(api.saveProfile).toHaveBeenLastCalledWith(
        'My draft',
        '9007199254740995',
        expect.any(AbortSignal)
      )
    );
  });

  it('validates locally and discards a late save after route unmount', async () => {
    const result = deferred<Profile>();
    api.saveProfile.mockReturnValue(result.promise);
    const view = render(<ProfileEditor />);
    const input = screen.getByLabelText('Display name');
    fireEvent.change(input, { target: { value: 'x'.repeat(81) } });
    fireEvent.submit(screen.getByRole('form'));
    expect(api.saveProfile).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(input);
    fireEvent.change(input, { target: { value: 'Late draft' } });
    fireEvent.submit(screen.getByRole('form'));
    view.unmount();
    await act(async () => result.resolve({ ...profile, display_name: 'Late draft' }));
    expect(updateProfile).not.toHaveBeenCalled();
  });
});

describe('native verification dialog', () => {
  it('starts with confirmation, contains focus, cancels without a ceremony and returns focus', () => {
    const onCancel = jest.fn();
    const opener = document.createElement('button');
    document.body.append(opener);
    opener.focus();
    const view = render(
      <StepUpDialog
        title="Confirm action"
        description="Pinned target"
        onCancel={onCancel}
        onAuthorized={jest.fn()}
      />
    );
    const dialog = screen.getByRole('dialog', { name: 'Confirm action' });
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Confirm action' }));
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: 'Continue to verification' })
    );
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
    view.unmount();
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });

  it('offers only advertised factors, requires exact TOTP input, and keeps failed TOTP inside the dialog', async () => {
    api.stepUpVerify
      .mockRejectedValueOnce(new PortalError('invalid_credentials', 401))
      .mockImplementationOnce(async () => grant());
    const authorized = jest.fn().mockResolvedValue(undefined);
    const onCancel = jest.fn();
    render(
      <StepUpDialog
        title="Confirm action"
        description="Pinned target"
        onCancel={onCancel}
        onAuthorized={authorized}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
    const form = screen.getByRole('form', { name: 'Step-up authenticator verification' });
    fireEvent.submit(form);
    expect(api.stepUpVerify).not.toHaveBeenCalled();
    const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
    expect(document.activeElement).toBe(code);
    fireEvent.change(code, { target: { value: '012345' } });
    expect(api.stepUpVerify).not.toHaveBeenCalled();
    fireEvent.submit(form);
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Verification failed or expired'
    );
    expect(code.value).toBe('');
    expect(onCancel).not.toHaveBeenCalled();
    expect(authorized).not.toHaveBeenCalled();
    fireEvent.change(code, { target: { value: '654321' } });
    fireEvent.submit(form);
    await waitFor(() => expect(authorized).toHaveBeenCalledTimes(1));
    expect(api.stepUpVerify.mock.calls[0][0]).toEqual({ method: 'totp', code: '012345' });
    const usedGrant = authorized.mock.calls[0][0] as StepUpGrant;
    expect(() => usedGrant.take(profile.session.id)).toThrow('grant_expired');
  });

  it('uses required WebAuthn UV and never spends a late grant after cancellation', async () => {
    const result = deferred<StepUpGrant>();
    api.stepUpVerify.mockReturnValue(result.promise);
    const authorized = jest.fn();
    const onCancel = jest.fn();
    render(
      <StepUpDialog
        title="Confirm action"
        description="Pinned target"
        onCancel={onCancel}
        onAuthorized={authorized}
      />
    );
    await verifyPasskey();
    await waitFor(() => expect(api.stepUpVerify).toHaveBeenCalledTimes(1));
    expect(usePasskey).toHaveBeenCalledWith(
      { publicKey: { challenge: 'AA' } },
      expect.any(AbortSignal),
      false,
      true
    );
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    const late = grant();
    await act(async () => result.resolve(late));
    expect(authorized).not.toHaveBeenCalled();
    expect(() => late.take(profile.session.id)).toThrow('grant_expired');
  });

  it('does not expose TOTP when the account did not advertise it', async () => {
    api.stepUpChallenge.mockResolvedValueOnce({
      methods: ['webauthn'],
      webauthn: { publicKey: { challenge: 'AA' } },
    });
    render(
      <StepUpDialog
        title="Confirm action"
        description="Pinned target"
        onCancel={jest.fn()}
        onAuthorized={jest.fn()}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    await screen.findByRole('button', { name: 'Verify with a passkey' });
    expect(screen.queryByRole('button', { name: 'Use authenticator code' })).toBeNull();
  });

  it('restricts WebAuthn-only actions even when TOTP is advertised or requested as a resume method', async () => {
    const authorized = jest.fn().mockResolvedValue(undefined);
    render(
      <StepUpDialog
        title="Delete account"
        description="Deletion requires UV"
        mode="webauthn-only"
        resumeMethod="totp"
        onCancel={jest.fn()}
        onAuthorized={authorized}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    const verify = await screen.findByRole('button', { name: 'Verify with a passkey' });
    expect(screen.queryByRole('button', { name: 'Use authenticator code' })).toBeNull();
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    expect(screen.queryByText(/pending action was restored/)).toBeNull();
    fireEvent.click(verify);
    await waitFor(() => expect(authorized).toHaveBeenCalledTimes(1));
    expect(usePasskey).toHaveBeenCalledWith(
      { publicKey: { challenge: 'AA' } },
      expect.any(AbortSignal),
      false,
      true
    );
    expect(api.stepUpVerify.mock.calls[0][0].method).toBe('webauthn');
  });

  it('fails closed when only TOTP is available for a WebAuthn-only action', async () => {
    api.stepUpChallenge.mockResolvedValueOnce({ methods: ['totp'] });
    render(
      <StepUpDialog
        title="Delete account"
        description="Deletion requires UV"
        mode="webauthn-only"
        onCancel={jest.fn()}
        onAuthorized={jest.fn()}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    const message = (await screen.findByRole('alert')).textContent;
    expect(message).toContain('requires a passkey');
    expect(message).not.toMatch(/authenticator app|authenticator code|TOTP/);
    expect(screen.queryByLabelText('Authenticator code')).toBeNull();
    expect(api.stepUpVerify).not.toHaveBeenCalled();
  });

  it.each(['user_verification_required', 'invalid_credentials'])(
    'does not recommend TOTP for a WebAuthn-only %s failure',
    async (code) => {
      api.stepUpVerify.mockRejectedValueOnce(new PortalError(code, 401));
      const authorized = jest.fn();
      render(
        <StepUpDialog
          title="Delete account"
          description="Deletion requires UV"
          mode="webauthn-only"
          onCancel={jest.fn()}
          onAuthorized={authorized}
        />
      );
      await verifyPasskey();
      const message = (await screen.findByRole('alert')).textContent;
      expect(message).toContain('passkey');
      expect(message).not.toMatch(/authenticator app|authenticator code|TOTP/);
      expect(authorized).not.toHaveBeenCalled();
    }
  );
});

describe('passkey and session management', () => {
  async function openAction(kind: 'add' | 'rename' | 'remove') {
    if (kind === 'add') {
      fireEvent.change(screen.getByLabelText('New passkey name'), { target: { value: 'New key' } });
      fireEvent.submit(screen.getByRole('form', { name: 'Add passkey' }));
    } else if (kind === 'rename') {
      fireEvent.click(screen.getByRole('button', { name: 'Rename My key' }));
      fireEvent.change(screen.getByLabelText('Passkey name'), {
        target: { value: 'Chosen label' },
      });
      fireEvent.submit(screen.getByRole('form', { name: 'Rename passkey' }));
    } else fireEvent.click(screen.getByRole('button', { name: 'Remove My key' }));
    await verifyPasskey();
  }

  it('validates names before verification and grants registration start only, not completion', async () => {
    render(<PasskeysPanel />);
    await screen.findByRole('heading', { name: 'My key' });
    const input = screen.getByLabelText('New passkey name');
    fireEvent.change(input, { target: { value: 'x'.repeat(81) } });
    fireEvent.submit(screen.getByRole('form', { name: 'Add passkey' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: ' New key ' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Add passkey' }));
    await verifyPasskey();
    await screen.findByRole('heading', { name: 'New key' });
    expect(api.registerOptions).toHaveBeenCalledWith(
      'New key',
      expect.any(StepUpGrant),
      expect.any(AbortSignal)
    );
    expect(api.registerVerify).toHaveBeenCalledWith(
      { response: 'adapted-credential' },
      expect.any(AbortSignal),
      expect.any(Function)
    );
    expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
    expect(usePasskey).toHaveBeenLastCalledWith(
      { publicKey: { challenge: 'AQ' } },
      expect.any(AbortSignal),
      true
    );
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('pins rename target and submitted name, preserving final-key error semantics', async () => {
    api.renameKey.mockResolvedValue({ ...firstKey, name: 'Chosen label' });
    render(<PasskeysPanel />);
    fireEvent.click(await screen.findByRole('button', { name: 'Rename My key' }));
    fireEvent.change(screen.getByLabelText('Passkey name'), { target: { value: 'Chosen label' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Rename passkey' }));
    fireEvent.change(screen.getByLabelText('Passkey name'), {
      target: { value: 'Not the pinned label' },
    });
    await verifyPasskey();
    await screen.findByRole('heading', { name: 'Chosen label' });
    expect(api.renameKey).toHaveBeenCalledWith(
      'first-key',
      'Chosen label',
      expect.any(StepUpGrant),
      expect.any(AbortSignal),
      expect.any(Function)
    );
    api.removeKey.mockRejectedValueOnce(new PortalError('last_credential', 409));
    fireEvent.click(screen.getByRole('button', { name: 'Remove Chosen label' }));
    await verifyPasskey();
    expect((await screen.findByRole('alert')).textContent).toContain(
      'last passkey cannot be removed'
    );
    expect(screen.getByRole('button', { name: 'Start new verification' })).toBeTruthy();
    expect(api.removeKey).toHaveBeenCalledTimes(1);
  });

  it('uses the server current flag, confirms individual revocation and treats a vanished target as a list change', async () => {
    api.sessions.mockResolvedValue([
      {
        id: 'flagged-current',
        current: true,
        ip: '127.0.0.1',
        user_agent: '<script>not markup</script>',
        created_at: '2026-01-01T00:00:00Z',
        last_seen_at: '2026-01-02T00:00:00Z',
      },
      {
        id: 'remote-id',
        current: false,
        ip: '',
        user_agent: '',
        created_at: '2026-01-01T00:00:00Z',
        last_seen_at: '2026-01-02T00:00:00Z',
      },
    ]);
    api.revokeSession.mockRejectedValueOnce(new PortalError('not_found', 404));
    const { container } = render(<SessionsView />);
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke session' }));
    expect(api.revokeSession).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('remote-id')).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm revocation' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(api.revokeSession).toHaveBeenCalledWith('remote-id', expect.any(AbortSignal));
    expect(screen.getByRole('status').textContent).toContain('no longer in the list');
    expect(container.querySelector('script')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out this session' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm sign out' }));
    expect(signOut).toHaveBeenCalledWith('flagged-current');
  });

  it.each(['add', 'rename', 'remove'] as const)(
    'reports a cancelled transmitted %s as uncertain and permits only explicit authenticated refresh, ignoring late completion',
    async (kind) => {
      const pending = deferred<unknown>();
      const mutate =
        kind === 'add' ? api.registerVerify : kind === 'rename' ? api.renameKey : api.removeKey;
      mutate.mockImplementation((...args: unknown[]) => {
        (args[args.length - 1] as () => void)();
        return pending.promise;
      });
      const initial = [firstKey, secondKey];
      const confirmed =
        kind === 'add'
          ? [...initial, { ...firstKey, id: 'new-key', name: 'New key' }]
          : kind === 'rename'
            ? [{ ...firstKey, name: 'Chosen label' }, secondKey]
            : [secondKey];
      api.keys.mockResolvedValueOnce(initial).mockResolvedValueOnce(confirmed);
      render(<PasskeysPanel />);
      await screen.findByRole('heading', { name: 'My key' });
      await openAction(kind);
      await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
      const issued = (await api.stepUpVerify.mock.results[0].value) as StepUpGrant;
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
      expect(screen.queryByRole('dialog')).toBeNull();
      expect(screen.getByRole('alert').textContent).toContain('may already have completed');
      expect(screen.getByRole('alert').textContent).toContain('Refresh passkeys');
      expect(() => issued.take(profile.session.id)).toThrow('grant_expired');
      expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Add passkey' }).disabled).toBe(
        true
      );
      expect(api.keys).toHaveBeenCalledTimes(1);
      await act(async () => pending.resolve(kind === 'remove' ? undefined : confirmed[0]));
      expect(screen.getByRole('heading', { name: 'My key' })).toBeTruthy();
      expect(mutate).toHaveBeenCalledTimes(1);
      expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
      fireEvent.click(screen.getByRole('button', { name: 'Refresh passkeys' }));
      await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
      expect(api.keys).toHaveBeenCalledTimes(2);
      expect(screen.getAllByTestId('passkey-row')).toHaveLength(confirmed.length);
      expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Add passkey' }).disabled).toBe(
        false
      );
      expect(mutate).toHaveBeenCalledTimes(1);
    }
  );

  it('does not claim possible mutation completion if cancellation precedes transmission', async () => {
    const pending = deferred<unknown>();
    api.renameKey.mockReturnValueOnce(pending.promise);
    render(<PasskeysPanel />);
    await screen.findByRole('heading', { name: 'My key' });
    await openAction('rename');
    await waitFor(() => expect(api.renameKey).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alert')).toBeNull();
    await act(async () => pending.resolve({ ...firstKey, name: 'Chosen label' }));
    expect(screen.getByRole('heading', { name: 'My key' })).toBeTruthy();
  });

  it.each(['rename', 'remove'] as const)(
    'invalidates pending key reads before a confirmed %s so late GET cannot overwrite it',
    async (kind) => {
      const stale = deferred<unknown>();
      api.keys.mockResolvedValueOnce([firstKey, secondKey]).mockReturnValueOnce(stale.promise);
      api.renameKey.mockResolvedValueOnce({ ...firstKey, name: 'Chosen label' });
      render(<PasskeysPanel />);
      await screen.findByRole('heading', { name: 'My key' });
      fireEvent.click(screen.getByRole('button', { name: 'Refresh passkeys' }));
      await waitFor(() => expect(api.keys).toHaveBeenCalledTimes(2));
      const readSignal = api.keys.mock.calls[1][0] as AbortSignal;
      await openAction(kind);
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
      expect(readSignal.aborted).toBe(true);
      await act(async () => stale.resolve([firstKey, secondKey]));
      expect(screen.queryByRole('heading', { name: 'My key' })).toBeNull();
      if (kind === 'rename')
        expect(screen.getByRole('heading', { name: 'Chosen label' })).toBeTruthy();
      else expect(screen.getAllByTestId('passkey-row')).toHaveLength(1);
    }
  );

  it('does not reinsert a revoked session from a previously pending list GET', async () => {
    const sessions = [
      {
        id: 'current',
        current: true,
        ip: '',
        user_agent: '',
        created_at: '2026-01-01T00:00:00Z',
        last_seen_at: '2026-01-01T00:00:00Z',
      },
      {
        id: 'remote',
        current: false,
        ip: '',
        user_agent: '',
        created_at: '2026-01-01T00:00:00Z',
        last_seen_at: '2026-01-01T00:00:00Z',
      },
    ];
    const stale = deferred<unknown>();
    api.sessions.mockResolvedValueOnce(sessions).mockReturnValueOnce(stale.promise);
    render(<SessionsView />);
    await screen.findByRole('button', { name: 'Revoke session' });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh sessions' }));
    await waitFor(() => expect(api.sessions).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole('button', { name: 'Revoke session' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revocation' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect((api.sessions.mock.calls[1][0] as AbortSignal).aborted).toBe(true);
    await act(async () => stale.resolve(sessions));
    expect(screen.queryByRole('button', { name: 'Revoke session' })).toBeNull();
    expect(screen.getAllByTestId('session-row')).toHaveLength(1);
  });
});
