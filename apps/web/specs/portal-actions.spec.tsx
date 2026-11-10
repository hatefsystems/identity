import { act, fireEvent, I18nTestProvider, render, screen, waitFor, within } from '../i18n/testing';
import { ProfileEditor } from '../app/dashboard/_components/profile-editor';
import { PasskeysPanel } from '../app/dashboard/_components/passkeys-panel';
import { SessionsView } from '../app/dashboard/_components/sessions-view';
import { PrivacyView } from '../app/dashboard/_components/privacy-view';
import { StepUpDialog } from '../app/dashboard/_components/step-up-dialog';
import { NativeDialog } from '../app/_components/native-dialog';
import { usePortal } from '../app/_components/portal-provider';
import { StepUpGrant, type BrowserSession, type Profile } from '../app/_lib/portal/contracts';
import { PortalClient } from '../app/_lib/portal/client';
import { PortalError } from '../app/_lib/portal/errors';
import { sensitiveClearEvent } from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

jest.mock('../app/_components/portal-provider', () => ({ usePortal: jest.fn() }));
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
  Object.defineProperty(HTMLElement.prototype, 'getClientRects', {
    configurable: true,
    value: () => [new DOMRect(0, 0, 100, 44)],
  });
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
    configurable: true,
    value: jest.fn(),
  });
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
    reportPermissionLoss: jest.fn(),
    reportModerationInterruption: jest.fn(),
    reportLegalInterruption: jest.fn(),
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
  const verify = await screen.findByRole('button', { name: 'Verify with a passkey' });
  await act(async () => fireEvent.click(verify));
}

describe('repeated profile edits and conflicts', () => {
  it.each([
    ['en', 'Display name', 'Save profile', 'Refresh saved profile', 'Last loaded saved name:'],
    ['fa-IR', 'نام نمایشی', 'ذخیرهٔ نمایه', 'تازه‌سازی نمایهٔ ذخیره‌شده', 'نام ذخیره‌شده در آخرین دریافت:'],
  ] as const)('promotes explicit Refresh in %s without treating the last-loaded value as latest or saving the draft automatically', async (locale, nameLabel, saveLabel, refreshLabel, loadedLabel) => {
    api.saveProfile.mockRejectedValueOnce(new PortalError('profile_conflict', 409)).mockResolvedValueOnce({
      ...profile, display_name: 'Preserved draft', lifecycle_revision: '9007199254740996',
    });
    const read = deferred<Profile>();
    api.bootstrap.mockReturnValueOnce(read.promise);
    render(<ProfileEditor />, { locale });
    const name = screen.getByLabelText<HTMLInputElement>(nameLabel);
    const form = screen.getByRole('form');
    const save = screen.getByRole<HTMLButtonElement>('button', { name: saveLabel });
    const refresh = screen.getByRole<HTMLButtonElement>('button', { name: refreshLabel });
    expect(form.className).toContain('max-w-xl');
    expect(refresh.className).toContain('bg-background');
    fireEvent.change(name, { target: { value: 'Preserved draft' } });
    fireEvent.submit(form);
    await screen.findByRole('alert');
    expect(save.disabled).toBe(true);
    expect(refresh.className).toContain('bg-primary');
    expect(refresh.parentElement?.firstElementChild).toBe(refresh);
    expect(screen.getByText((text) => text.startsWith(loadedLabel))).toBeTruthy();
    expect(screen.getByTestId('saved-display-name').textContent).toBe('Original');
    expect(api.bootstrap).not.toHaveBeenCalled();
    fireEvent.submit(form);
    expect(api.saveProfile).toHaveBeenCalledTimes(1);
    fireEvent.click(refresh);
    await act(async () => read.resolve({ ...profile, display_name: 'Server comparison', lifecycle_revision: '9007199254740995' }));
    expect(screen.getByTestId('saved-display-name').textContent).toBe('Server comparison');
    expect(screen.getByLabelText(nameLabel)).toBe(name);
    expect(name.value).toBe('Preserved draft');
    expect(save.disabled).toBe(false);
    expect(refresh.className).toContain('bg-background');
    expect(api.saveProfile).toHaveBeenCalledTimes(1);
    fireEvent.click(save);
    await waitFor(() => expect(api.saveProfile).toHaveBeenLastCalledWith(
      'Preserved draft', '9007199254740995', expect.any(AbortSignal)
    ));
  });

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

describe('privacy task hierarchy', () => {
  it.each([
    ['en', 'Delete my account', 'Retention and recovery policy details', /not a promise of complete erasure/],
    ['fa-IR', 'حذف حساب من', 'جزئیات سیاست نگهداری و بازیابی', /وعدهٔ پاک‌شدن کامل همهٔ نسخه‌ها/],
  ] as const)('keeps consequences and acknowledgement ahead of closed secondary policy in %s', (locale, deleteLabel, policyLabel, warning) => {
    profile.deletion_enabled = true;
    render(<PrivacyView />, { locale });
    const remove = screen.getByRole<HTMLButtonElement>('button', { name: deleteLabel });
    const acknowledge = screen.getByRole<HTMLInputElement>('checkbox');
    const limitation = screen.getAllByText(warning).find((element) => !element.closest('details'));
    const policy = screen.getByText(policyLabel).closest('details');
    expect(limitation).toBeTruthy();
    expect(acknowledge.closest('details')).toBeNull();
    expect(remove.closest('details')).toBeNull();
    expect(remove.disabled).toBe(true);
    expect(policy?.open).toBe(false);
    expect(remove.compareDocumentPosition(policy as Node) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);
    fireEvent.click(acknowledge);
    expect(remove.disabled).toBe(false);
    if (policy) policy.open = true;
    expect(acknowledge.checked).toBe(true);
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
    expect(api.bootstrap).not.toHaveBeenCalled();
  });
});

describe('native verification dialog', () => {
  it('contains only visible enabled controls, including collapsed evidence summaries', () => {
    render(
      <NativeDialog title="Review action" description="Pinned target" onCancel={jest.fn()}>
        <details>
          <summary>Secondary evidence</summary>
          <button type="button">Collapsed control</button>
        </details>
        <div style={{ display: 'none' }}><button type="button">CSS hidden</button></div>
        <button type="button" hidden>Hidden</button>
        <button type="button" disabled>Disabled</button>
        <fieldset disabled><button type="button">Disabled by fieldset</button></fieldset>
        <div inert><button type="button">Inert</button></div>
        <button type="button" data-testid="zero-rect">No layout rectangle</button>
        <button type="button">Cancel review</button>
      </NativeDialog>
    );
    Object.defineProperty(screen.getByTestId('zero-rect'), 'getClientRects', { value: () => [] });
    const dialog = screen.getByRole('dialog');
    const last = screen.getByRole('button', { name: 'Cancel review' });
    const summary = screen.getByText('Secondary evidence');
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(last);
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(summary);
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  it('restores a visible equivalent opener after reflow and falls back rather than focusing hidden duplicates', () => {
    const opener = document.createElement('button');
    opener.dataset.focusReturn = 'review-target';
    opener.textContent = 'Open review';
    const equivalent = document.createElement('button');
    equivalent.dataset.focusReturn = 'review-target';
    equivalent.textContent = 'Open review';
    equivalent.hidden = true;
    const fallback = document.createElement('main');
    fallback.id = 'portal-content';
    fallback.tabIndex = -1;
    document.body.append(opener, equivalent, fallback);
    opener.focus();
    const view = render(
      <NativeDialog title="Review action" description="Pinned target" onCancel={jest.fn()}>
        <button type="button">Cancel review</button>
      </NativeDialog>
    );
    opener.hidden = true;
    equivalent.hidden = false;
    view.unmount();
    expect(document.activeElement).toBe(equivalent);
    const second = render(
      <NativeDialog title="Review action" description="Pinned target" onCancel={jest.fn()}>
        <button type="button">Cancel review</button>
      </NativeDialog>
    );
    equivalent.style.display = 'none';
    second.unmount();
    expect(document.activeElement).toBe(fallback);
    opener.remove();
    equivalent.remove();
    fallback.remove();
  });

  it('opts into one review scroll body and a persistent footer without remounting verification', async () => {
    const authorized = deferred<void>();
    const onAuthorized = jest.fn(() => authorized.promise);
    const view = render(
      <StepUpDialog
        layout="review"
        title="Review action"
        description="Pinned target"
        onCancel={jest.fn()}
        onAuthorized={onAuthorized}
        verifiedContent={<p>Final review</p>}
        verifiedActions={<button type="button">Confirm action</button>}
      />
    );
    const dialog = screen.getByRole('dialog');
    const heading = screen.getByRole('heading', { name: 'Review action' });
    const cancel = screen.getByRole('button', { name: 'Cancel' });
    expect(dialog.getAttribute('data-layout')).toBe('review');
    expect(dialog.className.split(' ')).toContain('!m-0');
    expect(dialog.className.split(' ')).toContain('md:!m-auto');
    expect(dialog.className).toContain('supports-[height:100dvh]:h-[100dvh]');
    expect(dialog.querySelectorAll('[data-dialog-scroll]')).toHaveLength(1);
    expect(cancel.closest('footer')).not.toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
    const input = screen.getByLabelText<HTMLInputElement>('Authenticator code');
    const verify = screen.getByRole<HTMLButtonElement>('button', { name: 'Verify code' });
    const form = screen.getByRole<HTMLFormElement>('form');
    expect(verify.form).toBe(form);
    expect(verify.closest('footer')).not.toBeNull();
    expect(form.contains(verify)).toBe(false);
    fireEvent.change(input, { target: { value: '۰١2۳٤5' } });
    fireEvent.click(verify);
    await screen.findByText('Final review');
    expect(onAuthorized).toHaveBeenCalledTimes(1);
    expect(api.stepUpVerify.mock.calls[0][0]).toEqual({ method: 'totp', code: '012345' });
    expect(screen.getByRole('dialog')).toBe(dialog);
    expect(screen.getByRole('heading', { name: 'Review action' })).toBe(heading);
    expect(screen.getByRole('button', { name: 'Cancel' })).toBe(cancel);
    expect(screen.getByRole('button', { name: 'Confirm action' }).closest('footer')).not.toBeNull();
    expect(api.stepUpChallenge).toHaveBeenCalledTimes(1);
    await act(async () => authorized.resolve());
    view.unmount();
  });

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

  it('offers only advertised factors, rejects non-digit TOTP input, and keeps failed TOTP inside the dialog', async () => {
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
    for (const [value, expected] of [
      ['01234', '01234'],
      ['0123456', '0123456'],
      ['012 345', '012 345'],
      ['012-345', '012-345'],
      ['01234a', '01234a'],
      ['۰١۲-٣۴٥', '012-345'],
      ['۰١۲ ٣۴٥', '012 345'],
      ['۰١۲٣۴٥6', '0123456'],
      ['０１２３４５', '０１２３４５'],
      ['\u202e۰١۲٣۴٥', '\u202e012345'],
      ['۰١۲٣۴٥\u2069', '012345\u2069'],
    ]) {
      fireEvent.change(code, { target: { value } });
      fireEvent.submit(form);
      expect(code.value).toBe(expected);
      expect(api.stepUpVerify).not.toHaveBeenCalled();
    }
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

  describe.each([
    [
      'en',
      'Continue to verification',
      'Use authenticator code',
      'Authenticator code',
      'Step-up authenticator verification',
    ],
    [
      'fa-IR',
      'ادامه برای تأیید هویت',
      'استفاده از کد رمزساز',
      'کد رمزساز',
      'تأیید هویت تکمیلی با رمزساز',
    ],
  ] as const)('numeric step-up input in %s', (locale, continueLabel, useCode, codeLabel, formLabel) => {
    it.each(['012345', '۰۱۲۳۴۵', '٠١٢٣٤٥', '۰١2۳٤5'])(
      'normalizes current DOM autofill bytes on explicit submit without relying on a change event', async (value) => {
        const authorized = jest.fn().mockResolvedValue(undefined);
        render(<StepUpDialog title="Confirm action" description="Pinned target" onCancel={jest.fn()} onAuthorized={authorized} />, { locale });
        fireEvent.click(screen.getByRole('button', { name: continueLabel }));
        fireEvent.click(await screen.findByRole('button', { name: useCode }));
        const input = screen.getByLabelText<HTMLInputElement>(codeLabel);
        input.value = value;
        expect(api.stepUpVerify).not.toHaveBeenCalled();
        fireEvent.submit(screen.getByRole('form', { name: formLabel }));
        await waitFor(() => expect(authorized).toHaveBeenCalledTimes(1));
        expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
        expect(api.stepUpVerify.mock.calls[0][0]).toEqual({ method: 'totp', code: '012345' });
        expect(input.value).toBe('');
      }
    );

    it.each([
      ['ASCII', '012345'],
      ['Persian', '۰۱۲۳۴۵'],
      ['Arabic-Indic', '٠١٢٣٤٥'],
      ['mixed', '۰١2۳٤5'],
    ])(
      'normalizes a paste-sized %s input and submits only six ASCII digits',
      async (_script, value) => {
        const authorized = jest.fn().mockResolvedValue(undefined);
        render(
          <StepUpDialog
            title="Confirm action"
            description="Pinned target"
            onCancel={jest.fn()}
            onAuthorized={authorized}
          />,
          { locale }
        );
        fireEvent.click(screen.getByRole('button', { name: continueLabel }));
        fireEvent.click(await screen.findByRole('button', { name: useCode }));
        const input = screen.getByLabelText<HTMLInputElement>(codeLabel);
        fireEvent.change(input, { target: { value } });
        expect(input.value).toBe('012345');
        expect(input.getAttribute('dir')).toBe('ltr');
        expect(input.getAttribute('autoComplete')).toBe('one-time-code');
        expect(api.stepUpVerify).not.toHaveBeenCalled();
        fireEvent.submit(screen.getByRole('form', { name: formLabel }));
        await waitFor(() => expect(authorized).toHaveBeenCalledTimes(1));
        expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
        expect(api.stepUpVerify).toHaveBeenCalledWith(
          { method: 'totp', code: '012345' },
          expect.any(AbortSignal)
        );
        expect(input.value).toBe('');
      }
    );

    it('normalizes successive typed native digits while retaining incomplete-length validation', async () => {
      render(
        <StepUpDialog
          title="Confirm action"
          description="Pinned target"
          onCancel={jest.fn()}
          onAuthorized={jest.fn().mockResolvedValue(undefined)}
        />,
        { locale }
      );
      fireEvent.click(screen.getByRole('button', { name: continueLabel }));
      fireEvent.click(await screen.findByRole('button', { name: useCode }));
      const input = screen.getByLabelText<HTMLInputElement>(codeLabel);
      const form = screen.getByRole('form', { name: formLabel });
      for (const [digit, expected] of [
        ['۰', '0'],
        ['١', '01'],
        ['۲', '012'],
        ['٣', '0123'],
        ['۴', '01234'],
      ]) {
        fireEvent.change(input, { target: { value: `${input.value}${digit}` } });
        expect(input.value).toBe(expected);
        fireEvent.submit(form);
        expect(input.getAttribute('aria-invalid')).toBe('true');
        expect(api.stepUpVerify).not.toHaveBeenCalled();
      }
      fireEvent.change(input, { target: { value: `${input.value}٥` } });
      expect(input.value).toBe('012345');
      expect(input.getAttribute('aria-invalid')).toBe('false');
      fireEvent.submit(form);
      await waitFor(() => expect(api.stepUpVerify).toHaveBeenCalledTimes(1));
      expect(api.stepUpVerify.mock.calls[0][0]).toEqual({ method: 'totp', code: '012345' });
    });
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
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Chosen label' })));
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

  it.each(['en', 'fa-IR'] as const)(
    'keeps similar reported-browser targets frozen through list changes and locale rerenders in %s',
    async (locale) => {
      const selected: BrowserSession = {
        id: 'similar-session-0000000000000001', current: false, ip: '192.0.2.1',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
        created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T01:00:00Z',
      };
      const similar = { ...selected, id: 'similar-session-0000000000000002', last_seen_at: '2026-01-02T02:00:00Z' };
      const original = { ...selected };
      const stale = deferred<BrowserSession[]>();
      api.sessions.mockResolvedValueOnce([selected, similar]).mockReturnValueOnce(stale.promise);
      const view = (language: 'en' | 'fa-IR') => (
        <I18nTestProvider locale={language}><SessionsView /></I18nTestProvider>
      );
      const result = render(view(locale));
      const rows = await screen.findAllByTestId('session-row');
      const browserLabel = locale === 'en' ? 'Reported browser: Chrome' : 'مرورگر گزارش‌شده: Chrome';
      expect(screen.getAllByRole('heading', { name: browserLabel })).toHaveLength(2);
      expect(within(rows[0]).getByText(original.user_agent).getAttribute('dir')).toBe('auto');
      expect(rows[0].querySelector('time')?.getAttribute('datetime')).toBe(original.last_seen_at);
      expect(rows[1].querySelector('time')?.getAttribute('datetime')).toBe(similar.last_seen_at);
      expect(within(rows[0]).getByText(original.id).getAttribute('dir')).toBe('ltr');
      const refresh = locale === 'en' ? 'Refresh sessions' : 'تازه‌سازی نشست‌ها';
      const revoke = locale === 'en' ? 'Revoke session' : 'ابطال نشست';
      fireEvent.click(screen.getByRole('button', { name: refresh }));
      await waitFor(() => expect(api.sessions).toHaveBeenCalledTimes(2));
      fireEvent.click(within(rows[0]).getByRole('button', { name: revoke }));
      const dialog = screen.getByRole('dialog');
      expect(within(dialog).getByRole('heading', { name: browserLabel })).toBeTruthy();
      expect(within(dialog).getByText(original.id)).toBeTruthy();
      expect(dialog.querySelector('time')?.getAttribute('datetime')).toBe(original.last_seen_at);
      // Changing the list's original object must not change the cloned selected entry.
      selected.id = 'replacement-session';
      selected.current = true;
      selected.user_agent = 'Version/18.0 Safari/605.1.15';
      selected.last_seen_at = '2026-01-03T00:00:00Z';
      await act(async () => stale.resolve([{ ...selected }, similar]));
      const otherLocale = locale === 'en' ? 'fa-IR' : 'en';
      result.rerender(view(otherLocale));
      expect(screen.getByRole('dialog')).toBe(dialog);
      expect(within(dialog).getByText(original.id)).toBeTruthy();
      expect(within(dialog).queryByText(selected.id)).toBeNull();
      expect(within(dialog).getByRole('heading', {
        name: otherLocale === 'en' ? 'Reported browser: Chrome' : 'مرورگر گزارش‌شده: Chrome',
      })).toBeTruthy();
      expect(within(dialog).getByText(otherLocale === 'en' ? 'Other browser session' : 'نشست مرورگر دیگر')).toBeTruthy();
      expect(dialog.querySelector('time')?.getAttribute('datetime')).toBe(original.last_seen_at);
      expect(api.sessions).toHaveBeenCalledTimes(2);
      fireEvent.click(within(dialog).getByRole('button', {
        name: otherLocale === 'en' ? 'Confirm revocation' : 'تأیید ابطال',
      }));
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
      expect(api.revokeSession).toHaveBeenCalledWith(original.id, expect.any(AbortSignal));
      expect(signOut).not.toHaveBeenCalled();
    }
  );

  it.each(['en', 'fa-IR'] as const)('provides an honest missing/reduced/unknown UA fallback in %s', async (locale) => {
    api.sessions.mockResolvedValue(['', 'Mozilla/5.0', 'UnrecognizedBrowser/1.0'].map((user_agent, index) => ({
      id: `unknown-${index}`, current: index === 0, ip: '', user_agent,
      created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z',
    })));
    render(<SessionsView />, { locale });
    const rows = await screen.findAllByTestId('session-row');
    const unknown = locale === 'en'
      ? 'Unknown browser (details missing or reduced)'
      : 'مرورگر نامشخص (جزئیات موجود نیست یا کاهش یافته است)';
    expect(screen.getAllByRole('heading', { name: unknown })).toHaveLength(3);
    fireEvent.click(within(rows[0]).getByRole('button', {
      name: locale === 'en' ? 'Sign out this session' : 'خروج از این نشست',
    }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: unknown })).toBeTruthy();
    expect(within(dialog).getByText('unknown-0')).toBeTruthy();
    expect(within(dialog).getByText(locale === 'en' ? 'This browser session' : 'نشست این مرورگر')).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', {
      name: locale === 'en' ? 'Confirm sign out' : 'تأیید خروج',
    }));
    expect(signOut).toHaveBeenCalledWith('unknown-0');
    expect(api.revokeSession).not.toHaveBeenCalled();
  });

  it.each([
    ['Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0', 'Edge'],
    ['Chrome/120.0.0.0 Safari/537.36 OPR/105.0', 'Opera'],
    ['Chrome/120.0.0.0 SamsungBrowser/24.0', 'Samsung Internet'],
    ['Mozilla/5.0 Firefox/132.0', 'Firefox'],
    ['Mozilla/5.0 FxiOS/132.0 Safari/605.1', 'Firefox'],
    ['Mozilla/5.0 CriOS/132.0 Safari/605.1', 'Chrome'],
    ['Mozilla/5.0 Version/18.0 Safari/605.1.15', 'Safari'],
  ])('uses only self-reported browser tokens for %s', async (user_agent, browser) => {
    api.sessions.mockResolvedValue([{
      id: 'reported-browser', current: false, ip: '', user_agent,
      created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z',
    }]);
    render(<SessionsView />);
    await screen.findByRole('heading', { name: `Reported browser: ${browser}` });
    expect(screen.getByText(user_agent)).toBeTruthy();
  });

  it.each(['clear', 'unmount'] as const)('preserves session-operation abort and late-response rules on %s', async (end) => {
    const session: BrowserSession = {
      id: 'remote', current: false, ip: '', user_agent: 'Firefox/132.0',
      created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z',
    };
    const pending = deferred<void>();
    api.sessions.mockResolvedValueOnce([session]);
    api.revokeSession.mockReturnValueOnce(pending.promise);
    const result = render(<SessionsView />);
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke session' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revocation' }));
    const signal = api.revokeSession.mock.calls[0][1] as AbortSignal;
    if (end === 'clear') act(() => window.dispatchEvent(new Event(sensitiveClearEvent)));
    else result.unmount();
    expect(signal.aborted).toBe(true);
    expect(screen.queryByRole('dialog')).toBeNull();
    await act(async () => pending.resolve());
    expect(api.sessions).toHaveBeenCalledTimes(1);
    expect(api.revokeSession).toHaveBeenCalledTimes(1);
    expect(signOut).not.toHaveBeenCalled();
    if (end === 'clear') {
      expect(screen.getAllByTestId('session-row')).toHaveLength(1);
      expect(screen.getByRole('status').textContent).not.toContain('Session revoked');
    }
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
             ? [{ ...firstKey, name: 'Server-confirmed label' }, secondKey]
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
      expect(screen.getByRole('button', { name: 'Refresh passkeys' }).className).toContain('bg-primary');
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
      expect(screen.getByRole('button', { name: 'Refresh passkeys' }).className).toContain('bg-background');
      expect(screen.getByRole('button', { name: 'Add passkey' }).className).toContain('bg-background');
      if (kind === 'rename') {
        expect(screen.getByRole('heading', { name: 'Server-confirmed label' })).toBeTruthy();
        expect(screen.getByLabelText<HTMLInputElement>('Passkey name').value).toBe('Chosen label');
        expect(screen.getByRole('button', { name: 'Save passkey name' }).className).toContain('bg-background');
      }
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
