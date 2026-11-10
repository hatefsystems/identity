jest.mock('next-intl/server', () => ({
  getTranslations: (...args: unknown[]) =>
    jest.requireActual('../i18n/testing').getTestTranslations(...args),
}));

import { act, fireEvent, render, screen, waitFor, within } from '../i18n/testing';
import { RecoveryPanel } from '../app/dashboard/_components/recovery-panel';
import { usePortal } from '../app/_components/portal-provider';
import { PortalClient } from '../app/_lib/portal/client';
import { StepUpGrant, type Profile, type RecoveryBatch } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { sensitiveClearEvent } from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

jest.mock('../app/_components/portal-provider', () => ({ usePortal: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));

const codes = ['ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567-89', '12345-6789A-BCDEF-GHJKM-NPQRS-TVWXY-Z0'];
const api = {
  assertSession: jest.fn(),
  recoveryStatus: jest.fn(),
  generateRecovery: jest.fn(),
  stepUpChallenge: jest.fn(),
  stepUpVerify: jest.fn(),
};
const clipboard = jest.fn();
const createURL = jest.fn();
const revokeURL = jest.fn();
let profile: Profile;
let visibility: PropertyDescriptor | undefined;
let click: jest.SpyInstance;
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
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: clipboard },
  });
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createURL });
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeURL });
});
beforeEach(() => {
  jest.resetAllMocks();
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  profile = {
    id: 'user-id',
    email: 'private@example.test',
    display_name: 'Account',
    status: 'active',
    deletion_enabled: false,
    lifecycle_revision: '1',
    session: { id: 'session-id', expires_at: new Date(Date.now() + 3600000).toISOString() },
  };
  jest.mocked(usePortal).mockReturnValue({
    profile,
    client: api as unknown as PortalClient,
    updateProfile: jest.fn(),
    signOut: jest.fn(),
    deleteAccount: jest.fn(),
    rememberStepUp: jest.fn(),
    reportPermissionLoss: jest.fn(),
    reportModerationInterruption: jest.fn(),
    reportLegalInterruption: jest.fn(),
  });
  api.assertSession.mockImplementation(() => profile);
  api.recoveryStatus.mockResolvedValue({ remaining: 2, low: true });
  api.generateRecovery.mockResolvedValue({ codes: [...codes], count: codes.length });
  api.stepUpChallenge.mockResolvedValue({
    methods: ['webauthn'],
    webauthn: { publicKey: { challenge: 'AA' } },
  });
  api.stepUpVerify.mockImplementation(
    async () =>
      new StepUpGrant(
        { token: 'fresh-grant', token_type: 'StepUp', expires_in: 60 },
        profile.session.id,
        Date.now(),
        Date.now() + 60000
      )
  );
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ response: 'credential' } as unknown as Awaited<
      ReturnType<typeof usePasskey>
    >);
  clipboard.mockResolvedValue(undefined);
  createURL.mockReturnValue('blob:http://localhost/private-random-id');
  click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
});
afterEach(() => {
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
  click.mockRestore();
  jest.useRealTimers();
});

async function startGeneration() {
  fireEvent.click(await screen.findByRole('button', { name: 'Replace recovery codes' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
}

async function generateView() {
  await startGeneration();
  await screen.findByTestId('recovery-viewer');
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
}

describe('one-time recovery viewer', () => {
  it.each([
    ['en', 0, 'Generate new recovery codes'],
    ['en', 2, 'Replace recovery codes'],
    ['fa-IR', 0, 'تولید کدهای بازیابی جدید'],
    ['fa-IR', 2, 'جایگزینی کدهای بازیابی'],
  ] as const)('labels generation from the known remaining count in %s (%i)', async (locale, remaining, label) => {
    api.recoveryStatus.mockResolvedValueOnce({ remaining, low: remaining < 3 });
    render(<RecoveryPanel />, { locale });
    const action = await screen.findByRole('button', { name: label });
    expect(api.generateRecovery).not.toHaveBeenCalled();
    fireEvent.click(action);
    expect(screen.getByRole('dialog', { name: label })).toBeTruthy();
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
  });

  it.each([
    ['en', 'Generate or replace recovery codes', 'Replace recovery codes', 'Refresh recovery status'],
    ['fa-IR', 'تولید یا جایگزینی کدهای بازیابی', 'جایگزینی کدهای بازیابی', 'تازه‌سازی وضعیت بازیابی'],
  ] as const)('keeps unknown/loading/failed status generation neutral in %s even after an earlier successful read', async (locale, neutral, replace, refresh) => {
    let reject: (error: PortalError) => void = () => undefined;
    api.recoveryStatus.mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail; }));
    render(<RecoveryPanel />, { locale });
    expect(screen.getByRole('button', { name: neutral })).toBeTruthy();
    await act(async () => reject(new PortalError('network_error')));
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.getByRole('button', { name: neutral })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: refresh }));
    await screen.findByRole('button', { name: replace });
    api.recoveryStatus.mockRejectedValueOnce(new PortalError('network_error'));
    fireEvent.click(screen.getByRole('button', { name: refresh }));
    expect(screen.getByRole('button', { name: neutral })).toBeTruthy();
    await screen.findByRole('alert');
    expect(screen.getByRole('button', { name: neutral })).toBeTruthy();
    expect(api.generateRecovery).not.toHaveBeenCalled();
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
  });

  it('reads only status before explicit warning and fresh verification; never auto-copies or downloads', async () => {
    const storage = jest.spyOn(Storage.prototype, 'setItem');
    render(<RecoveryPanel />);
    expect((await screen.findByTestId('recovery-status')).textContent).toContain(
      '2 unused codes remaining'
    );
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    expect(api.generateRecovery).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Replace recovery codes' }));
    const dialog = screen.getByRole('dialog', { name: 'Replace recovery codes' });
    expect(dialog.textContent).toContain('invalidates every previous recovery code');
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
    expect(api.generateRecovery).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Continue to verification' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
    const viewer = await screen.findByTestId('recovery-viewer');
    expect(
      within(viewer)
        .getAllByTestId('recovery-code')
        .map((element) => element.textContent)
    ).toEqual(codes);
    expect(api.generateRecovery).toHaveBeenCalledWith(
      expect.any(StepUpGrant),
      expect.any(AbortSignal)
    );
    expect(clipboard).not.toHaveBeenCalled();
    expect(createURL).not.toHaveBeenCalled();
    expect(storage).not.toHaveBeenCalled();
    storage.mockRestore();
    expect(viewer.textContent).toContain('does not erase your clipboard');
    expect(within(viewer).getAllByRole('button').map((button) => button.textContent)).toEqual([
      'Copy codes', 'Download codes', 'Done',
    ]);
    const details = within(viewer).getByText('Storage and clearing details').closest('details');
    expect(details?.open).toBe(false);
    expect(within(viewer).getAllByTestId('recovery-code').every((code) => !code.closest('details'))).toBe(true);
    expect(viewer.compareDocumentPosition(screen.getByText(/Recovery codes provide account recovery/)) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);
  });

  it('copies only on request, reports actual clipboard failure and never claims a failed copy succeeded', async () => {
    clipboard.mockRejectedValueOnce(new Error('private clipboard failure'));
    render(<RecoveryPanel />);
    await generateView();
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }));
    expect((await screen.findByRole('alert')).textContent).toContain('Copy failed');
    expect(screen.getByRole('alert').textContent).not.toContain('private clipboard failure');
    expect(clipboard).toHaveBeenCalledWith(`${codes.join('\n')}\n`);
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }));
    await waitFor(() =>
      expect(screen.getByText(/Codes copied\. Store them privately/)).toBeTruthy()
    );
    expect(clipboard).toHaveBeenCalledTimes(2);
  });

  it('downloads plaintext with a neutral filename, removes the link and promptly revokes object URLs', async () => {
    jest.useFakeTimers();
    let filename = '';
    let href = '';
    click.mockImplementation(function (this: HTMLAnchorElement) {
      filename = this.download;
      href = this.href;
    });
    render(<RecoveryPanel />);
    await generateView();
    fireEvent.click(screen.getByRole('button', { name: 'Download codes' }));
    expect(filename).toBe('recovery-codes.txt');
    expect(href).toBe('blob:http://localhost/private-random-id');
    expect(document.querySelector('a[download]')).toBeNull();
    const blob = createURL.mock.calls[0][0] as Blob;
    expect(blob.type).toBe('text/plain;charset=utf-8');
    expect(blob.size).toBe(`${codes.join('\n')}\n`.length);
    expect(screen.getByText(/Download requested\. Check your browser downloads/)).toBeTruthy();
    expect(revokeURL).not.toHaveBeenCalled();
    act(() => jest.advanceTimersByTime(1000));
    expect(revokeURL).toHaveBeenCalledWith(href);
  });

  it('reports download creation failure without leaking the thrown detail', async () => {
    createURL.mockImplementationOnce(() => {
      throw new Error('sensitive export error');
    });
    render(<RecoveryPanel />);
    await generateView();
    fireEvent.click(screen.getByRole('button', { name: 'Download codes' }));
    expect(screen.getByRole('alert').textContent).toContain('download could not be started');
    expect(screen.getByRole('alert').textContent).not.toContain('sensitive export error');
    expect(click).not.toHaveBeenCalled();
  });

  it.each([2000, 3600000])(
    'clears by the earlier of five minutes and session expiry (%i ms)',
    async (sessionLifetime) => {
      jest.useFakeTimers();
      profile.session.expires_at = new Date(Date.now() + sessionLifetime).toISOString();
      render(<RecoveryPanel />);
      await generateView();
      act(() => jest.advanceTimersByTime(Math.min(sessionLifetime, 300000) + 1));
      expect(screen.queryByTestId('recovery-viewer')).toBeNull();
      expect(screen.queryByText(codes[0])).toBeNull();
      expect(clipboard).not.toHaveBeenCalled();
    }
  );

  it.each(['pagehide', 'popstate', sensitiveClearEvent])(
    'clears on %s and does not redisplay after bfcache restoration',
    async (eventName) => {
      render(<RecoveryPanel />);
      await generateView();
      fireEvent(window, new Event(eventName));
      expect(screen.queryByTestId('recovery-viewer')).toBeNull();
      fireEvent(window, new PageTransitionEvent('pageshow', { persisted: true }));
      expect(screen.queryByText(codes[0])).toBeNull();
      expect(api.generateRecovery).toHaveBeenCalledTimes(1);
    }
  );

  it('clears on backgrounding, Done, and session loss before export, without background polling', async () => {
    render(<RecoveryPanel />);
    await generateView();
    const reads = api.recoveryStatus.mock.calls.length;
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    fireEvent(document, new Event('visibilitychange'));
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    expect(api.recoveryStatus).toHaveBeenCalledTimes(reads);
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    fireEvent(document, new Event('visibilitychange'));
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    await generateView();
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    await generateView();
    api.assertSession.mockImplementationOnce(() => {
      throw new PortalError('session_required', 401);
    });
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }));
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    expect(clipboard).not.toHaveBeenCalled();
  });

  it('discards late generation after cancellation/unmount and late clipboard completion after Done', async () => {
    let finish!: (value: RecoveryBatch) => void;
    api.generateRecovery.mockReturnValueOnce(
      new Promise((resolve) => {
        finish = resolve;
      })
    );
    const view = render(<RecoveryPanel />);
    await startGeneration();
    await waitFor(() => expect(api.generateRecovery).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('alert').textContent).toContain(
      'Previous recovery codes may already be invalid'
    );
    view.unmount();
    await act(async () => finish({ codes: [...codes], count: 2 }));
    render(<RecoveryPanel />);
    await generateView();
    let copied!: () => void;
    clipboard.mockReturnValueOnce(
      new Promise<void>((resolve) => {
        copied = resolve;
      })
    );
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }));
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    await act(async () => copied());
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    expect(screen.queryByText(/Codes copied\./)).toBeNull();
  });

  it('treats a lost response as uncertain replacement, never regenerates silently and requires another explicit verification', async () => {
    api.generateRecovery.mockRejectedValueOnce(new PortalError('network_error', 0, true));
    render(<RecoveryPanel />);
    await startGeneration();
    await waitFor(() =>
      expect(within(screen.getByRole('dialog')).getByRole('alert').textContent).toContain(
        'Previous recovery codes may already be invalid'
      )
    );
    expect(api.generateRecovery).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId('recovery-viewer')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Start new verification' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Verify with a passkey' }));
    await screen.findByTestId('recovery-viewer');
    expect(api.stepUpVerify).toHaveBeenCalledTimes(2);
    expect(api.generateRecovery).toHaveBeenCalledTimes(2);
    expect(api.generateRecovery.mock.calls[0][0]).not.toBe(api.generateRecovery.mock.calls[1][0]);
  });
});

it('keeps one-time bytes and the original five-minute deadline when language, calendar and time zone change', async () => {
  jest.useFakeTimers();
  const { I18nTestProvider } = await import('../i18n/testing');
  const view = (locale: 'en' | 'fa-IR') => (
    <I18nTestProvider
      locale={locale}
      preferences={{
        calendar: locale === 'en' ? 'gregory' : 'persian',
        timeZone: locale === 'en' ? 'UTC' : 'Asia/Tehran',
      }}
    >
      <RecoveryPanel />
    </I18nTestProvider>
  );
  const result = render(view('en'));
  await generateView();
  const originalNodes = screen.getAllByTestId('recovery-code');
  const details = screen.getByText('Storage and clearing details').closest('details');
  if (details) details.open = true;
  const originalStatusReads = api.recoveryStatus.mock.calls.length;
  act(() => jest.advanceTimersByTime(299000));
  result.rerender(view('fa-IR'));
  expect(
    screen.getByRole('heading', { name: 'کدهای بازیابی جدید خود را ذخیره کنید' })
  ).toBeTruthy();
  const currentNodes = screen.getAllByTestId('recovery-code');
  expect(currentNodes[0]).toBe(originalNodes[0]);
  expect(screen.getByText('جزئیات نگهداری و پاک‌کردن کدها').closest('details')).toBe(details);
  expect(details?.open).toBe(true);
  expect(currentNodes.map((item) => item.textContent)).toEqual(codes);
  fireEvent.click(screen.getByRole('button', { name: 'کپی کدها' }));
  await act(async () => undefined);
  expect(clipboard).toHaveBeenCalledWith(`${codes.join('\n')}\n`);
  expect(api.generateRecovery).toHaveBeenCalledTimes(1);
  expect(api.stepUpChallenge).toHaveBeenCalledTimes(1);
  expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
  expect(api.recoveryStatus).toHaveBeenCalledTimes(originalStatusReads);
  act(() => jest.advanceTimersByTime(1001));
  expect(screen.queryByTestId('recovery-viewer')).toBeNull();
  expect(
    screen.getByText(
      'مهلت نمایش یک‌باره پایان یافت. کدهای ذخیره‌شده تا زمان استفاده یا جایگزینی معتبر می‌مانند.'
    )
  ).toBeTruthy();
});
