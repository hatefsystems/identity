import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
    expect((await screen.findByRole('alert')).textContent).toContain('may already have completed');
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
