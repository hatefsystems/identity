import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { PortalProvider, usePortal } from '../app/dashboard/_components/portal-provider';
import { PortalClient } from '../app/_lib/portal/client';
import { PortalError } from '../app/_lib/portal/errors';
import { invalidateOtherTabs, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';

jest.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
  useRouter: () => ({ replace: jest.fn() }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));

// Model the browser's object-level exclusion faithfully: distinct channel
// objects in the SAME document receive one another's queued messages too.
class BrowserChannel {
  static instances = new Set<BrowserChannel>();
  static sent: unknown[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  closed = false;
  constructor(readonly name: string) {
    BrowserChannel.instances.add(this);
  }
  postMessage(data: unknown) {
    BrowserChannel.sent.push(data);
    for (const target of BrowserChannel.instances) {
      if (target === this || target.name !== this.name) continue;
      queueMicrotask(() => {
        if (!target.closed) target.onmessage?.({ data } as MessageEvent);
      });
    }
  }
  close() {
    this.closed = true;
    BrowserChannel.instances.delete(this);
  }
}

const profile = {
  id: 'user-id',
  email: 'private@example.test',
  display_name: 'Private',
  status: 'active',
  lifecycle_revision: '1',
  session: { id: 'session-id', expires_at: '2030-01-01T00:00:00Z' },
};
const api = { profile, bootstrap: jest.fn(), dispose: jest.fn(), logout: jest.fn() };
const channelDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'BroadcastChannel');
let visibility: PropertyDescriptor | undefined;
function PrivateContent() {
  return <p>{usePortal().profile.email}</p>;
}

beforeEach(() => {
  jest.clearAllMocks();
  BrowserChannel.sent = [];
  Object.defineProperty(globalThis, 'BroadcastChannel', {
    configurable: true,
    value: BrowserChannel,
  });
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  jest.mocked(PortalClient).mockImplementation(() => api as unknown as PortalClient);
  api.bootstrap.mockResolvedValue(profile);
  api.logout.mockRejectedValue(new PortalError('network_error', 0, true));
});
afterEach(() => {
  for (const instance of BrowserChannel.instances) instance.close();
  if (channelDescriptor) Object.defineProperty(globalThis, 'BroadcastChannel', channelDescriptor);
  else Reflect.deleteProperty(globalThis, 'BroadcastChannel');
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
});

it('publishes only invalidation notifications without echoing to document-local subscribers', async () => {
  const first = jest.fn();
  const second = jest.fn();
  const offFirst = onOtherTabInvalidation(first);
  const offSecond = onOtherTabInvalidation(second);
  const otherDocument = new BrowserChannel('hatef-portal-session');
  const peer = jest.fn();
  otherDocument.onmessage = peer;
  await act(async () => invalidateOtherTabs());
  expect(first).not.toHaveBeenCalled();
  expect(second).not.toHaveBeenCalled();
  expect(peer).toHaveBeenCalledTimes(1);
  expect(BrowserChannel.sent).toEqual(['invalidate']);
  await act(async () => otherDocument.postMessage('invalidate'));
  expect(first).toHaveBeenCalledTimes(1);
  expect(second).toHaveBeenCalledTimes(1);
  offFirst();
  offSecond();
  otherDocument.close();
});

it('keeps failed logout cleared despite faithful self-echo delivery, foreground events and peer invalidation until explicit reconciliation', async () => {
  render(
    <PortalProvider>
      <PrivateContent />
    </PortalProvider>
  );
  await screen.findByText(profile.email);
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  await waitFor(() =>
    expect(screen.getByRole('alert').textContent).toContain('Sign-out could not be confirmed')
  );
  await act(async () => Promise.resolve());
  expect(screen.queryByText(profile.email)).toBeNull();
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
  const peer = new BrowserChannel('hatef-portal-session');
  await act(async () => peer.postMessage('invalidate'));
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(screen.queryByText(profile.email)).toBeNull();
  expect(screen.getByRole('alert').textContent).toContain('Sign-out could not be confirmed');
  fireEvent.click(screen.getByRole('button', { name: 'Check current session' }));
  await screen.findByText(profile.email);
  expect(api.bootstrap).toHaveBeenCalledTimes(2);
});
