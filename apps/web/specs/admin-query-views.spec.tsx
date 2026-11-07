import { TextEncoder } from 'node:util';
import { act, fireEvent, render, screen, within } from '../i18n/testing';
import { renderToStaticMarkup } from 'react-dom/server';
import { I18nTestProvider } from '../i18n/testing';
import { UsersView } from '../app/admin/_components/users-view';
import { AuditView, auditCursorHistoryLimit } from '../app/admin/_components/audit-view';
import { IntegrityView } from '../app/admin/_components/integrity-view';
import { auditQueryDefaults, auditQueryFromDraft } from '../app/admin/_components/audit-query-form';
import { queryPageSize } from '../app/admin/_components/query-view-state';
import { usePortal } from '../app/_components/portal-provider';
import { AdminClient } from '../app/_lib/admin/client';
import type {
  AdminAuditLog,
  AdminAuditPage,
  AdminCapabilities,
  AdminLookupPage,
  AdminUser,
  AdminUsersPage,
  AdminVerification,
} from '../app/_lib/admin/contracts';
import type { PortalClient } from '../app/_lib/portal/client';
import type { Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { sensitiveClearEvent, sensitiveSuspendEvent } from '../app/_lib/portal/invalidation';

jest.mock('../app/_components/portal-provider', () => ({ usePortal: jest.fn() }));
jest.mock('../app/_lib/admin/client', () => ({ AdminClient: jest.fn() }));
jest.mock('next/navigation', () => ({
  usePathname: () => '/admin/users',
  useRouter: () => ({ replace: jest.fn() }),
}));

const limits = {
  page_size_default: 2,
  page_size_max: 5,
  audit_max_window_seconds: 31 * 86400,
  chain_verify_max_limit: 2,
};
const noFlags: AdminCapabilities['capabilities'] = {
  users_read: false,
  users_pii: false,
  users_lookup: false,
  users_status_write: false,
  audit_logs_read: false,
  audit_chain_verify: false,
  ledger_verify: false,
  legal_holds_read: false,
  legal_holds_apply: false,
  legal_holds_release: false,
  preservation_requests_create: false,
  legal_inquiry_lookup: false,
};
const allFlags: AdminCapabilities['capabilities'] = {
  users_read: true,
  users_pii: true,
  users_lookup: true,
  users_status_write: true,
  audit_logs_read: true,
  audit_chain_verify: true,
  ledger_verify: true,
  legal_holds_read: false,
  legal_holds_apply: false,
  legal_holds_release: false,
  preservation_requests_create: false,
  legal_inquiry_lookup: false,
};
const profile: Profile = {
  id: '00000000-0000-4000-8000-000000000099',
  email: 'operator@example.test',
  display_name: 'Operator',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '1',
  session: { id: 'private-session', expires_at: '2030-01-01T00:00:00Z' },
};
const api = {
  users: jest.fn(),
  lookup: jest.fn(),
  auditLogs: jest.fn(),
  verify: jest.fn(),
  user: jest.fn(),
};
const portal = {} as PortalClient;
const reportPermissionLoss = jest.fn();
const signOut = jest.fn();
const maximum = '9223372036854775807';
const high = '9007199254740993';
const seed = '5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb';
const ledgerSeed = '6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54';
const hash = 'b'.repeat(64);
const lastHash = 'c'.repeat(64);
const auditScope =
  'database_relative_chain_and_retained_leaves; not complete ingestion, independent historical authenticity, or legal authorization';
const ledgerScope =
  'database_relative_chain_retained_leaves_and_erasure_annotations; annotations do not prove receipt chaining or legal authorization; not complete ingestion or independent historical authenticity';
const now = Date.parse('2026-10-28T12:00:00Z');

function context(flags = allFlags, effectiveLimits = limits, currentProfile = profile) {
  jest.mocked(usePortal).mockReturnValue({
    client: portal,
    profile: currentProfile,
    capabilities: { capabilities: flags, limits: effectiveLimits },
    reportPermissionLoss,
    signOut,
    updateProfile: jest.fn(),
    deleteAccount: jest.fn(),
    rememberStepUp: jest.fn(),
    reportModerationInterruption: jest.fn(),
    reportLegalInterruption: jest.fn(),
  });
}
function account(index: number, overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    email: `account${index}@example.test`,
    status: 'active',
    lifecycle_revision: high,
    is_mfa_enabled: false,
    created_at: '2026-10-27T10:00:00Z',
    updated_at: null,
    deleted_at: null,
    ...overrides,
  };
}
function accounts(items: AdminUser[], total = items.length, offset = 0, limit = 2): AdminUsersPage {
  return { items, total, offset, limit };
}
function log(seq = high, overrides: Partial<AdminAuditLog> = {}): AdminAuditLog {
  return {
    id: '00000000-0000-4000-8000-000000000011',
    seq,
    actor_id: profile.id,
    actor_spiffe_id: 'spiffe://test/service',
    user_id: null,
    event_type: 'user.login',
    action_status: 'success',
    client_ip: '203.0.113.5',
    user_agent: 'Untrusted browser',
    payload:
      '{"untrusted":"<img src=x onerror=alert(1)><script>alert(1)</script><a href=javascript:alert(1)>link</a> https://example.test"}',
    timestamp: '2026-10-28T10:00:00Z',
    sha256_leaf_hash: seed,
    sha256_chain_hash: hash,
    ...overrides,
  };
}
function auditPage(seq = high, has_more = false, row = log(seq)): AdminAuditPage {
  return { items: [row], limit: 1, has_more, next_before_seq: seq };
}
function proof(overrides: Partial<AdminVerification> = {}): AdminVerification {
  return {
    chain: 'audit',
    after_seq: '0',
    through_seq: maximum,
    seed_hash: seed,
    seed_source: 'genesis',
    scope: auditScope,
    last_hash: hash,
    complete: false,
    verified: true,
    checked: 2,
    first_seq: '2',
    last_seq: high,
    broken_at_seq: null,
    expected_hash: null,
    stored_hash: null,
    next_after_seq: high,
    ...overrides,
  } as AdminVerification;
}
function completeProof(overrides: Partial<AdminVerification> = {}): AdminVerification {
  return proof({
    after_seq: high,
    seed_source: 'supplied_predecessor',
    seed_hash: hash,
    checked: 1,
    first_seq: maximum,
    last_seq: maximum,
    last_hash: lastHash,
    complete: true,
    next_after_seq: maximum,
    ...overrides,
  });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((finish, fail) => {
    resolve = finish;
    reject = fail;
  });
  return { promise, resolve, reject };
}
const button = (name: string) => screen.getByRole<HTMLButtonElement>('button', { name });
function submitAudit() {
  fireEvent.submit(screen.getByRole('form', { name: 'Search audit logs' }));
}
function submitAccounts() {
  fireEvent.submit(screen.getByRole('form', { name: 'Filter accounts' }));
}
const encoderDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder');
let visibility: PropertyDescriptor | undefined;

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
    configurable: true,
    value: jest.fn(),
  });
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
  jest.resetAllMocks();
  jest.spyOn(Date, 'now').mockReturnValue(now);
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  context();
  jest.mocked(AdminClient).mockImplementation(() => api as unknown as AdminClient);
  api.users.mockResolvedValue(accounts([account(1), account(2)]));
  api.lookup.mockResolvedValue({
    ...accounts([account(3)], 1, 0, 1),
    canonical_email: 'account3@example.test',
  });
  api.auditLogs.mockResolvedValue(auditPage());
  api.verify.mockResolvedValue(proof());
});
afterEach(() => {
  jest.restoreAllMocks();
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
});
afterAll(() => {
  if (encoderDescriptor) Object.defineProperty(globalThis, 'TextEncoder', encoderDescriptor);
  else Reflect.deleteProperty(globalThis, 'TextEncoder');
});

describe('admin query presentation gates', () => {
  it.each([
    ['Support', { ...noFlags, users_read: true }],
    [
      'Moderator',
      {
        ...noFlags,
        users_read: true,
        users_pii: true,
        users_lookup: true,
        users_status_write: true,
      },
    ],
    ['DPO', { ...noFlags, audit_logs_read: true, audit_chain_verify: true, ledger_verify: true }],
    ['Super Admin', { ...noFlags, audit_chain_verify: true, ledger_verify: true }],
    ['Combined', allFlags],
    ['None', noFlags],
  ] as const)(
    'exposes only capability-granted forms for %s and never fetches on mount',
    (_role, flags) => {
      context(flags);
      render(
        <>
          <UsersView />
          <AuditView />
          <IntegrityView />
        </>
      );
      expect(Boolean(screen.queryByRole('form', { name: 'Filter accounts' }))).toBe(
        flags.users_read
      );
      expect(Boolean(screen.queryByLabelText('Exact email'))).toBe(
        flags.users_pii && flags.users_lookup && flags.users_read
      );
      expect(Boolean(screen.queryByRole('form', { name: 'Search audit logs' }))).toBe(
        flags.audit_logs_read
      );
      expect(Boolean(screen.queryByLabelText('Chain'))).toBe(
        flags.audit_chain_verify || flags.ledger_verify
      );
      expect(AdminClient).not.toHaveBeenCalled();
    }
  );

  it.each([UsersView, AuditView, IntegrityView])(
    'has no privileged form or values in the initial server shell (%p)',
    (View) => {
      const { PortalProvider } = jest.requireActual<
        typeof import('../app/_components/portal-provider')
      >('../app/_components/portal-provider');
      const html = renderToStaticMarkup(
        <I18nTestProvider>
          <PortalProvider surface="admin">
            <View />
          </PortalProvider>
        </I18nTestProvider>
      );
      expect(html).toContain('Checking your secure browser session and administrative access');
      expect(html).not.toContain('<form');
      expect(html).not.toContain(profile.email);
      expect(html).not.toContain('datetime-local');
      expect(AdminClient).not.toHaveBeenCalled();
    }
  );

  it('withholds every query when capability discovery has not been supplied', () => {
    jest
      .mocked(usePortal)
      .mockReturnValue({ ...jest.mocked(usePortal)(), capabilities: undefined });
    render(
      <>
        <UsersView />
        <AuditView />
        <IntegrityView />
      </>
    );
    expect(screen.queryByRole('button')).toBeNull();
    expect(AdminClient).not.toHaveBeenCalled();
  });
});

describe('bounded accounts and exact lookup', () => {
  it('keeps Support free of email even if returned, and uses bounded server offsets', async () => {
    context({ ...noFlags, users_read: true });
    api.users
      .mockResolvedValueOnce(accounts([account(1), account(2)], 3))
      .mockResolvedValueOnce(accounts([account(3)], 3, 2));
    render(<UsersView />);
    submitAccounts();
    await screen.findByRole('link', { name: `View account ${account(1).id}` });
    expect(api.users).toHaveBeenCalledWith({ limit: 2, offset: 0 }, expect.any(AbortSignal));
    expect(screen.queryByRole('columnheader', { name: 'Email' })).toBeNull();
    expect(screen.queryByText('account1@example.test')).toBeNull();
    expect(screen.queryByLabelText('Exact email')).toBeNull();
    expect(button('Previous page').disabled).toBe(true);
    fireEvent.click(button('Next page'));
    await screen.findByRole('link', { name: `View account ${account(3).id}` });
    expect(api.users).toHaveBeenLastCalledWith({ limit: 2, offset: 2 }, expect.any(AbortSignal));
    expect(button('Next page').disabled).toBe(true);
    expect(screen.getByText('3-3 of 3 matching accounts')).toBeTruthy();
    expect(
      screen.getByRole('region', { name: 'Account results, horizontally scrollable' }).className
    ).toContain('overflow-x-auto');
    expect(api.lookup).not.toHaveBeenCalled();
  });

  it('validates page bounds and changes status without fetching until explicit submission', async () => {
    render(<UsersView />);
    fireEvent.change(screen.getByLabelText('Page size'), { target: { value: '6' } });
    submitAccounts();
    expect(screen.getByRole('alert').textContent).toContain('1 to 5');
    expect(document.activeElement).toBe(screen.getByLabelText('Page size'));
    expect(api.users).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Page size'), { target: { value: '1' } });
    fireEvent.change(screen.getByLabelText('Account status'), { target: { value: 'banned' } });
    expect(api.users).not.toHaveBeenCalled();
    api.users.mockResolvedValueOnce(accounts([account(1, { status: 'banned' })], 1, 0, 1));
    submitAccounts();
    await screen.findByRole('table');
    expect(api.users).toHaveBeenCalledWith(
      { limit: 1, offset: 0, status: 'banned' },
      expect.any(AbortSignal)
    );
    expect(button('Next page').disabled).toBe(true);
    expect(queryPageSize('2\n', 5)).toBeNull();
    expect(queryPageSize('2147483647', 5)).toBeNull();
  });

  it('sends lookup only through the explicit body-only method and clears its query and late result', async () => {
    const late = deferred<AdminLookupPage>();
    api.lookup.mockReturnValueOnce(late.promise);
    render(<UsersView />);
    const input = screen.getByLabelText<HTMLInputElement>('Exact email');
    expect(input.type).toBe('text');
    expect(input.inputMode).toBe('email');
    expect(input.hasAttribute('maxlength')).toBe(false);
    fireEvent.change(input, { target: { value: ' person@example.test ' } });
    expect(api.lookup).not.toHaveBeenCalled();
    const form = screen.getByRole('form', { name: 'Exact email lookup' });
    expect(form.getAttribute('method')).toBe('post');
    fireEvent.submit(form);
    expect(api.lookup).toHaveBeenCalledWith(' person@example.test ', expect.any(AbortSignal));
    const signal = api.lookup.mock.calls[0][1] as AbortSignal;
    fireEvent.click(button('Clear lookup'));
    expect(input.value).toBe('');
    expect(signal.aborted).toBe(true);
    await act(async () =>
      late.resolve({
        ...accounts([account(3, { email: 'person@example.test' })], 1, 0, 1),
        canonical_email: 'person@example.test',
      })
    );
    expect(screen.queryByRole('table')).toBeNull();
    expect(window.location.search).not.toContain('person');
    expect(api.users).not.toHaveBeenCalled();
  });

  it('rejects an oversized UTF-8 lookup without a request', () => {
    render(<UsersView />);
    fireEvent.change(screen.getByLabelText('Exact email'), {
      target: { value: `${'\u00e9'.repeat(512)}@test.test` },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Exact email lookup' }));
    expect(screen.getByRole('alert').textContent).toContain('254 UTF-8 bytes');
    expect(api.lookup).not.toHaveBeenCalled();
  });

  it('displays the backend canonical Unicode email in bidi isolation and clears it with the result', async () => {
    const canonical = '\u00fcser@xn--bcher-kva.test';
    const raw = ' U\u0308SER@B\u00dcCHER.test ';
    api.lookup.mockResolvedValueOnce({
      ...accounts([account(3, { email: canonical })], 1, 0, 1),
      canonical_email: canonical,
    });
    render(<UsersView />);
    fireEvent.change(screen.getByLabelText('Exact email'), { target: { value: raw } });
    expect(api.lookup).not.toHaveBeenCalled();
    fireEvent.submit(screen.getByRole('form', { name: 'Exact email lookup' }));
    await screen.findByRole('table');
    expect(api.lookup).toHaveBeenCalledWith(raw, expect.any(AbortSignal));
    for (const address of screen.getAllByText(canonical)) expect(address.tagName).toBe('BDI');
    fireEvent.click(button('Clear lookup'));
    expect(screen.queryByText(canonical)).toBeNull();
  });

  it('ignores stale account responses after a replacement status query', async () => {
    const stale = deferred<AdminUsersPage>();
    api.users
      .mockReturnValueOnce(stale.promise)
      .mockResolvedValueOnce(accounts([account(3, { status: 'banned' })]));
    render(<UsersView />);
    submitAccounts();
    const signal = api.users.mock.calls[0][1] as AbortSignal;
    fireEvent.change(screen.getByLabelText('Account status'), { target: { value: 'banned' } });
    submitAccounts();
    await screen.findByRole('link', { name: `View account ${account(3).id}` });
    expect(signal.aborted).toBe(true);
    await act(async () => stale.resolve(accounts([account(1), account(2)])));
    expect(screen.queryByRole('link', { name: `View account ${account(1).id}` })).toBeNull();
    expect(screen.getByRole('link', { name: `View account ${account(3).id}` })).toBeTruthy();
  });

  it('withholds an old page on service failure rather than presenting an empty result', async () => {
    api.users
      .mockResolvedValueOnce(accounts([account(1)]))
      .mockRejectedValueOnce(new PortalError('audit_unavailable', 503));
    render(<UsersView />);
    submitAccounts();
    await screen.findByRole('table');
    submitAccounts();
    expect((await screen.findByRole('alert')).textContent).toContain('not an empty result');
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.queryByText(/No accounts returned/)).toBeNull();
  });

  it('discards the old account request and draft when the session changes', async () => {
    const late = deferred<AdminLookupPage>();
    api.lookup.mockReturnValueOnce(late.promise);
    const view = render(<UsersView />);
    fireEvent.change(screen.getByLabelText('Exact email'), {
      target: { value: 'private@example.test' },
    });
    fireEvent.submit(screen.getByRole('form', { name: 'Exact email lookup' }));
    context(allFlags, limits, {
      ...profile,
      session: { ...profile.session, id: 'replacement-session' },
    });
    view.rerender(<UsersView />);
    expect((api.lookup.mock.calls[0][1] as AbortSignal).aborted).toBe(true);
    expect(screen.getByLabelText<HTMLInputElement>('Exact email').value).toBe('');
    await act(async () =>
      late.resolve({
        ...accounts([account(3, { email: 'private@example.test' })], 1, 0, 1),
        canonical_email: 'private@example.test',
      })
    );
    expect(screen.queryByRole('table')).toBeNull();
  });
});

describe('UTC audit query and bounded keyset navigation', () => {
  it.each([31 * 86400, 3600, 0.5, 0.0000001])(
    'bounds its last-24-hours default by %p configured seconds',
    (maximumWindow) => {
      const effective = { ...limits, audit_max_window_seconds: maximumWindow };
      const draft = auditQueryDefaults(effective, now);
      const result = auditQueryFromDraft(draft, effective);
      expect(result.error).toBeUndefined();
      expect(result.query?.end_time).toBe('2026-10-28T12:00:00.000Z');
      if (!result.query) throw new Error('The bounded default must be a valid query.');
      const duration = Date.parse(result.query.end_time) - Date.parse(result.query.start_time);
      expect(duration).toBeLessThanOrEqual(Math.min(86400, maximumWindow) * 1000);
    }
  );

  it('validates UTC ordering, configured window, event syntax and page bounds with focused errors', () => {
    const draft = auditQueryDefaults(limits, now);
    for (const [patch, field] of [
      [{ start: '2026-02-30T00:00' }, 'start'],
      [{ start: '2026-10-28T12:00:00Z' }, 'start'],
      [{ end: '2026-10-26T00:00' }, 'end'],
      [{ start: '2026-01-01T00:00' }, 'start'],
      [{ event: 'User.login' }, 'event'],
      [{ event: 'x'.repeat(101) }, 'event'],
      [{ size: '0' }, 'size'],
      [{ size: '6' }, 'size'],
    ] as const)
      expect(auditQueryFromDraft({ ...draft, ...patch }, limits).error?.field).toBe(field);
    render(<AuditView />);
    fireEvent.change(screen.getByLabelText('End time (UTC)'), {
      target: { value: '2026-10-26T00:00' },
    });
    expect(api.auditLogs).not.toHaveBeenCalled();
    submitAudit();
    expect(screen.getByRole('alert').textContent).toContain('at or after');
    expect(document.activeElement).toBe(screen.getByLabelText('End time (UTC)'));
    expect(api.auditLogs).not.toHaveBeenCalled();
  });

  it('freezes submitted UTC/event/page filters and uses exact descending cursors without offsets or totals', async () => {
    api.auditLogs
      .mockResolvedValueOnce(auditPage(high, true))
      .mockResolvedValueOnce(auditPage('3'))
      .mockResolvedValueOnce(auditPage(high, true));
    render(<AuditView />);
    fireEvent.change(screen.getByLabelText('Page size'), { target: { value: '1' } });
    fireEvent.change(screen.getByLabelText('Event type (exact)'), {
      target: { value: 'user.login' },
    });
    expect(api.auditLogs).not.toHaveBeenCalled();
    submitAudit();
    await screen.findByText(high);
    const query = {
      start_time: '2026-10-27T12:00:00.000Z',
      end_time: '2026-10-28T12:00:00.000Z',
      event_type: 'user.login',
      limit: 1,
    };
    expect(api.auditLogs).toHaveBeenNthCalledWith(1, query, expect.any(AbortSignal));
    expect(button('Newer records').disabled).toBe(true);
    fireEvent.click(button('Older records'));
    await screen.findByText('3');
    expect(api.auditLogs).toHaveBeenNthCalledWith(
      2,
      { ...query, before_seq: high },
      expect.any(AbortSignal)
    );
    expect(button('Older records').disabled).toBe(true);
    fireEvent.click(button('Newer records'));
    await screen.findByText(high);
    expect(api.auditLogs).toHaveBeenNthCalledWith(3, query, expect.any(AbortSignal));
    expect(screen.getByText('1 record on this page. No total is calculated.')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Event type (exact)'), {
      target: { value: 'user.logout' },
    });
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.queryByRole('navigation', { name: 'Audit cursor pagination' })).toBeNull();
    expect(api.auditLogs).toHaveBeenCalledTimes(3);
  });

  it('retains at most the bounded cursor history and rereads pages instead of caching payloads', async () => {
    api.auditLogs.mockImplementation(async (query) => {
      const seq = query.before_seq ? String(BigInt(query.before_seq) - 1n) : '1000';
      return auditPage(seq, true);
    });
    render(<AuditView />);
    submitAudit();
    await screen.findByText('1000');
    for (let index = 1; index <= auditCursorHistoryLimit + 1; index++) {
      fireEvent.click(button('Older records'));
      await screen.findByText(String(1000 - index));
    }
    expect(screen.getByText(/Earlier cursor history was discarded/)).toBeTruthy();
    for (let index = 1; index < auditCursorHistoryLimit; index++) {
      fireEvent.click(button('Newer records'));
      await screen.findByText(String(1000 - auditCursorHistoryLimit - 1 + index));
    }
    expect(button('Newer records').disabled).toBe(true);
    expect(api.auditLogs).toHaveBeenCalledTimes(auditCursorHistoryLimit * 2 + 1);
    expect(screen.getAllByTestId('admin-audit-row')).toHaveLength(1);
  });

  it('ignores stale success and failure after replacement and clears affected records', async () => {
    const old = deferred<AdminAuditPage>();
    api.auditLogs.mockReturnValueOnce(old.promise).mockResolvedValueOnce(auditPage('3'));
    render(<AuditView />);
    submitAudit();
    fireEvent.change(screen.getByLabelText('Event type (exact)'), {
      target: { value: 'user.logout' },
    });
    submitAudit();
    await screen.findByText('3');
    expect((api.auditLogs.mock.calls[0][1] as AbortSignal).aborted).toBe(true);
    await act(async () => old.reject(new PortalError('forbidden', 403)));
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(reportPermissionLoss).not.toHaveBeenCalled();
    fireEvent.click(button('Clear query'));
    expect(screen.getByLabelText<HTMLInputElement>('Event type (exact)').value).toBe('');
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('discloses details explicitly as inert text, contains overflow, and restores dialog focus', async () => {
    const row = log();
    render(<AuditView />);
    submitAudit();
    const open = await screen.findByRole('button', { name: `View details for sequence ${high}` });
    expect(screen.queryByText(row.payload)).toBeNull();
    expect(screen.queryByText(row.client_ip)).toBeNull();
    expect(screen.queryByText(row.actor_id)).toBeNull();
    const frame = screen.getByRole('region', { name: 'Audit results, horizontally scrollable' });
    jest.mocked(frame.scrollIntoView).mockClear();
    frame.focus();
    expect(frame.scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', inline: 'nearest' });
    expect(frame.className).toContain('scroll-m-2');
    open.focus();
    fireEvent.click(open);
    const dialog = screen.getByRole('dialog', { name: 'Audit record details' });
    expect(within(dialog).getByLabelText('Audit payload text').textContent).toBe(row.payload);
    expect(dialog.querySelector('script, img, a')).toBeNull();
    expect(within(dialog).getByText(row.sha256_chain_hash)).toBeTruthy();
    expect(within(dialog).getByText(/Stored hashes are record fields, not proof/)).toBeTruthy();
    expect(
      screen.getByRole('region', { name: 'Audit results, horizontally scrollable' }).className
    ).toContain('overflow-x-auto');
    expect(button('Close details').className).toContain('min-h-11');
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(button('Close details'));
    fireEvent(dialog, new Event('cancel', { cancelable: true }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(open);
    expect(api.user).not.toHaveBeenCalled();
  });

  it.each([
    new PortalError('audit_unavailable', 503),
    new PortalError('server_error', 500),
    new PortalError('invalid_response'),
    new PortalError('rate_limited', 429, false, 42),
  ])('withholds failed query results rather than calling them empty (%p)', async (failure) => {
    api.auditLogs.mockRejectedValueOnce(failure);
    render(<AuditView />);
    submitAudit();
    await screen.findByRole('alert');
    expect(screen.queryByText(/No audit records matched/)).toBeNull();
    expect(screen.queryByRole('table')).toBeNull();
    if (failure.status === 429)
      expect(screen.getByRole('alert').textContent).toContain('Wait 42 seconds');
    expect(api.auditLogs).toHaveBeenCalledTimes(1);
  });
});

describe('honest independent canonical-v2 verification', () => {
  it('walks an explicit fixed-bound run across sequence gaps and ignores a completed response cursor', async () => {
    api.verify.mockResolvedValueOnce(proof()).mockResolvedValueOnce(completeProof());
    render(<IntegrityView />);
    expect(api.verify).not.toHaveBeenCalled();
    expect(button('Continue verification').disabled).toBe(true);
    fireEvent.click(button('Start new run'));
    await screen.findByText('Clean partial segment. Verification is not complete.');
    expect(api.verify).toHaveBeenNthCalledWith(
      1,
      'audit',
      { after_seq: '0', limit: 2 },
      expect.any(AbortSignal)
    );
    expect(screen.getByTestId('verification-bound').textContent).toBe(maximum);
    expect(screen.queryByText(/Verification complete for/)).toBeNull();
    expect(api.verify).toHaveBeenCalledTimes(1);
    fireEvent.click(button('Continue verification'));
    await screen.findByText('Verification complete for the captured database-relative range.');
    expect(api.verify).toHaveBeenNthCalledWith(
      2,
      'audit',
      { after_seq: high, through_seq: maximum, predecessor_hash: hash, limit: 2 },
      expect.any(AbortSignal)
    );
    expect(button('Continue verification').disabled).toBe(true);
    expect(button('Stop verification').disabled).toBe(true);
    expect(screen.getByText(auditScope)).toBeTruthy();
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(api.auditLogs).not.toHaveBeenCalled();
    expect(api.users).not.toHaveBeenCalled();
    expect(api.verify).toHaveBeenCalledTimes(2);
  });

  it('caps work at 1000 even with a larger configured maximum', async () => {
    context(allFlags, { ...limits, chain_verify_max_limit: 5000 });
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    await screen.findByTestId('verification-page');
    expect(api.verify).toHaveBeenCalledWith(
      'audit',
      { after_seq: '0', limit: 1000 },
      expect.any(AbortSignal)
    );
  });

  it('starts ledger independently and discards an old-chain reply; fully erased payloads are not recomputed', async () => {
    const old = deferred<AdminVerification>();
    api.verify.mockReturnValueOnce(old.promise).mockResolvedValueOnce(
      proof({
        chain: 'ledger',
        seed_hash: ledgerSeed,
        scope: ledgerScope,
        erased_checked: 2,
        through_seq: '6',
        first_seq: '3',
        last_seq: '6',
        next_after_seq: '6',
        complete: true,
      })
    );
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    fireEvent.change(screen.getByLabelText('Chain'), { target: { value: 'ledger' } });
    expect((api.verify.mock.calls[0][2] as AbortSignal).aborted).toBe(true);
    fireEvent.click(button('Start new run'));
    await screen.findByText('Verification complete for the captured database-relative range.');
    expect(api.verify).toHaveBeenLastCalledWith(
      'ledger',
      { after_seq: '0', limit: 2 },
      expect.any(AbortSignal)
    );
    expect(
      screen.getByText(/Retained payloads recomputed: 0 on the last clean page; 0 cumulative/)
    ).toBeTruthy();
    expect(screen.getByText(/a subset of 2 checked chain nodes, not extra work/)).toBeTruthy();
    expect(screen.getByText(/original bodies cannot be recomputed/)).toBeTruthy();
    await act(async () => old.resolve(proof()));
    expect(screen.getByTestId('verification-bound').textContent).toBe('6');
    expect(screen.getByText(ledgerScope)).toBeTruthy();
    expect(api.auditLogs).not.toHaveBeenCalled();
  });

  it.each(['audit', 'ledger'] as const)(
    'presents empty %s genesis neutrally, without claiming payload verification',
    async (chain) => {
      const genesis = chain === 'audit' ? seed : ledgerSeed;
      api.verify.mockResolvedValueOnce(
        proof({
          ...(chain === 'audit'
            ? { chain, scope: auditScope }
            : { chain, scope: ledgerScope, erased_checked: 0 }),
          seed_hash: genesis,
          through_seq: '0',
          checked: 0,
          first_seq: null,
          last_seq: null,
          last_hash: genesis,
          next_after_seq: null,
          complete: true,
        })
      );
      render(<IntegrityView />);
      fireEvent.change(screen.getByLabelText('Chain'), { target: { value: chain } });
      fireEvent.click(button('Start new run'));
      await screen.findByText('No records checked.');
      expect(screen.getByText(/No payload or record content was verified/)).toBeTruthy();
      expect(screen.queryByText(/Verification complete for/)).toBeNull();
      expect(screen.queryByText(/Retained audit payloads were recomputed/)).toBeNull();
      expect(button('Continue verification').disabled).toBe(true);
    }
  );

  it.each(
    (['audit', 'ledger'] as const).flatMap((chain) =>
      (['partial', 'complete', 'empty'] as const).flatMap((state) => [
        { chain, state, seedKind: 'wrong', seedHash: 'a'.repeat(64) },
        { chain, state, seedKind: 'swapped', seedHash: chain === 'audit' ? ledgerSeed : seed },
      ])
    )
  )(
    'rejects a $seedKind $chain genesis seed on an otherwise clean $state first page',
    async ({ chain, state, seedHash }) => {
      const empty = state === 'empty';
      api.verify.mockResolvedValueOnce(
        proof({
          ...(chain === 'audit'
            ? { chain, scope: auditScope }
            : { chain, scope: ledgerScope, erased_checked: 0 }),
          seed_hash: seedHash,
          through_seq: empty ? '0' : state === 'complete' ? high : maximum,
          checked: empty ? 0 : 2,
          first_seq: empty ? null : '2',
          last_seq: empty ? null : high,
          last_hash: empty ? seedHash : hash,
          next_after_seq: empty ? null : high,
          complete: state !== 'partial',
        })
      );
      render(<IntegrityView />);
      fireEvent.change(screen.getByLabelText('Chain'), { target: { value: chain } });
      fireEvent.click(button('Start new run'));
      expect((await screen.findByRole('alert')).textContent).toContain('inconsistent');
      expect(screen.getByText(/Run incomplete/)).toBeTruthy();
      expect(screen.getByTestId('verification-bound').textContent).toBe('Not captured yet');
      expect(screen.queryByTestId('verification-page')).toBeNull();
      expect(screen.queryByText('No records checked.')).toBeNull();
      expect(screen.queryByText(/Verification complete for/)).toBeNull();
      expect(button('Continue verification').disabled).toBe(true);
      expect(button('Stop verification').disabled).toBe(true);
      expect(api.verify).toHaveBeenCalledTimes(1);
      expect(api.verify).toHaveBeenCalledWith(
        chain,
        { after_seq: '0', limit: 2 },
        expect.any(AbortSignal)
      );
    }
  );

  it('treats no_stored_records as no evidence, not proof of no activity or a clean chain', async () => {
    api.verify.mockResolvedValueOnce(
      proof({
        verified: false,
        failure_reason: 'no_stored_records',
        checked: 0,
        first_seq: null,
        last_seq: null,
        last_hash: seed,
        next_after_seq: null,
      })
    );
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    await screen.findByText('No verification evidence.');
    expect(screen.getByText(/not proof of no activity/)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(button('Continue verification').disabled).toBe(true);
  });

  it.each([
    'chain_mismatch',
    'leaf_mismatch',
    'invalid_leaf_hash',
    'invalid_chain_hash',
    'record_not_serializable',
    'payload_absent_without_erasure_record',
    'head_mismatch',
  ] as const)(
    'stops on HTTP-200 integrity failure %s without blessing checked counts',
    async (reason) => {
      const invalidDigest = reason === 'invalid_leaf_hash' || reason === 'invalid_chain_hash';
      const head = reason === 'head_mismatch';
      const mismatch = reason === 'chain_mismatch' || reason === 'leaf_mismatch' || head;
      const seq = head ? maximum : '2';
      api.verify.mockResolvedValueOnce(
        proof({
          verified: false,
          failure_reason: reason,
          checked: invalidDigest ? 0 : 1,
          first_seq: invalidDigest ? null : seq,
          last_seq: invalidDigest ? null : seq,
          last_hash: head ? hash : seed,
          next_after_seq: null,
          broken_at_seq: seq,
          expected_hash: mismatch ? hash : null,
          stored_hash: mismatch ? lastHash : null,
        })
      );
      render(<IntegrityView />);
      fireEvent.click(button('Start new run'));
      await screen.findByText(reason);
      expect(screen.getByRole('alert').textContent).toContain('No continuation');
      expect(screen.getByText(/visited nodes, not successfully verified payloads/)).toBeTruthy();
      expect(button('Continue verification').disabled).toBe(true);
      expect(screen.queryByText(/Verification complete for/)).toBeNull();
      if (mismatch) expect(screen.getByText('Expected hash')).toBeTruthy();
    }
  );

  it('shows a changed stored predecessor as a failure at the exact continuation seed', async () => {
    api.verify.mockResolvedValueOnce(proof()).mockResolvedValueOnce(
      completeProof({
        complete: false,
        verified: false,
        failure_reason: 'predecessor_mismatch',
        checked: 0,
        first_seq: null,
        last_seq: null,
        last_hash: hash,
        next_after_seq: null,
        broken_at_seq: high,
        expected_hash: hash,
        stored_hash: lastHash,
      })
    );
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    await screen.findByText('Clean partial segment. Verification is not complete.');
    fireEvent.click(button('Continue verification'));
    await screen.findByText('predecessor_mismatch');
    expect(screen.getByRole('alert').textContent).toContain('stored predecessor changed');
    expect(button('Continue verification').disabled).toBe(true);
  });

  it.each([
    { through_seq: '9223372036854775806' },
    { seed_hash: lastHash },
    { after_seq: '0' },
    { seed_source: 'database_predecessor' },
    { complete: false, next_after_seq: null },
    { chain: 'ledger', scope: ledgerScope, erased_checked: 0 },
  ] as Partial<AdminVerification>[])(
    'rejects inconsistent proof continuation without accepting a terminal claim (%p)',
    async (patch) => {
      api.verify.mockResolvedValueOnce(proof()).mockResolvedValueOnce(completeProof(patch));
      render(<IntegrityView />);
      fireEvent.click(button('Start new run'));
      await screen.findByText('Clean partial segment. Verification is not complete.');
      fireEvent.click(button('Continue verification'));
      expect((await screen.findByRole('alert')).textContent).toContain('inconsistent');
      expect(screen.getByText(/Run incomplete/)).toBeTruthy();
      expect(screen.getByTestId('verification-bound').textContent).toBe(maximum);
      expect(button('Continue verification').disabled).toBe(true);
      expect(
        screen.queryByText('Verification complete for the captured database-relative range.')
      ).toBeNull();
    }
  );

  it.each([
    [new PortalError('unknown_seq', 400), 'boundary was rejected'],
    [new PortalError('missing_head', 400), 'Verification state is missing'],
    [new PortalError('audit_unavailable', 503), 'not an empty result or an integrity finding'],
    [new PortalError('network_error'), 'could not be completed'],
    [new PortalError('rate_limited', 429, false, 30), 'Wait 30 seconds'],
  ] as const)(
    'separates unavailable/boundary/transport failures from cryptographic mismatches (%p)',
    async (failure, message) => {
      api.verify.mockResolvedValueOnce(proof()).mockRejectedValueOnce(failure);
      render(<IntegrityView />);
      fireEvent.click(button('Start new run'));
      await screen.findByText('Clean partial segment. Verification is not complete.');
      fireEvent.click(button('Continue verification'));
      expect((await screen.findByRole('alert')).textContent).toContain(message);
      expect(screen.queryByText('Failure code')).toBeNull();
      expect(button('Continue verification').disabled).toBe(true);
      expect(api.verify).toHaveBeenCalledTimes(2);
    }
  );

  it('cancels an in-flight run, starts afresh, and ignores an old successful terminal reply', async () => {
    const late = deferred<AdminVerification>();
    api.verify
      .mockReturnValueOnce(late.promise)
      .mockResolvedValueOnce(proof({ through_seq: '42', last_seq: '40', next_after_seq: '40' }));
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    const signal = api.verify.mock.calls[0][2] as AbortSignal;
    fireEvent.click(button('Stop verification'));
    expect(signal.aborted).toBe(true);
    expect(button('Continue verification').disabled).toBe(true);
    fireEvent.click(button('Start new run'));
    await screen.findByText('Clean partial segment. Verification is not complete.');
    await act(async () => late.resolve(proof({ through_seq: high, complete: true })));
    expect(screen.getByTestId('verification-bound').textContent).toBe('42');
    expect(
      screen.queryByText('Verification complete for the captured database-relative range.')
    ).toBeNull();
  });
});

describe('query privacy lifetime', () => {
  it.each([
    [UsersView, 'Apply filters', api.users],
    [AuditView, 'Search audit logs', api.auditLogs],
    [IntegrityView, 'Start new run', api.verify],
  ] as const)(
    'clears active private data on admin 403 without signing out the normal session (%p)',
    async (View, action, method) => {
      method.mockRejectedValueOnce(new PortalError('invalid_response', 403));
      render(<View />);
      fireEvent.click(button(action));
      await screen.findByText(
        'Private query data was cleared. Session and administrative access must be checked again before continuing.'
      );
      expect(reportPermissionLoss).toHaveBeenCalledTimes(1);
      expect(signOut).not.toHaveBeenCalled();
      expect(screen.queryByRole('form')).toBeNull();
      expect(screen.queryByTestId('verification-page')).toBeNull();
    }
  );

  it.each([sensitiveClearEvent, sensitiveSuspendEvent, 'pagehide', 'popstate'])(
    'clears audit payloads, drafts, cursors and pending replies on %s',
    async (event) => {
      const late = deferred<AdminAuditPage>();
      api.auditLogs.mockResolvedValueOnce(auditPage(high, true)).mockReturnValueOnce(late.promise);
      render(<AuditView />);
      fireEvent.change(screen.getByLabelText('Event type (exact)'), {
        target: { value: 'user.login' },
      });
      submitAudit();
      await screen.findByText(high);
      fireEvent.click(button('Older records'));
      const signal = api.auditLogs.mock.calls[1][1] as AbortSignal;
      fireEvent(window, new Event(event));
      expect(signal.aborted).toBe(true);
      expect(
        screen.getByText(
          'Private query data was cleared. Session and administrative access must be checked again before continuing.'
        )
      ).toBeTruthy();
      expect(screen.queryByLabelText('Event type (exact)')).toBeNull();
      await act(async () => late.resolve(auditPage('3')));
      expect(screen.queryByRole('table')).toBeNull();
      expect(api.auditLogs).toHaveBeenCalledTimes(2);
    }
  );

  it('discards verification progress on background and does not restore it or poll on foreground', async () => {
    const late = deferred<AdminVerification>();
    api.verify.mockResolvedValueOnce(proof()).mockReturnValueOnce(late.promise);
    render(<IntegrityView />);
    fireEvent.click(button('Start new run'));
    await screen.findByTestId('verification-page');
    fireEvent.click(button('Continue verification'));
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    fireEvent(document, new Event('visibilitychange'));
    expect((api.verify.mock.calls[1][2] as AbortSignal).aborted).toBe(true);
    expect(screen.queryByTestId('verification-page')).toBeNull();
    expect(screen.queryByTestId('verification-bound')).toBeNull();
    await act(async () => late.resolve(completeProof()));
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    fireEvent(document, new Event('visibilitychange'));
    expect(
      screen.getByText(
        'Private query data was cleared. Session and administrative access must be checked again before continuing.'
      )
    ).toBeTruthy();
    expect(api.verify).toHaveBeenCalledTimes(2);
  });

  it.each([
    [UsersView, 'Apply filters', api.users, 1],
    [AuditView, 'Search audit logs', api.auditLogs, 1],
    [IntegrityView, 'Start new run', api.verify, 2],
  ] as const)(
    'aborts its own outstanding work on navigation unmount (%p)',
    async (View, action, method, signalIndex) => {
      const late = deferred<never>();
      method.mockReturnValueOnce(late.promise);
      const view = render(<View />);
      fireEvent.click(button(action));
      const signal = method.mock.calls[0][signalIndex] as AbortSignal;
      view.unmount();
      expect(signal.aborted).toBe(true);
      await act(async () => late.reject(new PortalError('network_error')));
      expect(reportPermissionLoss).not.toHaveBeenCalled();
    }
  );
});

it('translates audit validation and pending results in place without replaying a query', async () => {
  const content = (locale: 'en' | 'fa-IR') => (
    <I18nTestProvider locale={locale}>
      <AuditView />
    </I18nTestProvider>
  );
  const view = render(content('en'));
  const start = screen.getByLabelText<HTMLInputElement>('Start time (UTC)');
  fireEvent.change(start, { target: { value: '' } });
  submitAudit();
  expect(screen.getByRole('alert').textContent).toBe('Enter a valid start time in UTC.');
  view.rerender(content('fa-IR'));
  expect(screen.getByRole('alert').textContent).toBe('زمان آغاز معتبری بر اساس UTC وارد کنید.');
  expect(screen.getByLabelText('زمان آغاز (UTC)')).toBe(start);
  expect(api.auditLogs).not.toHaveBeenCalled();
  fireEvent.change(start, { target: { value: '2026-10-28T09:00:00' } });
  const pending = deferred<AdminAuditPage>();
  api.auditLogs.mockReturnValueOnce(pending.promise);
  fireEvent.submit(screen.getByRole('form', { name: 'جست‌وجوی سوابق ممیزی' }));
  expect(screen.getByRole('status').textContent).toBe('در حال بارگیری یک صفحه از سوابق ممیزی...');
  const signal = api.auditLogs.mock.calls[0][1];
  view.rerender(content('en'));
  expect(screen.getByRole('status').textContent).toBe('Loading one audit-log page...');
  expect(signal.aborted).toBe(false);
  expect(api.auditLogs).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve(auditPage()));
  const row = screen.getByTestId('admin-audit-row');
  view.rerender(content('fa-IR'));
  expect(screen.getByRole('columnheader', { name: 'شمارهٔ توالی' })).toBeTruthy();
  expect(screen.getByTestId('admin-audit-row')).toBe(row);
  expect(within(row).getByText(high).closest('bdi')?.dir).toBe('ltr');
  fireEvent.click(screen.getByRole('button', { name: `مشاهدهٔ جزئیات توالی ${high}` }));
  expect(screen.getByRole('dialog').textContent).toContain('اثبات بررسی تمامیت زنجیره نیستند');
  const payload = screen.getByRole('dialog').querySelector('pre');
  expect(payload?.textContent).toBe(log().payload);
  expect(payload?.dir).toBe('ltr');
  view.rerender(content('en'));
  expect(screen.getByRole('dialog').querySelector('pre')).toBe(payload);
  expect(api.auditLogs).toHaveBeenCalledTimes(1);
});

it('preserves a pending verification and exact bound across language and display preference changes', async () => {
  const pending = deferred<AdminVerification>();
  api.verify.mockReturnValueOnce(pending.promise).mockResolvedValueOnce(completeProof());
  const content = (locale: 'en' | 'fa-IR') => (
    <I18nTestProvider
      locale={locale}
      preferences={{ calendar: 'persian', timeZone: 'Asia/Tehran' }}
    >
      <IntegrityView />
    </I18nTestProvider>
  );
  const view = render(content('en'));
  fireEvent.click(button('Start new run'));
  const signal = api.verify.mock.calls[0][2] as AbortSignal;
  view.rerender(content('fa-IR'));
  expect(screen.getByRole('status').textContent).toBe('در حال بررسی یک صفحهٔ محدود...');
  expect(signal.aborted).toBe(false);
  expect(api.verify).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve(proof()));
  const bound = screen.getByTestId('verification-bound');
  expect(bound.textContent).toBe(maximum);
  expect(bound.dir).toBe('ltr');
  expect(screen.getByText('شواهد فنی اصلی')).toBeTruthy();
  const raw = screen.getByText(auditScope);
  expect(raw.closest('details')).toBeTruthy();
  expect(raw.dir).toBe('ltr');
  expect(screen.getByText(/ورود کامل داده، تشخیص قطع‌شدن انتهای زنجیره/)).toBeTruthy();
  view.rerender(content('en'));
  expect(screen.getByTestId('verification-bound')).toBe(bound);
  expect(bound.textContent).toBe(maximum);
  expect(api.verify).toHaveBeenCalledTimes(1);
  fireEvent.click(button('Continue verification'));
  await screen.findByText('Verification complete for the captured database-relative range.');
  expect(api.verify).toHaveBeenLastCalledWith(
    'audit',
    { after_seq: high, through_seq: maximum, predecessor_hash: hash, limit: 2 },
    expect.any(AbortSignal)
  );
});
