import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TextEncoder } from 'node:util';
import { I18nTestProvider, render } from '../i18n/testing';
import { PortalProvider } from '../app/_components/portal-provider';
import { NativeDialog } from '../app/_components/native-dialog';
import { LegalView } from '../app/admin/_components/legal-view';
import { legalFailureMessage } from '../app/admin/_components/legal-view-state';
import { generateMetadata } from '../app/admin/legal/page';
import { QueryUtcTime } from '../app/admin/_components/query-view-time';
import { AdminOverview } from '../app/admin/_components/admin-overview';
import { AdminClient } from '../app/_lib/admin/client';
import type { AdminCapabilities } from '../app/_lib/admin/contracts';
import { LegalClient } from '../app/_lib/admin/legal-api';
import type {
  LegalHold,
  LegalHoldRequest,
  LegalHoldsPage,
  LegalHoldsQuery,
  LegalLookupPage,
  LegalLookupQuery,
  LegalPreservationRequest,
  LegalPreservationResult,
} from '../app/_lib/admin/legal-contracts';
import { PortalClient } from '../app/_lib/portal/client';
import { StepUpGrant, type Profile } from '../app/_lib/portal/contracts';
import { PortalError } from '../app/_lib/portal/errors';
import { clearSensitiveViews, onOtherTabInvalidation } from '../app/_lib/portal/invalidation';
import { usePasskey } from '../app/_lib/portal/webauthn';

let mockPathname = '/admin/legal';
let mockMetadataLocale: 'en' | 'fa-IR' = 'en';
jest.mock('next-intl/server', () => ({
  getTranslations: (namespace: 'legal') =>
    jest.requireActual('../i18n/testing').getTestTranslations(namespace, mockMetadataLocale),
}));
jest.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useRouter: () => ({ replace: jest.fn() }),
}));
jest.mock('../app/_lib/portal/client', () => ({ PortalClient: jest.fn() }));
jest.mock('../app/_lib/admin/client', () => ({ AdminClient: jest.fn() }));
jest.mock('../app/_lib/admin/legal-api', () => ({ LegalClient: jest.fn() }));
jest.mock('../app/_lib/portal/webauthn', () => ({ usePasskey: jest.fn() }));
jest.mock('../app/_lib/portal/invalidation', () => ({
  ...jest.requireActual('../app/_lib/portal/invalidation'),
  onOtherTabInvalidation: jest.fn(),
}));

const reference = '00000000-0000-4000-8000-000000000002';
const otherReference = '00000000-0000-4000-8000-000000000003';
const operationID = '00000000-0000-4000-8000-000000000011';
const holdID = '00000000-0000-4000-8000-000000000021';
const high = '9007199254740993';
const maximum = '9223372036854775807';
const profile = (): Profile => ({
  id: '00000000-0000-4000-8000-000000000001',
  email: 'operator@example.test',
  display_name: 'Operator',
  status: 'active',
  deletion_enabled: false,
  lifecycle_revision: '1',
  session: { id: 'private-session', expires_at: new Date(Date.now() + 3600000).toISOString() },
});
const permissions = (): AdminCapabilities => ({
  capabilities: {
    users_read: false,
    users_pii: false,
    users_lookup: false,
    users_status_write: false,
    audit_logs_read: false,
    audit_chain_verify: false,
    ledger_verify: false,
    legal_holds_read: true,
    legal_holds_apply: true,
    legal_holds_release: true,
    preservation_requests_create: true,
    legal_inquiry_lookup: true,
  },
  limits: {
    page_size_default: 2,
    page_size_max: 200,
    audit_max_window_seconds: 86400,
    chain_verify_max_limit: 1000,
  },
});
const hold = (overrides: Partial<LegalHold> = {}): LegalHold => ({
  id: holdID,
  account_ref: reference,
  request_kind: 'legal_hold',
  is_active: true,
  applied_by: profile().id,
  applied_at: '2026-11-01T11:00:00Z',
  review_at: null,
  released_at: null,
  released_by: null,
  reason: 'Controlled legal reason',
  requesting_authority: 'Authority',
  legal_basis: 'Reviewed legal basis',
  details_purged: false,
  replayed: false,
  ...overrides,
});
const lookupPage = (overrides: Partial<LegalLookupPage> = {}): LegalLookupPage => ({
  items: [
    {
      id: operationID,
      account_ref: reference,
      event_type: 'user.login',
      timestamp: '2026-11-01T10:30:00Z',
      retain_until: '2027-11-01T10:30:00Z',
      seq: high,
    },
  ],
  next_cursor: 'opaque_cursor',
  coverage: {
    through_seq: maximum,
    observed_at: '2026-11-01T11:00:00Z',
    eligibility_checked_at: '2026-11-01T11:00:00Z',
    note: 'Complete explanatory coverage note; eligibility is checked for this page.',
  },
  ...overrides,
});
let clients: ReturnType<typeof makeClient>[];
let grants: StepUpGrant[];
let grantSeconds: number;
let nextBootstrap: () => Promise<Profile>;
let nextCapabilities: () => Promise<AdminCapabilities>;
let visibility: PropertyDescriptor | undefined;
let peerInvalidation: () => void;
const resultMatchMediaDescriptor = Object.getOwnPropertyDescriptor(window, 'matchMedia');

function resultViewport(initial = false) {
  let wide = initial;
  const events = new EventTarget();
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: jest.fn((query: string) => ({
      media: query,
      get matches() { return query === '(min-width: 1024px)' && wide; },
      addEventListener: query === '(min-width: 1024px)' ? events.addEventListener.bind(events) : jest.fn(),
      removeEventListener: query === '(min-width: 1024px)' ? events.removeEventListener.bind(events) : jest.fn(),
    })),
  });
  return (desktop: boolean) => {
    wide = desktop;
    act(() => events.dispatchEvent(new Event('change')));
  };
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
    admin: { capabilities: jest.fn(nextCapabilities) },
    legal: {
      holds: jest.fn(
        async (query: LegalHoldsQuery, _signal?: AbortSignal): Promise<LegalHoldsPage> => ({
          items: [hold()],
          total: 1,
          limit: query.limit,
          offset: query.offset,
        })
      ),
      applyHold: jest.fn(
        async (
          request: LegalHoldRequest,
          grant: StepUpGrant,
          _signal?: AbortSignal,
          onSend?: () => void
        ) => {
          grant.take('private-session');
          onSend?.();
          return hold({
            account_ref: request.accountRef,
            reason: request.reason,
            requesting_authority: request.requestingAuthority,
            legal_basis: request.legalBasis,
            review_at: request.reviewAt ?? null,
          });
        }
      ),
      preserve: jest.fn(
        async (
          request: LegalPreservationRequest,
          grant: StepUpGrant,
          _signal?: AbortSignal,
          onSend?: () => void
        ): Promise<LegalPreservationResult> => {
          grant.take('private-session');
          onSend?.();
          return {
            hold: hold({
              account_ref: request.accountRef,
              request_kind: 'preservation',
              reason: request.reason,
              requesting_authority: request.requestingAuthority,
              legal_basis: 'preservation_request',
              review_at: request.expiresAt ?? null,
            }),
            replayed: false,
            account_present: false,
            ledger_evidence_present: false,
            observed_at: '2026-11-01T11:00:00Z',
            note: 'Presence observations are not completeness evidence.',
          };
        }
      ),
      releaseHold: jest.fn(
        async (_id: string, grant: StepUpGrant, _signal?: AbortSignal, onSend?: () => void) => {
          grant.take('private-session');
          onSend?.();
        }
      ),
      lookup: jest.fn(
        async (
          _query: LegalLookupQuery,
          grant: StepUpGrant,
          _signal?: AbortSignal,
          onSend?: () => void
        ): Promise<LegalLookupPage> => {
          grant.take('private-session');
          onSend?.();
          return lookupPage();
        }
      ),
    },
  };
  api.bootstrap.mockImplementation(async () => {
    api.profile = await bootstrap();
    return api.profile;
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
      { token: 'one-use-private-grant', token_type: 'StepUp', expires_in: grantSeconds },
      current.session.id,
      Date.now(),
      Date.parse(current.session.expires_at)
    );
    grants.push(grant);
    return grant;
  });
  return api;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (failure: unknown) => void;
  const promise = new Promise<T>((finish, fail) => {
    resolve = finish;
    reject = fail;
  });
  return { promise, resolve, reject };
}
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'getClientRects', {
    configurable: true,
    value: () => [new DOMRect(0, 0, 100, 44)],
  });
  Object.defineProperty(HTMLElement.prototype, 'getClientRects', {
    configurable: true,
    value: () => [new DOMRect(0, 0, 100, 44)],
  });
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
  jest.clearAllMocks();
  mockPathname = '/admin/legal';
  mockMetadataLocale = 'en';
  clients = [];
  grants = [];
  grantSeconds = 60;
  nextBootstrap = async () => profile();
  nextCapabilities = async () => permissions();
  visibility = Object.getOwnPropertyDescriptor(document, 'visibilityState');
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  jest.mocked(PortalClient).mockImplementation(() => {
    const value = makeClient();
    clients.push(value);
    return value as unknown as PortalClient;
  });
  jest
    .mocked(AdminClient)
    .mockImplementation(
      (client) =>
        (client as unknown as ReturnType<typeof makeClient>).admin as unknown as AdminClient
    );
  jest
    .mocked(LegalClient)
    .mockImplementation(
      (client) =>
        (client as unknown as ReturnType<typeof makeClient>).legal as unknown as LegalClient
    );
  jest.mocked(onOtherTabInvalidation).mockImplementation((listener) => {
    peerInvalidation = listener;
    return jest.fn();
  });
  jest
    .mocked(usePasskey)
    .mockResolvedValue({ id: 'assertion' } as Awaited<ReturnType<typeof usePasskey>>);
});
afterEach(() => {
  jest.useRealTimers();
  if (resultMatchMediaDescriptor) Object.defineProperty(window, 'matchMedia', resultMatchMediaDescriptor);
  else Reflect.deleteProperty(window, 'matchMedia');
  if (visibility) Object.defineProperty(document, 'visibilityState', visibility);
  else Reflect.deleteProperty(document, 'visibilityState');
});
function legalTree(locale: 'en' | 'fa-IR' = 'en') {
  return (
    <I18nTestProvider locale={locale}>
      <PortalProvider surface="admin">
        <LegalView />
      </PortalProvider>
    </I18nTestProvider>
  );
}
function renderLegal(locale: 'en' | 'fa-IR' = 'en') {
  return render(legalTree(locale));
}
function hide() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
}
function show() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
}
async function openAction(name = 'Apply Legal Hold', factor: 'webauthn' | 'totp' = 'webauthn') {
  fireEvent.click(await screen.findByRole('button', { name }));
  const dialog = within(screen.getByRole('dialog'));
  expect(dialog.queryByLabelText('Operation UUID')).toBeNull();
  expect(dialog.queryByLabelText('Email for attribution')).toBeNull();
  fireEvent.click(dialog.getByRole('button', { name: 'Continue to verification' }));
  await dialog.findByRole('button', { name: 'Verify with a passkey' });
  if (factor === 'totp') {
    fireEvent.click(dialog.getByRole('button', { name: 'Use authenticator code' }));
    fireEvent.change(dialog.getByLabelText('Authenticator code'), { target: { value: '123456' } });
    fireEvent.submit(dialog.getByRole('form', { name: 'Step-up authenticator verification' }));
  } else fireEvent.click(dialog.getByRole('button', { name: 'Verify with a passkey' }));
  await dialog.findByText(/Verification complete/);
  return dialog;
}
function fillCreate(
  kind: 'hold' | 'preservation' = 'hold',
  overrides: Record<string, string> = {}
) {
  const dialog = within(screen.getByRole('dialog'));
  const values = {
    'Original account reference': reference,
    'Operation UUID': operationID,
    Reason: '  Controlled legal reason  ',
    'Requesting authority': '  Authority ',
    ...(kind === 'hold' ? { 'Legal basis': ' Reviewed legal basis ' } : {}),
    ...overrides,
  };
  for (const [label, value] of Object.entries(values)) {
    const input = dialog.getByLabelText<HTMLInputElement>(label, { exact: true });
    if (!input.disabled) fireEvent.change(input, { target: { value } });
  }
  fireEvent.click(dialog.getByRole('button', { name: 'Review request' }));
}
function fillLookup(fields: string[] = [], size = '1') {
  const dialog = within(screen.getByRole('dialog'));
  for (const [label, value] of Object.entries({
    'Email for attribution': 'Person@example.test',
    'Requesting authority': 'Authority',
    'Case reference': 'Case-41',
    'Inquiry purpose': 'Controlled inquiry purpose',
    'Start time (UTC)': '2026-11-01T10:00:00Z',
    'End time (UTC)': '2026-11-01T11:00:00Z',
    'Page size': size,
  }))
    fireEvent.change(dialog.getByLabelText(label, { exact: true }), { target: { value } });
  for (const label of fields) fireEvent.click(dialog.getByRole('checkbox', { name: label }));
  fireEvent.click(dialog.getByRole('button', { name: 'Review request' }));
}
function confirm() {
  const dialog = within(screen.getByRole('dialog'));
  fireEvent.click(dialog.getByRole('checkbox', { name: /I reviewed/ }));
  fireEvent.submit(dialog.getByRole('form', { name: 'Confirm legal request' }));
}
async function readHolds() {
  fireEvent.click(await screen.findByRole('checkbox', { name: 'All original references' }));
  fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
  await screen.findByTestId('legal-hold-row');
}
async function inquiry(fields: string[] = [], size = '1') {
  fireEvent.click(await screen.findByRole('button', { name: 'Attribution' }));
  await openAction('Start attribution inquiry');
  fillLookup(fields, size);
  confirm();
  await screen.findAllByTestId('legal-result-row');
}

it('server-renders only a neutral shell without legal fields, values or requests', () => {
  const html = renderToStaticMarkup(legalTree());
  expect(html).toContain('Checking your secure browser session and administrative access');
  for (const value of [reference, operationID, 'Operation UUID', 'Email for attribution', '<form'])
    expect(html).not.toContain(value);
  expect(PortalClient).not.toHaveBeenCalled();
  expect(LegalClient).not.toHaveBeenCalled();
});

it.each([
  ['2020-01-01T00:00:00.123456Z', '2020-01-01 00:00:00.123456 UTC'],
  ['2020-01-01T00:00:00.123456789Z', '2020-01-01 00:00:00.123456789 UTC'],
  ['2020-01-01T03:30:00.123456+03:30', '2020-01-01 00:00:00.123456 UTC'],
  ['2020-01-01T00:00:00.000Z', '2020-01-01 00:00:00.000 UTC'],
])('visibly retains exact UTC wire precision for %s', (value, expected) => {
  render(<QueryUtcTime value={value} />);
  expect(screen.getByText(expected).getAttribute('datetime')).toBe(value);
});

it('keeps a sole dialog control in view when Tab wraps after responsive reflow', () => {
  render(
    <NativeDialog title="Restricted details" description="Restricted text" onCancel={jest.fn()}>
      <button type="button">Close details</button>
    </NativeDialog>
  );
  const close = screen.getByRole('button', { name: 'Close details' });
  close.focus();
  fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Tab' });
  expect(document.activeElement).toBe(close);
  expect(close.scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', inline: 'nearest' });
});

it('keeps legal prepare and confirmation actions in one stable review footer with exact form association', async () => {
  renderLegal();
  const dialog = await openAction();
  const element = screen.getByRole('dialog');
  const title = dialog.getByRole('heading', { name: 'Apply Legal Hold' });
  const cancel = dialog.getByRole('button', { name: 'Cancel' });
  expect(element.getAttribute('data-layout')).toBe('review');
  expect(element.querySelectorAll('[data-dialog-scroll]')).toHaveLength(1);
  const review = dialog.getByRole<HTMLButtonElement>('button', { name: 'Review request' });
  expect(review.form).toBe(dialog.getByRole('form', { name: 'Prepare legal request' }));
  expect(review.closest('footer')).not.toBeNull();
  fillCreate();
  const form = dialog.getByRole<HTMLFormElement>('form', { name: 'Confirm legal request' });
  const confirm = dialog.getByRole<HTMLButtonElement>('button', { name: 'Confirm Legal Hold' });
  expect(confirm.form).toBe(form);
  expect(form.contains(confirm)).toBe(false);
  expect(confirm.closest('footer')).not.toBeNull();
  expect(confirm.disabled).toBe(true);
  expect(dialog.getByRole('heading', { name: 'Apply Legal Hold' })).toBe(title);
  expect(dialog.getByRole('button', { name: 'Cancel' })).toBe(cancel);
  expect(element.querySelector('[data-dialog-scroll]')?.contains(form)).toBe(true);
  fireEvent.click(dialog.getByRole('checkbox', { name: /I reviewed/ }));
  expect(confirm.disabled).toBe(false);
  fireEvent.click(confirm);
  await waitFor(() => expect(clients[0].legal.applyHold).toHaveBeenCalledTimes(1));
  expect(clients[0].legal.applyHold.mock.calls[0][0].accountRef).toBe(reference);
});

it.each([
  'legal_holds_read',
  'legal_holds_apply',
  'legal_holds_release',
  'preservation_requests_create',
  'legal_inquiry_lookup',
] as const)(
  'admits a legal-only %s workspace without prefetching accounts or legal data',
  async (flag) => {
    nextCapabilities = async () => ({
      ...permissions(),
      capabilities: {
        ...permissions().capabilities,
        legal_holds_read: false,
        legal_holds_apply: false,
        legal_holds_release: false,
        preservation_requests_create: false,
        legal_inquiry_lookup: false,
        [flag]: true,
      },
    });
    renderLegal();
    await screen.findByRole('heading', { name: 'DPO and Legal' });
    expect(screen.getByRole('link', { name: 'DPO and Legal' }).getAttribute('href')).toBe(
      '/admin/legal'
    );
    expect(screen.queryByRole('link', { name: 'Accounts' })).toBeNull();
    expect(LegalClient).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Apply Legal Hold' }) !== null).toBe(
      flag === 'legal_holds_apply'
    );
    expect(screen.queryByRole('button', { name: 'Read Legal Holds' }) !== null).toBe(
      flag === 'legal_holds_read'
    );
    expect(screen.queryByRole('button', { name: 'Record preservation' }) !== null).toBe(
      flag === 'preservation_requests_create'
    );
    expect(screen.queryByRole('button', { name: 'Start attribution inquiry' }) !== null).toBe(
      flag === 'legal_inquiry_lookup'
    );
  }
);

it('denies the direct route without signing out or inferring permission versus missing prerequisites', async () => {
  nextCapabilities = async () => ({
    ...permissions(),
    capabilities: {
      ...permissions().capabilities,
      legal_holds_read: false,
      legal_holds_apply: false,
      legal_holds_release: false,
      preservation_requests_create: false,
      legal_inquiry_lookup: false,
    },
  });
  renderLegal();
  expect((await screen.findByRole('alert')).textContent).toContain('does not distinguish');
  expect(clients[0].logout).not.toHaveBeenCalled();
  expect(LegalClient).not.toHaveBeenCalled();
});

it('links the legal workspace from overview with no automatic requests', async () => {
  render(
    <PortalProvider surface="admin">
      <AdminOverview />
    </PortalProvider>
  );
  await screen.findByRole('heading', { name: 'Available workspaces' });
  expect(screen.getAllByRole('link', { name: 'DPO and Legal' })).toHaveLength(2);
  expect(LegalClient).not.toHaveBeenCalled();
});

it('requires explicit all-reference selection and bounds pages without silently widening invalid input', async () => {
  renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Read Legal Holds' }));
  expect((await screen.findByRole('alert')).textContent).toContain('never becomes an all-subject');
  expect(LegalClient).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Original account reference'), {
    target: { value: reference },
  });
  fireEvent.change(screen.getByLabelText('Page size'), { target: { value: '51' } });
  fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
  expect(clients[0].legal.holds).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Page size'), { target: { value: '1' } });
  fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
  await screen.findByTestId('legal-hold-row');
  expect(clients[0].legal.holds).toHaveBeenCalledWith(
    { accountRef: reference, status: 'active', limit: 1, offset: 0 },
    expect.any(AbortSignal)
  );
  expect(clients[0].stepUpChallenge).not.toHaveBeenCalled();
  expect(screen.queryByText('Controlled legal reason')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'View restricted details' }));
  expect((await screen.findByTestId('legal-hold-details')).textContent).toContain(
    'Controlled legal reason'
  );
});

describe.each(['en', 'fa-IR'] as const)('stable compact legal results in %s', (locale) => {
  const names = locale === 'en'
    ? { rows: 'Compact rows', table: 'Table view', holds: 'Legal Hold results', attribution: 'Attribution results', details: 'View restricted details', release: 'Release request', select: 'Select reference' }
    : { rows: 'ردیف‌های فشرده', table: 'نمای جدول', holds: 'نتایج دستورهای نگهداشت حقوقی', attribution: 'نتایج انتساب', details: 'مشاهده جزئیات محدودشده', release: 'لغو نگهداشت درخواست', select: 'انتخاب شناسه اصلی' };

  it('keeps independent hold UUIDs for the same original reference and only eligible actions through reflow', async () => {
    const viewport = resultViewport();
    const view = renderLegal();
    await screen.findByTestId('admin-ready');
    const api = clients[0];
    const secondID = '00000000-0000-4000-8000-000000000022';
    api.legal.holds.mockResolvedValueOnce({
      items: [hold({ review_at: '2020-01-01T00:00:00.123456Z' }), hold({
        id: secondID, request_kind: 'preservation', is_active: false,
        released_at: '2026-11-01T12:00:00Z', released_by: profile().id,
      })], total: 2, offset: 0, limit: 2,
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'All original references' }));
    fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
    const rows = await screen.findAllByTestId('legal-hold-row');
    view.rerender(legalTree(locale));
    const table = screen.getByRole('table');
    const frame = screen.getByRole('region', { name: names.holds });
    expect(frame.parentElement?.getAttribute('data-result-view')).toBe('compact');
    expect(frame.hasAttribute('data-legal-private')).toBe(true);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText(holdID).getAttribute('dir')).toBe('ltr');
    expect(within(rows[1]).getByText(secondID).getAttribute('dir')).toBe('ltr');
    for (const row of rows) expect(within(row).getByText(reference).getAttribute('dir')).toBe('ltr');
    expect(within(rows[0]).getByRole('button', { name: names.release })).toBeTruthy();
    expect(within(rows[1]).queryByRole('button', { name: names.release })).toBeNull();
    expect(within(rows[0]).getByText('2020-01-01 00:00:00.123456 UTC')).toBeTruthy();
    expect(screen.queryByText('Controlled legal reason')).toBeNull();
    const open = within(rows[1]).getByRole('button', { name: names.details });
    const tableChoice = screen.getByRole('button', { name: names.table });
    tableChoice.focus();
    fireEvent.click(tableChoice);
    expect(document.activeElement).toBe(tableChoice);
    viewport(true);
    expect(document.activeElement).toBe(frame);
    expect(screen.getByRole('table')).toBe(table);
    expect(screen.getAllByTestId('legal-hold-row')[1]).toBe(rows[1]);
    open.focus();
    viewport(false);
    fireEvent.click(screen.getByRole('button', { name: names.rows }));
    expect(within(rows[1]).getByRole('button', { name: names.details })).toBe(open);
    expect(screen.getAllByRole('button', { name: names.details })).toHaveLength(2);
    open.focus();
    fireEvent.click(open);
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText(secondID)).toBeTruthy();
    expect(within(dialog).getByText(reference)).toBeTruthy();
    viewport(true);
    fireEvent.click(within(dialog).getByRole('button', { name: locale === 'en' ? 'Close details' : 'بستن جزئیات' }));
    expect(document.activeElement).toBe(open);
    expect(api.legal.holds).toHaveBeenCalledTimes(1);
    expect(api.stepUpChallenge).not.toHaveBeenCalled();
    expect(api.legal.releaseHold).not.toHaveBeenCalled();
    expect(api.legal.applyHold).not.toHaveBeenCalled();
    expect(clients).toHaveLength(1);
  });

  it('retains exact attribution references/sequences, selected disclosure and selection without another read or verification', async () => {
    const viewport = resultViewport(true);
    const view = renderLegal();
    await screen.findByTestId('admin-ready');
    const api = clients[0];
    const optional = '<script>inert reported metadata</script>';
    api.legal.lookup.mockResolvedValueOnce(lookupPage({ items: [
      { ...lookupPage().items[0], timestamp: '2026-11-08T21:00:00.123456789Z', user_agent: optional },
      { ...lookupPage().items[0], id: holdID, account_ref: otherReference, seq: maximum, user_agent: optional },
    ] }));
    await inquiry(['User agent'], '2');
    const rows = screen.getAllByTestId('legal-result-row');
    const table = screen.getByRole('table');
    view.rerender(legalTree(locale));
    const frame = screen.getByRole('region', { name: names.attribution });
    expect(frame.parentElement?.getAttribute('data-result-view')).toBe('table');
    expect(within(rows[0]).getByText(reference).getAttribute('dir')).toBe('ltr');
    expect(within(rows[1]).getByText(otherReference).getAttribute('dir')).toBe('ltr');
    expect(within(rows[1]).getByText(maximum).getAttribute('dir')).toBe('ltr');
    expect(within(rows[0]).getByText('2026-11-08 21:00:00.123456789 UTC')).toBeTruthy();
    expect(within(rows[1]).getByText(optional).textContent).toBe(optional);
    expect(rows[1].querySelector('script, a')).toBeNull();
    const select = within(rows[1]).getByRole('button', { name: names.select });
    select.focus();
    viewport(false);
    expect(document.activeElement).toBe(select);
    fireEvent.click(select);
    const selected = screen.getByTestId('legal-selected-reference');
    expect(selected.textContent).toContain(otherReference);
    expect(select.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: names.table }));
    expect(screen.getByRole('table')).toBe(table);
    expect(screen.getAllByTestId('legal-result-row')[1]).toBe(rows[1]);
    expect(screen.getByTestId('legal-selected-reference')).toBe(selected);
    expect(within(rows[1]).getByRole('button', { name: names.select })).toBe(select);
    expect(screen.getAllByRole('button', { name: names.select })).toHaveLength(2);
    viewport(true);
    viewport(false);
    fireEvent.click(screen.getByRole('button', { name: names.rows }));
    expect(select.getAttribute('aria-pressed')).toBe('true');
    expect(api.legal.lookup).toHaveBeenCalledTimes(1);
    expect(api.legal.lookup.mock.calls[0][0].fields).toEqual(['user_agent']);
    expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
    expect(api.admin.capabilities).toHaveBeenCalledTimes(1);
    expect(api.legal.applyHold).not.toHaveBeenCalled();
    expect(api.legal.preserve).not.toHaveBeenCalled();
    expect(clients).toHaveLength(1);
  });
});

it('normalizes, freezes and confirms one recorded UUID create without generating or auto-refetching', async () => {
  renderLegal();
  await openAction();
  const input = within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>(
    'Operation UUID'
  );
  fillCreate('hold', { 'Review at (UTC)': '2020-01-01T00:00:00.123456Z' });
  expect(input.value).toBe('');
  expect(input.defaultValue).toBe('');
  expect(input.getAttribute('value')).not.toContain(operationID);
  expect(clients[0].legal.applyHold).not.toHaveBeenCalled();
  expect(screen.queryByLabelText('Operation UUID')).toBeNull();
  confirm();
  expect((await screen.findByTestId('legal-outcome')).getAttribute('data-outcome')).toBe(
    'confirmed'
  );
  expect(clients[0].legal.applyHold).toHaveBeenCalledTimes(1);
  expect(clients[0].legal.applyHold.mock.calls[0][0]).toEqual({
    accountRef: reference,
    requestId: operationID,
    reason: 'Controlled legal reason',
    requestingAuthority: 'Authority',
    legalBasis: 'Reviewed legal basis',
    reviewAt: '2020-01-01T00:00:00.123456Z',
  });
  expect(Object.isFrozen(clients[0].legal.applyHold.mock.calls[0][0])).toBe(true);
  expect(() => grants[0].take('private-session')).toThrow('grant_expired');
  expect(clients[0].legal.holds).not.toHaveBeenCalled();
  expect(screen.getByTestId('legal-outcome').textContent).toContain(
    '2020-01-01 00:00:00.123456 UTC'
  );
});

it.each(['', '00000000-0000-0000-0000-000000000000', 'not-a-uuid'])(
  'rejects invalid operation UUID %p without consuming the grant',
  async (value) => {
    renderLegal();
    await openAction();
    fillCreate('hold', { 'Operation UUID': value });
    expect((await screen.findByRole('alert')).textContent).toContain('canonical nonzero UUIDs');
    expect(clients[0].legal.applyHold).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Review request' })).toBeTruthy();
  }
);

it('uses the legal 4096-byte reason limit, not moderation limits, with strict dates and UTF-8 validation', async () => {
  renderLegal();
  await openAction();
  fillCreate('hold', { Reason: 'é'.repeat(2049) });
  expect((await screen.findByRole('alert')).textContent).toContain('1-4096');
  fillCreate('hold', {
    Reason: 'é'.repeat(1500),
    'Review at (UTC)': '2026-11-01T00:00:00.1234567Z',
  });
  expect(screen.getByRole('alert').textContent).toContain('six fractional digits');
  fillCreate('hold', { Reason: 'é'.repeat(1500), 'Review at (UTC)': '' });
  confirm();
  await screen.findByTestId('legal-outcome');
  expect(clients[0].legal.applyHold.mock.calls[0][0].reason).toHaveLength(1500);
});

it('records preservation without a legal-basis input and honors the top-level replay indicator', async () => {
  renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Preservation' }));
  await openAction('Record preservation', 'totp');
  expect(screen.queryByLabelText('Legal basis')).toBeNull();
  clients[0].legal.preserve.mockImplementationOnce(async (_request, grant, _signal, sent) => {
    grant.take('private-session');
    sent?.();
    return {
      hold: hold({
        request_kind: 'preservation',
        legal_basis: 'preservation_request',
        replayed: false,
        is_active: false,
        released_at: '2026-11-01T12:00:00Z',
        released_by: profile().id,
      }),
      replayed: true,
      account_present: false,
      ledger_evidence_present: false,
      observed_at: '2026-11-01T11:00:00Z',
      note: 'Complete preservation observation note.',
    };
  });
  fillCreate('preservation');
  confirm();
  const outcome = await screen.findByTestId('legal-outcome');
  expect(outcome.getAttribute('data-outcome')).toBe('replayed');
  expect(outcome.textContent).toContain('already released');
  expect(outcome.textContent).toContain('Complete preservation observation note.');
  expect(clients[0].legal.preserve.mock.calls[0][0]).not.toHaveProperty('legalBasis');
  expect(clients[0].stepUpVerify).toHaveBeenCalledWith(
    { method: 'totp', code: '123456' },
    expect.any(AbortSignal)
  );
});

it('pins release to an authorized immutable request row with no narrative, body, key or revision', async () => {
  renderLegal();
  await readHolds();
  await openAction('Release request');
  expect(screen.getByRole('dialog').textContent).toContain(holdID);
  expect(screen.queryByLabelText('Reason')).toBeNull();
  expect(screen.queryByLabelText('Operation UUID')).toBeNull();
  confirm();
  await screen.findByTestId('legal-outcome');
  expect(clients[0].legal.releaseHold).toHaveBeenCalledWith(
    holdID,
    grants[0],
    expect.any(AbortSignal),
    expect.any(Function)
  );
  expect(screen.getByTestId('legal-outcome').textContent).toContain(
    'does not prove this caller changed'
  );
});

it('prevents synchronous double-submit while the transmitted response is pending', async () => {
  renderLegal();
  await openAction();
  const pending = deferred<LegalHold>();
  clients[0].legal.applyHold.mockImplementationOnce((_request, grant, _signal, sent) => {
    grant.take('private-session');
    sent?.();
    return pending.promise;
  });
  fillCreate();
  confirm();
  fireEvent.submit(screen.getByRole('form', { name: 'Confirm legal request' }));
  expect(clients[0].legal.applyHold).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve(hold()));
  await screen.findByTestId('legal-outcome');
});

it.each(['lost', 'malformed', 'post-commit 503'])(
  'treats %s creation responses as unconfirmed, clearing drafts without retransmission',
  async (mode) => {
    renderLegal();
    await openAction();
    const input = within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>(
      'Operation UUID'
    );
    clients[0].legal.applyHold.mockImplementationOnce(async (_request, grant, _signal, sent) => {
      grant.take('private-session');
      sent?.();
      throw new PortalError(
        mode === 'malformed' ? 'invalid_response' : 'service_unavailable',
        mode === 'post-commit 503' ? 503 : 0,
        mode !== 'post-commit 503'
      );
    });
    fillCreate();
    confirm();
    expect((await screen.findByTestId('legal-outcome')).getAttribute('data-outcome')).toBe(
      'unconfirmed'
    );
    expect(input.value).toBe('');
    expect(screen.queryByText(operationID)).toBeNull();
    expect(screen.getByTestId('legal-interruption').textContent).toContain('exact original target');
    expect(clients[0].legal.applyHold).toHaveBeenCalledTimes(1);
    expect(clients[0].legal.holds).not.toHaveBeenCalled();
    await openAction();
    expect(
      within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>('Operation UUID').value
    ).toBe('');
    fillCreate();
    confirm();
    await screen.findByText('New legal request created.');
    expect(clients[0].stepUpVerify).toHaveBeenCalledTimes(2);
    expect(clients[0].legal.applyHold.mock.calls[1][0]).toEqual(
      clients[0].legal.applyHold.mock.calls[0][0]
    );
  }
);

it('reports an idempotency conflict without replacing a key, rollback claims or a new automatic request', async () => {
  renderLegal();
  await openAction();
  clients[0].legal.applyHold.mockRejectedValueOnce(new PortalError('idempotency_conflict', 409));
  fillCreate();
  confirm();
  expect((await screen.findByRole('alert')).textContent).toContain('Do not replace the UUID');
  expect(clients[0].legal.applyHold).toHaveBeenCalledTimes(1);
  expect(screen.queryByTestId('legal-interruption')).toBeNull();
});

it('keeps a confirmed write confirmed when an explicit subsequent list read fails', async () => {
  renderLegal();
  await openAction();
  fillCreate();
  confirm();
  await screen.findByTestId('legal-outcome');
  clients[0].legal.holds.mockRejectedValueOnce(new PortalError('audit_unavailable', 503));
  fireEvent.click(screen.getByRole('checkbox', { name: 'All original references' }));
  fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
  await screen.findByRole('alert');
  expect(screen.getByTestId('legal-outcome').getAttribute('data-outcome')).toBe('confirmed');
});

it('requests no optional metadata by default and preserves exact coverage and one-use scope on each page', async () => {
  renderLegal();
  await inquiry();
  const api = clients[0];
  expect(api.legal.lookup.mock.calls[0][0].fields).toEqual([]);
  expect(screen.queryByRole('columnheader', { name: 'Client IP' })).toBeNull();
  expect(screen.getByTestId('legal-coverage').textContent).toContain(maximum);
  expect(screen.getByTestId('legal-result-row').textContent).toContain(high);
  expect(screen.queryByText('Person@example.test')).toBeNull();
  expect(screen.queryByTestId('legal-selected-reference')).toBeNull();
  api.legal.lookup.mockResolvedValueOnce(
    lookupPage({ items: [{ ...lookupPage().items[0], seq: maximum }], next_cursor: undefined })
  );
  await openAction('Next attribution page');
  expect(api.legal.lookup).toHaveBeenCalledTimes(1);
  expect(screen.queryByLabelText('Email for attribution')).toBeNull();
  confirm();
  await waitFor(() => expect(api.legal.lookup).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  const second = (api.legal.lookup.mock.calls as unknown as unknown[][])[1];
  expect(second[0]).toEqual(api.legal.lookup.mock.calls[0][0]);
  expect(second[4]).toEqual({
    query: second[0],
    cursor: 'opaque_cursor',
    throughSeq: maximum,
    observedAt: '2026-11-01T11:00:00Z',
    afterSeq: high,
  });
  expect(api.stepUpVerify).toHaveBeenCalledTimes(2);
  expect(screen.queryByRole('button', { name: 'Next attribution page' })).toBeNull();
  expect(screen.getByTestId('legal-result-row').textContent).not.toContain(high);
});

it('fetches opt-in fields only when selected and renders their telemetry as inert text', async () => {
  renderLegal();
  await screen.findByTestId('admin-ready');
  const payload = '<script>alert(1)</script> https://example.test';
  clients[0].legal.lookup.mockResolvedValueOnce(
    lookupPage({ items: [{ ...lookupPage().items[0], user_agent: payload }] })
  );
  await inquiry(['User agent']);
  expect(clients[0].legal.lookup.mock.calls[0][0].fields).toEqual(['user_agent']);
  expect(screen.getByTestId('legal-result-row').textContent).toContain(payload);
  expect(screen.getByTestId('legal-result-row').querySelector('script, a')).toBeNull();
  const select = within(screen.getByTestId('legal-result-row')).getByRole('button', {
    name: 'Select reference',
  });
  select.focus();
  expect(select.scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', inline: 'nearest' });
});

it('selects one historical reference explicitly for an inline hold without a profile resolver or URL state', async () => {
  renderLegal();
  await screen.findByTestId('admin-ready');
  clients[0].legal.lookup.mockResolvedValueOnce(
    lookupPage({
      items: [
        lookupPage().items[0],
        {
          ...lookupPage().items[0],
          id: holdID,
          account_ref: otherReference,
          seq: '9007199254740994',
        },
      ],
    })
  );
  await inquiry([], '2');
  const rows = screen.getAllByTestId('legal-result-row');
  fireEvent.click(within(rows[1]).getByRole('button', { name: 'Select reference' }));
  expect(screen.getByTestId('legal-selected-reference').textContent).toContain(otherReference);
  await openAction();
  const input = within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>(
    'Original account reference'
  );
  expect(input.value).toBe(otherReference);
  expect(input.disabled).toBe(true);
  fillCreate();
  confirm();
  await screen.findByTestId('legal-outcome');
  expect(clients[0].legal.applyHold.mock.calls[0][0].accountRef).toBe(otherReference);
  expect(window.location.href).not.toContain(otherReference);
  expect(JSON.stringify(window.history.state)).not.toContain(otherReference);
  expect(clients[0].admin.capabilities).toHaveBeenCalledTimes(1);
});

it('withholds lost lookup results without no-match or moderation state-recovery advice', async () => {
  renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Attribution' }));
  await openAction('Start attribution inquiry');
  clients[0].legal.lookup.mockImplementationOnce(async (_query, grant, _signal, sent) => {
    grant.take('private-session');
    sent?.();
    throw new PortalError('invalid_response');
  });
  fillLookup();
  confirm();
  await screen.findByRole('alert');
  expect(screen.queryByTestId('legal-result-row')).toBeNull();
  expect(screen.queryByText(/No matching indexed/)).toBeNull();
  expect(screen.queryByText(/Read current account state/)).toBeNull();
  expect(clients[0].legal.lookup).toHaveBeenCalledTimes(1);
});

it.each(['hidden', 'pagehide', 'clear', 'peer', 'session loss'])(
  'synchronously clears detached controls and grants on %s and ignores a late write response',
  async (event) => {
    renderLegal();
    await openAction();
    const input = within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>(
      'Operation UUID'
    );
    const pending = deferred<LegalHold>();
    clients[0].legal.applyHold.mockImplementationOnce((_request, grant, _signal, sent) => {
      grant.take('private-session');
      sent?.();
      return pending.promise;
    });
    fillCreate();
    confirm();
    const api = clients[0];
    const signal = api.legal.applyHold.mock.calls[0][2];
    if (!signal) throw new Error('A legal request must be bound to its signal.');
    if (event === 'hidden') hide();
    else if (event === 'pagehide') fireEvent(window, new Event('pagehide'));
    else if (event === 'peer') act(() => peerInvalidation());
    else if (event === 'session loss')
      act(() => api.onSessionLoss?.(new PortalError('session_required', 401)));
    else act(() => clearSensitiveViews());
    expect(input.value).toBe('');
    expect(signal.aborted).toBe(true);
    expect(() => grants[0].take('private-session')).toThrow('grant_expired');
    await act(async () => pending.resolve(hold()));
    expect(screen.queryByText('New legal request created.')).toBeNull();
    expect(api.legal.applyHold).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('legal-interruption').textContent).toContain('outcome unconfirmed');
  }
);

it('clears verified inputs on real grant expiry without consuming or preserving authority', async () => {
  jest.useFakeTimers();
  grantSeconds = 1;
  renderLegal();
  await openAction();
  const input = within(screen.getByRole('dialog')).getByLabelText<HTMLInputElement>(
    'Operation UUID'
  );
  fireEvent.change(input, { target: { value: operationID } });
  act(() => jest.advanceTimersByTime(1001));
  expect(screen.getByRole('alert').textContent).toContain('Verification expired');
  expect(input.value).toBe('');
  expect(input.defaultValue).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(clients[0].legal.applyHold).not.toHaveBeenCalled();
});

it.each(['cancel', 'hide', 'unmount'])(
  'scrubs live and default values from detached text controls on %s',
  async (event) => {
    const view = renderLegal();
    const dialog = await openAction();
    const input = dialog.getByLabelText<HTMLInputElement>('Operation UUID');
    const reason = dialog.getByLabelText<HTMLTextAreaElement>('Reason');
    fireEvent.change(input, { target: { value: operationID } });
    fireEvent.change(reason, { target: { value: 'Private unsent narrative' } });
    expect(input.defaultValue).toBe(operationID);
    expect(reason.textContent).toBe('Private unsent narrative');
    if (event === 'cancel') fireEvent.click(dialog.getByRole('button', { name: 'Cancel' }));
    else if (event === 'hide') hide();
    else view.unmount();
    expect(input.value).toBe('');
    expect(input.defaultValue).toBe('');
    expect(input.getAttribute('value') ?? '').toBe('');
    expect(reason.value).toBe('');
    expect(reason.defaultValue).toBe('');
    expect(reason.textContent).toBe('');
    expect(clients[0].legal.applyHold).not.toHaveBeenCalled();
  }
);

it('switches sections without navigation and ignores late list responses even when abort is ignored', async () => {
  renderLegal();
  await screen.findByTestId('admin-ready');
  const pending = deferred<LegalHoldsPage>();
  clients[0].legal.holds.mockReturnValueOnce(pending.promise);
  const input = screen.getByLabelText<HTMLInputElement>('Original account reference');
  fireEvent.change(input, { target: { value: reference } });
  fireEvent.click(screen.getByRole('button', { name: 'Read Legal Holds' }));
  fireEvent.click(screen.getByRole('button', { name: 'Attribution' }));
  expect(input.value).toBe('');
  expect(clients[0].legal.holds.mock.calls[0][1]?.aborted).toBe(true);
  await act(async () => pending.resolve({ items: [hold()], total: 1, limit: 2, offset: 0 }));
  expect(screen.queryByTestId('legal-hold-row')).toBeNull();
  expect(screen.getByRole('button', { name: 'Attribution' }).getAttribute('aria-pressed')).toBe(
    'true'
  );
  fireEvent.click(screen.getByRole('button', { name: 'Legal Holds' }));
  expect(screen.getByLabelText<HTMLInputElement>('Original account reference').value).toBe('');
  expect(window.location.search).toBe('');
  expect(window.location.hash).toBe('');
});

it('retains only a waiting TOTP operation name and reenters an empty query after same-session revalidation', async () => {
  renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Attribution' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start attribution inquiry' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
  const old = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(old, { target: { value: '123456' } });
  hide();
  expect(old.value).toBe('');
  expect(old.defaultValue).toBe('');
  expect(old.getAttribute('value') ?? '').toBe('');
  show();
  await screen.findByRole('dialog', { name: 'Attribution inquiry' });
  expect(clients[1].stepUpChallenge).not.toHaveBeenCalled();
  expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  const code = await screen.findByLabelText<HTMLInputElement>('Authenticator code');
  expect(code.value).toBe('');
  fireEvent.change(code, { target: { value: '654321' } });
  fireEvent.submit(screen.getByRole('form', { name: 'Step-up authenticator verification' }));
  expect((await screen.findByLabelText<HTMLInputElement>('Email for attribution')).value).toBe('');
  expect(clients.every((api) => api.legal.lookup.mock.calls.length === 0)).toBe(true);
});

it.each(['capability', 'session'])(
  'does not resume even a waiting legal operation when %s changes',
  async (change) => {
    renderLegal();
    fireEvent.click(await screen.findByRole('button', { name: 'Apply Legal Hold' }));
    fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
    hide();
    if (change === 'capability')
      nextCapabilities = async () => ({
        ...permissions(),
        capabilities: { ...permissions().capabilities, legal_holds_apply: false },
      });
    else
      nextBootstrap = async () => ({
        ...profile(),
        session: { ...profile().session, id: 'replacement-session' },
      });
    show();
    await screen.findByTestId('admin-ready');
    expect(screen.queryByRole('dialog')).toBeNull();
  }
);

it('clears a forbidden privileged view and rechecks capabilities without ordinary logout', async () => {
  renderLegal();
  await readHolds();
  clients[0].legal.releaseHold.mockRejectedValueOnce(new PortalError('forbidden', 403));
  await openAction('Release request');
  confirm();
  expect((await screen.findByRole('alert')).textContent).toContain(
    'Administrative access was denied'
  );
  expect(screen.queryByTestId('legal-hold-row')).toBeNull();
  expect(clients[0].logout).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Check access again' }));
  await screen.findByTestId('admin-ready');
  expect(clients[1].admin.capabilities).toHaveBeenCalledTimes(1);
  expect(clients[1].legal.holds).not.toHaveBeenCalled();
});

it.each([
  ['en', 'DPO and Legal'],
  ['fa-IR', 'مسئول حفاظت از داده و امور حقوقی'],
] as const)('resolves legal metadata per request in %s', async (locale, title) => {
  mockMetadataLocale = locale;
  expect(await generateMetadata()).toEqual({ title });
});

it.each([
  ['idempotency_conflict', 409, 'legal.failure.conflict'],
  ['hold_not_found', 404, 'legal.failure.notFound'],
  ['insufficient_user_authentication', 403, 'legal.failure.verification'],
  ['grant_expired', 0, 'legal.failure.verification'],
  ['forbidden', 403, 'legal.failure.denied'],
  ['session_required', 401, 'legal.failure.session'],
  ['session_changed', 0, 'legal.failure.session'],
  ['not_found', 404, 'legal.failure.unavailable'],
  ['rate_limited', 429, 'legal.failure.rateLimited'],
  ['invalid_request', 400, 'legal.failure.invalidRequest'],
  ['unsupported_identifier_type', 400, 'legal.failure.invalidRequest'],
  ['invalid_response', 200, 'legal.failure.invalidResponse'],
  ['response_too_large', 200, 'legal.failure.invalidResponse'],
  ['audit_unavailable', 503, 'legal.failure.service'],
] as const)('keeps the safe %s distinction as a stable descriptor', (code, status, key) => {
  expect(legalFailureMessage(new PortalError(code, status))).toEqual({ key });
});

it('never promotes arbitrary exceptions to translated or raw legal feedback', () => {
  expect(legalFailureMessage(new Error('private narrative / internal database exception'))).toEqual(
    {
      key: 'legal.failure.unknown',
    }
  );
  const failure = new PortalError('rate_limited', 429, false, 17);
  expect(legalFailureMessage(failure)).toEqual({
    key: 'legal.failure.retryAfter',
    values: { seconds: 17 },
  });
});

it('translates validation and a pending bounded read without widening or replaying the query', async () => {
  const view = renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Read Legal Holds' }));
  expect(screen.getByRole('alert').textContent).toContain('never becomes an all-subject');
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByRole('heading', { name: 'مسئول حفاظت از داده و امور حقوقی' })).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toContain(
    'ورودی نامعتبر هرگز به پرس‌وجوی همه اشخاص تبدیل نمی‌شود'
  );
  const input = screen.getByLabelText<HTMLInputElement>('شناسه اصلی حساب');
  const readRegion = screen.getByRole('region', { name: 'خواندن درخواست‌های مستقل' });
  expect(input.dir).toBe('ltr');
  fireEvent.change(input, { target: { value: reference } });
  const pending = deferred<LegalHoldsPage>();
  const api = clients[0];
  api.legal.holds.mockReturnValueOnce(pending.promise);
  fireEvent.click(screen.getByRole('button', { name: 'خواندن دستورهای نگهداشت حقوقی' }));
  expect(within(readRegion).getByRole('status').textContent).toContain(
    'در حال خواندن یک صفحه محدود'
  );
  const signal = api.legal.holds.mock.calls[0][1];
  view.rerender(legalTree());
  expect(within(readRegion).getByRole('status').textContent).toContain(
    'Loading one bounded Legal Holds page'
  );
  expect(screen.getByLabelText('Original account reference')).toBe(input);
  expect(input.value).toBe(reference);
  expect(signal?.aborted).toBe(false);
  await act(async () => pending.resolve({ items: [hold()], total: 1, limit: 2, offset: 0 }));
  view.rerender(legalTree('fa-IR'));
  const row = await screen.findByTestId('legal-hold-row');
  expect(within(row).getByRole('button', { name: 'مشاهده جزئیات محدودشده' })).toBeTruthy();
  expect(within(row).getByText(holdID).closest('bdi')?.dir).toBe('ltr');
  expect(within(readRegion).getByRole('status').textContent).toContain(
    'فهرست ثابت چندصفحه‌ای نیست'
  );
  expect(api.legal.holds).toHaveBeenCalledTimes(1);
  expect(api.legal.holds.mock.calls[0][0]).toEqual({
    accountRef: reference,
    status: 'active',
    limit: 2,
    offset: 0,
  });
  expect(api.stepUpChallenge).not.toHaveBeenCalled();
  expect(api.bootstrap).toHaveBeenCalledTimes(1);
  expect(clients).toHaveLength(1);
  expect(api.dispose).not.toHaveBeenCalled();
});

it('keeps the held grant, frozen tuple and final confirmation across locale changes without replay', async () => {
  const view = renderLegal();
  await openAction();
  const api = clients[0];
  const clear = jest.spyOn(grants[0], 'clear');
  const deadline = grants[0].deadline;
  const narrative = 'دلیل حقوقی پرونده Case-41 <script>alert(1)</script>';
  const input = within(screen.getByRole('dialog')).getByLabelText<HTMLTextAreaElement>('Reason');
  expect(input.dir).toBe('auto');
  fillCreate('hold', {
    Reason: `  ${narrative}  `,
    'Review at (UTC)': '2020-01-01T00:00:00.123456Z',
  });
  expect(input.value).toBe('');
  const form = screen.getByRole('form', { name: 'Confirm legal request' });
  const reviewDialog = screen.getByRole('dialog');
  const reviewHeading = within(reviewDialog).getByRole('heading', { name: 'Apply Legal Hold' });
  const cancelReview = within(reviewDialog).getByRole('button', { name: 'Cancel' });
  const confirmReview = within(reviewDialog).getByRole<HTMLButtonElement>('button', { name: 'Confirm Legal Hold' });
  expect(confirmReview.form).toBe(form);
  const acknowledgement = within(form).getByRole<HTMLInputElement>('checkbox');
  fireEvent.click(acknowledgement);
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByRole('form', { name: 'تأیید درخواست حقوقی' })).toBe(form);
  expect(screen.getByRole('dialog')).toBe(reviewDialog);
  expect(within(reviewDialog).getByRole('heading', { name: 'اعمال دستور نگهداشت حقوقی' })).toBe(reviewHeading);
  expect(within(reviewDialog).getByRole('button', { name: 'لغو' })).toBe(cancelReview);
  expect(within(reviewDialog).getByRole('button', { name: 'تأیید نگهداشت حقوقی' })).toBe(confirmReview);
  expect(acknowledgement.checked).toBe(true);
  expect(within(form).getByText(narrative).closest('bdi')?.dir).toBe('auto');
  expect(form.querySelector('script, a')).toBeNull();
  expect(within(form).getByText(operationID).closest('bdi')?.dir).toBe('ltr');
  expect(form.textContent).toContain('2020-01-01 00:00:00.123456 UTC');
  expect(form.textContent).toContain('هر درخواست مستقل است');
  expect(form.textContent).toContain('اگر فقط رکورد نشانه باقی مانده');
  expect(clear).not.toHaveBeenCalled();
  expect(grants[0].deadline).toBe(deadline);
  const pending = deferred<LegalHold>();
  api.legal.applyHold.mockImplementationOnce((_request, grant, _signal, sent) => {
    grant.take('private-session');
    sent?.();
    return pending.promise;
  });
  fireEvent.submit(form);
  expect(
    screen.getByRole<HTMLButtonElement>('button', { name: 'در حال ارسال درخواست حقوقی…' }).disabled
  ).toBe(true);
  const signal = api.legal.applyHold.mock.calls[0][2];
  view.rerender(legalTree());
  expect(screen.getByRole('form', { name: 'Confirm legal request' })).toBe(form);
  expect(
    screen.getByRole<HTMLButtonElement>('button', { name: 'Submitting legal request...' }).disabled
  ).toBe(true);
  fireEvent.submit(form);
  expect(signal?.aborted).toBe(false);
  expect(api.legal.applyHold).toHaveBeenCalledTimes(1);
  expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
  expect(grants[0].deadline).toBe(deadline);
  await act(async () =>
    pending.resolve(hold({ reason: narrative, review_at: '2020-01-01T00:00:00.123456Z' }))
  );
  expect((await screen.findByTestId('legal-outcome')).getAttribute('data-outcome')).toBe(
    'confirmed'
  );
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByTestId('legal-outcome').textContent).toContain('درخواست حقوقی جدید ایجاد شد');
  expect(api.legal.applyHold.mock.calls[0][0]).toEqual({
    accountRef: reference,
    requestId: operationID,
    reason: narrative,
    requestingAuthority: 'Authority',
    legalBasis: 'Reviewed legal basis',
    reviewAt: '2020-01-01T00:00:00.123456Z',
  });
  expect(Object.isFrozen(api.legal.applyHold.mock.calls[0][0])).toBe(true);
  expect(api.legal.applyHold).toHaveBeenCalledTimes(1);
  expect(api.legal.holds).not.toHaveBeenCalled();
  expect(clients).toHaveLength(1);
  expect(screen.queryByTestId('legal-interruption')).toBeNull();
  hide();
  expect(screen.queryByTestId('legal-outcome')).toBeNull();
});

it('translates held-grant validation without clearing private drafts or extending expiry', async () => {
  jest.useFakeTimers();
  grantSeconds = 2;
  const view = renderLegal();
  await openAction();
  fillCreate('hold', { 'Operation UUID': 'invalid-uuid' });
  const input = screen.getByLabelText<HTMLInputElement>('Operation UUID');
  const clear = jest.spyOn(grants[0], 'clear');
  const deadline = grants[0].deadline;
  act(() => jest.advanceTimersByTime(1000));
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByRole('alert').textContent).toContain('UUIDهای استاندارد و غیرصفر');
  expect(screen.getByLabelText('UUID عملیات')).toBe(input);
  expect(input.value).toBe('invalid-uuid');
  expect(clear).not.toHaveBeenCalled();
  expect(grants[0].deadline).toBe(deadline);
  act(() => jest.advanceTimersByTime(1001));
  expect(screen.getByRole('alert').textContent).toContain('اعتبار تأیید هویت منقضی شد');
  expect(input.value).toBe('');
  expect(input.defaultValue).toBe('');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(clients[0].legal.applyHold).not.toHaveBeenCalled();
  expect(clients[0].stepUpVerify).toHaveBeenCalledTimes(1);
});

it('preserves waiting TOTP work on locale rerender but still clears it on privacy suspension', async () => {
  const view = renderLegal();
  fireEvent.click(await screen.findByRole('button', { name: 'Attribution' }));
  fireEvent.click(screen.getByRole('button', { name: 'Start attribution inquiry' }));
  fireEvent.click(screen.getByRole('button', { name: 'Continue to verification' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Use authenticator code' }));
  const code = screen.getByLabelText<HTMLInputElement>('Authenticator code');
  fireEvent.change(code, { target: { value: '123456' } });
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByRole('dialog', { name: 'استعلام انتساب' }).contains(code)).toBe(true);
  expect(code.value).toBe('123456');
  expect(clients[0].stepUpChallenge).toHaveBeenCalledTimes(1);
  expect(clients[0].stepUpVerify).not.toHaveBeenCalled();
  expect(clients).toHaveLength(1);
  hide();
  expect(code.value).toBe('');
  expect(code.defaultValue).toBe('');
  expect(clients[0].legal.lookup).not.toHaveBeenCalled();
});

const preservationNote =
  'preservation does not restore purged data; ingestion may still be pending; account and ledger presence are observations, not completeness guarantees; expires_at is advisory only';
const coverageNote =
  'matching indexed retained records only; ingestion may be pending; unindexed or purged history is not covered; separate account references do not establish one person';
const unknownNote =
  '<script>alert(1)</script> https://example.test یادداشت جدید\nRaw original note';

it.each([preservationNote, unknownNote])(
  'localizes preservation explanations without altering original note %p',
  async (note) => {
    const view = renderLegal();
    fireEvent.click(await screen.findByRole('button', { name: 'Preservation' }));
    await openAction('Record preservation');
    const api = clients[0];
    const response: LegalPreservationResult = {
      hold: hold({ request_kind: 'preservation', legal_basis: 'preservation_request' }),
      replayed: false,
      account_present: false,
      ledger_evidence_present: false,
      observed_at: '2026-11-01T11:00:00.123456Z',
      note,
    };
    api.legal.preserve.mockImplementationOnce(async (_request, grant, _signal, sent) => {
      grant.take('private-session');
      sent?.();
      return response;
    });
    fillCreate('preservation');
    confirm();
    await screen.findByTestId('legal-outcome');
    view.rerender(legalTree('fa-IR'));
    const outcome = screen.getByTestId('legal-outcome');
    expect(outcome.hasAttribute('data-legal-private')).toBe(true);
    expect(outcome.textContent).toContain('حتی اگر هر دو مشاهده منفی باشند، نگهداشت معتبر است');
    expect(outcome.textContent).toContain('جست‌وجو و ایجاد نگهداشت دو تراکنش جداگانه‌اند');
    expect(outcome.textContent).toContain('2026-11-01 11:00:00.123456 UTC');
    if (note === preservationNote) {
      expect(outcome.textContent).toContain(
        'حفظ پیشگیرانه، داده‌های پاک‌سازی‌شده را بازنمی‌گرداند'
      );
      expect(outcome.textContent).toContain('ممکن است ورود داده‌ها هنوز در انتظار انجام باشد');
      expect(outcome.textContent).toContain('نه تضمین کامل بودن');
      expect(outcome.textContent).toContain('نگهداشت را خودکار لغو نمی‌کند');
      expect(
        within(outcome).getByText('یادداشت اصلی سرور (بدون تغییر)').closest('details')
      ).not.toBeNull();
      expect(outcome.querySelector('details bdi')?.textContent).toBe(note);
    } else {
      expect(outcome.textContent).toContain('این یادداشت سرور از توضیحات ثابت شناخته‌شده نیست');
      expect(outcome.querySelector('details')).toBeNull();
      expect(outcome.textContent).not.toContain(
        'حفظ پیشگیرانه، داده‌های پاک‌سازی‌شده را بازنمی‌گرداند'
      );
    }
    expect(outcome.textContent).toContain(note);
    expect(outcome.querySelector('script, a')).toBeNull();
    expect(response.note).toBe(note);
    view.rerender(legalTree());
    expect(screen.getByTestId('legal-outcome').textContent).toContain(note);
    expect(api.legal.preserve).toHaveBeenCalledTimes(1);
    expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
    expect(clients).toHaveLength(1);
    hide();
    expect(screen.queryByTestId('legal-outcome')).toBeNull();
  }
);

it.each([coverageNote, `${coverageNote} `, unknownNote])(
  'uses only exact known attribution notes and preserves final evidence across locales: %p',
  async (note) => {
    const view = renderLegal();
    await screen.findByTestId('admin-ready');
    const api = clients[0];
    const response = lookupPage({
      next_cursor: undefined,
      coverage: {
        ...lookupPage().coverage,
        note,
        observed_at: '2026-11-01T11:00:00.123456789Z',
        eligibility_checked_at: '2026-11-01T11:00:00.123456789Z',
      },
    });
    api.legal.lookup.mockResolvedValueOnce(response);
    await inquiry();
    const row = screen.getByTestId('legal-result-row');
    const heading = screen.getByRole('columnheader', { name: 'Original account reference' });
    view.rerender(legalTree('fa-IR'));
    expect(screen.getByRole('columnheader', { name: 'شناسه اصلی حساب' })).toBe(heading);
    expect(screen.getByTestId('legal-result-row')).toBe(row);
    expect(within(row).getByText(high).closest('bdi')?.dir).toBe('ltr');
    const coverage = screen.getByTestId('legal-coverage');
    expect(within(coverage).getByText(maximum).closest('bdi')?.dir).toBe('ltr');
    expect(coverage.textContent).toContain('2026-11-01 11:00:00.123456789 UTC');
    expect(coverage.textContent).toContain(note);
    if (note === coverageNote) {
      expect(coverage.textContent).toContain(
        'پوشش فقط شامل سوابق نگهداری‌شده و نمایه‌شده‌ای است که مطابقت دارند'
      );
      expect(coverage.textContent).toContain('تاریخچه نمایه‌نشده یا پاک‌سازی‌شده در این پوشش نیست');
      expect(coverage.textContent).toContain('متعلق به یک شخص هستند');
      expect(coverage.querySelector('details bdi')?.textContent).toBe(note);
    } else {
      expect(coverage.textContent).toContain('این یادداشت سرور از توضیحات ثابت شناخته‌شده نیست');
      expect(coverage.querySelector('details')).toBeNull();
    }
    expect(coverage.querySelector('script, a')).toBeNull();
    expect(
      screen.getByText('نشانگر ادامه‌ای بازگردانده نشد. این نتیجه به معنای کامل بودن تاریخچه نیست.')
    ).toBeTruthy();
    expect(response.coverage.note).toBe(note);
    expect(screen.queryByText('Person@example.test')).toBeNull();
    expect(api.legal.lookup).toHaveBeenCalledTimes(1);
    expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
    expect(clients).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'پاک کردن استعلام' }));
    expect(screen.queryByTestId('legal-coverage')).toBeNull();
    expect(screen.queryByTestId('legal-result-row')).toBeNull();
  }
);

it('keeps unconfirmed writes distinct and unreplayed when the language changes after failure', async () => {
  const view = renderLegal();
  await openAction();
  const api = clients[0];
  api.legal.applyHold.mockImplementationOnce(async (_request, grant, _signal, sent) => {
    grant.take('private-session');
    sent?.();
    throw new PortalError('service_unavailable', 503);
  });
  fillCreate();
  confirm();
  await screen.findByTestId('legal-outcome');
  view.rerender(legalTree('fa-IR'));
  expect(screen.getByTestId('legal-outcome').getAttribute('data-outcome')).toBe('unconfirmed');
  expect(screen.getByText(/نتیجه عملیات نوشتن حقوقی تأیید نشده است/)).toBeTruthy();
  expect(screen.queryByText(operationID)).toBeNull();
  expect(api.legal.applyHold).toHaveBeenCalledTimes(1);
  expect(api.legal.holds).not.toHaveBeenCalled();
  expect(api.stepUpVerify).toHaveBeenCalledTimes(1);
  expect(clients).toHaveLength(1);
});
