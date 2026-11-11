import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { localizedText, setBrowserLocale, setBrowserTheme } from '../../.github/scripts/browser-localization.mjs';
import {
  addAuthenticator, api as portalAPI, newContext, operationResponse, signIn, visit,
} from '../../.github/scripts/web-portal.browser.mjs';

// Legal seed references belong to the harness run, not the locale. Its inserts
// are deliberately not idempotent; each locale still creates new real requests.
const legalSeeds = new WeakMap();
const stateIDs = [
  'admin-baseline', 'admin-no-access', 'admin-navigation-closed', 'admin-navigation-open',
  'admin-users-baseline', 'admin-users-populated', 'admin-users-table-view', 'admin-users-empty', 'admin-users-support-read-only', 'admin-users-support-table-view',
  'admin-user-baseline', 'admin-user-moderation-entry', 'admin-user-moderation-review', 'admin-user-moderation-enabled',
  'admin-audit-baseline', 'admin-audit-populated', 'admin-audit-table-view', 'admin-audit-audit-detail-dialog',
  'admin-integrity-baseline', 'admin-integrity-ledger-form', 'admin-integrity-audit-report', 'admin-integrity-ledger-report',
  'admin-legal-baseline', 'admin-legal-holds-populated', 'admin-legal-holds-table-view', 'admin-legal-preservation-form',
  'admin-legal-attribution-form', 'admin-legal-hold-review', 'admin-legal-release-review',
  'admin-legal-attribution-review', 'admin-legal-attribution-results', 'admin-legal-attribution-table-view',
];
const valueMasks = ['main bdi', 'main time', 'main pre', 'main code'];
const masks = {
  overview: valueMasks,
  users: valueMasks,
  detail: [...valueMasks, 'main dd'],
  audit: [...valueMasks, 'main dd'],
  integrity: [...valueMasks, 'main dd', '[data-testid="verification-page"] details'],
  // Preserve only fixed request/status labels and controls, never legal evidence,
  // identifiers, narratives, timestamps, technical notes or optional disclosures.
  legal: [...valueMasks, 'main dd', '[data-testid="legal-coverage"]',
    '[data-legal-private] details'],
};

export async function adminViews(api, harness, browser) {
  setBrowserLocale(api.locale);
  assert.deepEqual([...stateIDs].sort(), api.views.filter(view => view.surface === 'admin').map(view => view.id).sort(),
    'Admin gallery IDs must match the declared core manifest');
  assert(/^https:\/\/localhost:\d+$/.test(harness.origin) && typeof harness.tlsSPKI === 'string',
    'Admin gallery requires the caller-owned trusted HTTPS harness');
  const contexts = [];
  const actors = new Map();
  let target;
  let legalFixture;
  let holdID;
  const holdKey = randomUUID();
  const preservationKey = randomUUID();
  const button = (root, name) => root.getByRole('button', { name: localizedText(name), exact: true });
  const field = (root, name) => root.getByLabel(localizedText(name), { exact: true });
  const capture = (page, id, heading, kind, modal = false, role = 'combined', options = {}) =>
    api.capture(page, id, { heading, modal, sensitiveSelectors: masks[kind], sensitive: true, role, ...options });

  async function stage(role, name, operation) {
    try { return await operation(); }
    catch (error) {
      console.log(JSON.stringify({ adminGalleryStage: name, role,
        category: error?.name === 'TimeoutError' ? 'readiness-timeout' : 'operation-unavailable' }));
      throw error;
    }
  }

  function actor(role) {
    if (!actors.has(role)) actors.set(role, (async () => {
      const fixture = await stage(role, 'actor-fixture', () => harness.fixture('admin-seed', { role }));
      const { context, observed } = await stage(role, 'actor-context', () => newContext(browser, harness));
      contexts.push(context);
      api.contexts.add(context);
      const page = await context.newPage();
      await stage(role, 'actor-authenticator', () => addAuthenticator(page, fixture.credentials[0]));
      await stage(role, 'actor-admission-window', () => api.beforeSignIn());
      await stage(role, 'actor-sign-in', () => signIn(page, harness.origin));
      await stage(role, 'actor-profile', async () => {
        const profile = await portalAPI(page, '/api/v1/users/me');
        assert.equal(profile.status, 200, 'Actor requires a real DPoP account session');
        assert(profile.body.id === fixture.user_id, 'Passkey must admit the intended disposable actor');
      });
      return { page, fixture, observed, verificationTimes: [] };
    })());
    return actors.get(role);
  }

  async function open(role, path, heading, capability) {
    const current = await actor(role);
    await stage(role, 'admin-document', () => visit(current.page, harness.origin, path));
    await stage(role, 'admin-ready', () => current.page.getByTestId('admin-ready').waitFor({ state: 'visible' }));
    await stage(role, 'admin-heading', () => current.page.getByRole('heading', { name: localizedText(heading), exact: true }).waitFor());
    if (capability) {
      const response = await stage(role, 'admin-capabilities', () => portalAPI(current.page, '/api/v1/admin/capabilities'));
      assert.equal(response.status, 200);
      assert.equal(response.body.capabilities[capability], true, 'Required admin capability unavailable');
      if (role === 'support') assert.equal(response.body.capabilities.users_pii, false);
    }
    return current;
  }

  async function submit(page, path, method, action, status = 200) {
    const response = operationResponse(page, path, method);
    void response.catch(() => {});
    await action();
    assert.equal((await response).status(), status, 'Real admin operation was not confirmed');
  }

  async function cancel(page) {
    if (await page.getByTestId('stepup-dialog').count()) {
      await page.keyboard.press('Escape');
      await page.getByTestId('stepup-dialog').waitFor({ state: 'hidden' });
    }
  }

  async function verify(current, action, readiness, root = current.page) {
    const { page, verificationTimes } = current;
    await cancel(page);
    await setBrowserTheme(page, 'system');
    // Retain the real production rate window if a slow capture needs fresh
    // verification. Waiting never extends a grant or retransmits an operation.
    if (verificationTimes.length >= 5) {
      const wait = verificationTimes.at(-5) + 61_000 - Date.now();
      if (wait > 0) await delay(wait);
    }
    await page.bringToFront();
    await button(root, action).click();
    const dialog = page.getByTestId('stepup-dialog');
    await dialog.waitFor({ state: 'visible' });
    await button(dialog, 'Continue to verification').click();
    const verifiedAt = Date.now();
    verificationTimes.push(verifiedAt);
    await submit(page, '/api/v1/auth/stepup/verify', 'POST',
      () => button(dialog, 'Verify with a passkey').click());
    await (typeof readiness === 'string' ? field(dialog, readiness) : readiness).waitFor({ state: 'visible' });
    return { dialog, verifiedAt };
  }

  async function section(current, name) {
    await cancel(current.page);
    await current.page.bringToFront();
    const control = button(current.page, name);
    await control.click();
    assert.equal(await control.getAttribute('aria-pressed'), 'true');
  }

  async function prepareCreate(current, kind, operationID) {
    const isHold = kind === 'hold';
    await section(current, isHold ? 'Legal Holds' : 'Preservation');
    const verified = await verify(current, isHold ? 'Apply Legal Hold' : 'Record preservation', 'Reason');
    for (const [name, value] of [
      ['Original account reference', legalFixture.deleted_account_ref], ['Operation UUID', operationID],
      ['Reason', 'Disposable visual-review preservation request'],
      ['Requesting authority', 'Local fixture authority'],
      ...(isHold ? [['Legal basis', 'Disposable fixture only']] : []),
      [isHold ? 'Review at (UTC)' : 'Expires at (UTC)', '2020-01-01T00:00:00.000Z'],
    ]) await field(verified.dialog, name).fill(value);
    return verified;
  }

  async function review(verified) {
    await button(verified.dialog, 'Review request').click();
    await verified.dialog.getByRole('form', { name: localizedText('Confirm legal request'), exact: true }).waitFor();
    return verified;
  }

  async function freshIfNeeded(verified, prepare) {
    if (Date.now() - verified.verifiedAt > 10_000 || !(await verified.dialog.isVisible()))
      return prepare(); // Only unsent form/review state is reconstructed.
    return verified;
  }

  async function confirm(current, verified, name, path, method, status) {
    await verified.dialog.getByRole('checkbox', { name: localizedText(/^I reviewed /) }).check();
    await submit(current.page, path, method, () => button(verified.dialog, name).click(), status);
    await current.page.getByTestId('legal-outcome').waitFor({ state: 'visible' });
    assert.equal(await current.page.getByTestId('legal-outcome').getAttribute('data-outcome'), 'confirmed');
  }

  async function readHolds(current) {
    assert(holdID, 'A real gallery hold must precede its listing/release');
    await section(current, 'Legal Holds');
    const form = current.page.getByRole('form', { name: localizedText('Read Legal Holds'), exact: true });
    await field(form, 'Original account reference').fill(legalFixture.deleted_account_ref);
    await field(form, 'Hold status').selectOption('all');
    await field(form, 'Page size').fill('20');
    await submit(current.page, '/api/v1/admin/legal-holds', 'GET', () => button(form, 'Read Legal Holds').click());
    await current.page.getByTestId('legal-hold-row').filter({ hasText: holdID }).waitFor();
  }

  async function prepareLookup(current) {
    assert(legalFixture && harness.fixture('admin-legal-state', {
      account_ref: legalFixture.deleted_account_ref,
    }).eligible_records > 0, 'Attribution requires genuinely eligible preserved evidence');
    await section(current, 'Attribution');
    const verified = await verify(current, 'Start attribution inquiry', 'Email for attribution');
    for (const [name, value] of [
      ['Email for attribution', legalFixture.email], ['Requesting authority', 'Local fixture authority'],
      ['Case reference', 'Disposable gallery case'], ['Inquiry purpose', 'Local demo visual review only'],
      ['Start time (UTC)', legalFixture.start_time], ['End time (UTC)', legalFixture.end_time], ['Page size', '20'],
    ]) await field(verified.dialog, name).fill(value);
    // Core-only projection: do not opt into additional private metadata.
    assert.equal(await verified.dialog.locator('input[type="checkbox"]:checked').count(), 0);
    return verified;
  }

  try {
    await api.group(['admin-baseline', 'admin-navigation-closed', 'admin-navigation-open'], async () => {
      const current = await open('combined', '/admin', 'Admin control panel', 'users_status_write');
      await stage('combined', 'overview-legal-link', () =>
        current.page.getByRole('main').locator('a[href="/admin/legal"]').waitFor());
      await capture(current.page, 'admin-baseline', 'Admin control panel', 'overview');
      for (const id of ['admin-navigation-closed', 'admin-navigation-open']) await capture(current.page, id, 'Admin control panel', 'overview');
    });
    await api.group(['admin-no-access'], async () => {
      const current = await actor('ordinary');
      await visit(current.page, harness.origin, '/admin');
      await current.page.getByRole('main').getByRole('heading', { name: localizedText('Administration'), exact: true }).waitFor();
      await current.page.getByRole('link', { name: localizedText('Return to account'), exact: true }).waitFor();
      assert.equal(await current.page.getByTestId('admin-ready').count(), 0);
      assert.equal((await portalAPI(current.page, '/api/v1/admin/capabilities')).status, 403);
      assert.equal((await portalAPI(current.page, '/api/v1/users/me')).status, 200);
      await capture(current.page, 'admin-no-access', 'Administration', 'overview', false, 'ordinary');
    });
    await api.group(['admin-users-baseline'], async () => {
      const current = await open('combined', '/admin/users', 'Accounts', 'users_pii');
      await button(current.page, 'Apply filters').waitFor();
      assert.equal(await current.page.getByTestId('admin-account-row').count(), 0);
      await capture(current.page, 'admin-users-baseline', 'Accounts', 'users');
    });
    await api.group(['admin-users-populated', 'admin-users-table-view'], async () => {
      const current = await open('combined', '/admin/users', 'Accounts', 'users_read');
      await submit(current.page, '/api/v1/admin/users', 'GET', () => button(current.page, 'Apply filters').click());
      await current.page.getByTestId('admin-account-row').first().waitFor();
      await capture(current.page, 'admin-users-populated', 'Accounts', 'users');
      await capture(current.page, 'admin-users-table-view', 'Accounts', 'users');
    });
    await api.group(['admin-users-empty'], async () => {
      const current = await open('combined', '/admin/users', 'Accounts', 'users_read');
      await field(current.page, 'Account status').selectOption('banned');
      await submit(current.page, '/api/v1/admin/users', 'GET', () => button(current.page, 'Apply filters').click());
      await current.page.getByText(localizedText('No accounts returned on this page for the selected status.'), { exact: true }).waitFor();
      assert.equal(await current.page.getByTestId('admin-account-row').count(), 0);
      await capture(current.page, 'admin-users-empty', 'Accounts', 'users');
    });
    await api.group(['admin-users-support-read-only', 'admin-users-support-table-view'], async () => {
      const current = await open('support', '/admin/users', 'Accounts', 'users_read');
      assert.equal(await field(current.page, 'Exact email').count(), 0);
      await submit(current.page, '/api/v1/admin/users', 'GET', () => button(current.page, 'Apply filters').click());
      await current.page.getByTestId('admin-account-row').first().waitFor();
      assert.equal(await current.page.getByRole('columnheader', { name: localizedText('Email'), exact: true }).count(), 0);
      await capture(current.page, 'admin-users-support-read-only', 'Accounts', 'users', false, 'support');
      await capture(current.page, 'admin-users-support-table-view', 'Accounts', 'users', false, 'support');
    });
    await api.group(['admin-user-baseline'], async () => {
      target = harness.fixture('admin-seed', { role: 'ordinary' });
      const current = await open('combined', `/admin/users/${target.user_id}`, 'Account details', 'users_status_write');
      await current.page.getByRole('heading', { name: target.user_id, exact: true }).waitFor();
      await button(current.page, 'Suspend').waitFor();
      await capture(current.page, 'admin-user-baseline', 'Account details', 'detail');
    });
    await api.group(['admin-user-moderation-entry'], async () => {
      assert(target, 'Disposable moderation subject unavailable');
      const current = await open('combined', `/admin/users/${target.user_id}`, 'Account details', 'users_status_write');
      await setBrowserTheme(current.page, 'system');
      await button(current.page, 'Suspend').click();
      await button(current.page.getByTestId('stepup-dialog'), 'Continue to verification').waitFor();
      await capture(current.page, 'admin-user-moderation-entry', 'Suspend account', 'detail', true);
      await cancel(current.page);
    });
    for (const [id, acknowledged] of [['admin-user-moderation-review', false], ['admin-user-moderation-enabled', true]]) await api.group([id], async () => {
      assert(target, 'Disposable moderation subject unavailable');
      const current = await open('combined', `/admin/users/${target.user_id}`, 'Account details', 'users_status_write');
      const prepare = async () => {
        const verified = await verify(current, 'Suspend', 'Moderation reason');
        await field(verified.dialog, 'Moderation reason').fill('Disposable gallery moderation review');
        if (acknowledged) await verified.dialog.getByRole('checkbox').check();
        assert.equal(await button(verified.dialog, 'Confirm suspend').isEnabled(), acknowledged);
        return verified;
      };
      let verified = await prepare();
      await capture(current.page, id, 'Suspend account', 'detail', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      await cancel(current.page); // This view is a review, not a requested status mutation.
      assert.equal(harness.fixture('admin-state', { user_id: target.user_id }).status, 'active');
    });
    await api.group(['admin-audit-baseline'], async () => {
      const current = await open('combined', '/admin/audit-logs', 'Audit logs', 'audit_logs_read');
      await button(current.page, 'Search audit logs').waitFor();
      assert.equal(await current.page.getByTestId('admin-audit-row').count(), 0);
      await capture(current.page, 'admin-audit-baseline', 'Audit logs', 'audit');
    });
    await api.group(['admin-audit-populated', 'admin-audit-table-view', 'admin-audit-audit-detail-dialog'], async () => {
      target ||= harness.fixture('admin-seed', { role: 'ordinary' });
      const audit = harness.fixture('admin-audit', { user_id: target.user_id });
      const current = await open('combined', '/admin/audit-logs', 'Audit logs', 'audit_logs_read');
      await field(current.page, 'Event type (exact)').fill(audit.event_type);
      await submit(current.page, '/api/v1/admin/audit-logs', 'GET', () => button(current.page, 'Search audit logs').click());
      await current.page.getByTestId('admin-audit-row').first().waitFor();
      await capture(current.page, 'admin-audit-populated', 'Audit logs', 'audit');
      await capture(current.page, 'admin-audit-table-view', 'Audit logs', 'audit');
      await setBrowserTheme(current.page, 'system');
      await current.page.getByRole('button', { name: localizedText(/^View details for sequence /) }).first().click();
      await current.page.getByTestId('admin-audit-detail').waitFor();
      await capture(current.page, 'admin-audit-audit-detail-dialog', 'Audit record details', 'audit', true);
      await current.page.keyboard.press('Escape');
    });
    for (const [id, chain, report] of [
      ['admin-integrity-baseline', 'audit', false], ['admin-integrity-ledger-form', 'ledger', false],
      ['admin-integrity-audit-report', 'audit', true], ['admin-integrity-ledger-report', 'ledger', true],
    ]) await api.group([id], async () => {
      const current = await open('combined', '/admin/integrity', 'Integrity verification',
        chain === 'audit' ? 'audit_chain_verify' : 'ledger_verify');
      await field(current.page, 'Chain').selectOption(chain);
      if (report) {
        await submit(current.page, `/api/v1/admin/${chain === 'audit' ? 'audit-logs' : 'ledger'}/verify`, 'GET',
          () => button(current.page, 'Start new run').click());
        await current.page.getByTestId('verification-page').waitFor();
      } else {
        assert.equal(await current.page.getByTestId('verification-page').count(), 0);
        assert.equal(await button(current.page, 'Continue verification').count(), 0);
        assert.equal(await button(current.page, 'Stop verification').count(), 0);
      }
      await capture(current.page, id, 'Integrity verification', 'integrity');
    });
    await api.group(['admin-legal-baseline'], async () => {
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_holds_read');
      await button(current.page, 'Apply Legal Hold').waitFor();
      assert.equal(await current.page.getByTestId('legal-hold-row').count(), 0);
      await capture(current.page, 'admin-legal-baseline', 'DPO and Legal', 'legal');
    });
    await api.group(['admin-legal-hold-review'], async () => {
      if (!legalSeeds.has(harness)) legalSeeds.set(harness, harness.fixture('admin-legal-seed'));
      legalFixture = legalSeeds.get(harness);
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_holds_apply');
      const prepare = async () => review(await prepareCreate(current, 'hold', holdKey));
      let verified = await prepare();
      await capture(current.page, 'admin-legal-hold-review', 'Apply Legal Hold', 'legal', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      verified = await freshIfNeeded(verified, prepare);
      await confirm(current, verified, 'Confirm Legal Hold', '/api/v1/admin/legal-holds', 'POST', 201);
      const state = harness.fixture('admin-legal-state', {
        account_ref: legalFixture.deleted_account_ref, operation_id: holdKey, request_kind: 'legal_hold',
      });
      assert(state.is_active && state.eligible_records > 0);
      holdID = state.hold_id;
    });
    await api.group(['admin-legal-holds-populated', 'admin-legal-holds-table-view'], async () => {
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_holds_read');
      await readHolds(current);
      await capture(current.page, 'admin-legal-holds-populated', 'DPO and Legal', 'legal');
      await capture(current.page, 'admin-legal-holds-table-view', 'DPO and Legal', 'legal');
    });
    await api.group(['admin-legal-release-review'], async () => {
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_holds_release');
      // Release is pinned by an authorized real list row, never an invented ID.
      const prepare = async () => {
        await readHolds(current);
        const row = current.page.getByTestId('legal-hold-row').filter({ hasText: holdID });
        const dialog = current.page.getByTestId('stepup-dialog');
        return verify(current, 'Release request', button(dialog, 'Confirm release'), row);
      };
      let verified = await prepare();
      await capture(current.page, 'admin-legal-release-review', 'Release Legal Hold request', 'legal', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      verified = await freshIfNeeded(verified, prepare);
      await confirm(current, verified, 'Confirm release', `/api/v1/admin/legal-holds/${holdID}`, 'DELETE', 204);
    });
    await api.group(['admin-legal-preservation-form'], async () => {
      assert(legalFixture, 'Disposable legal evidence unavailable');
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'preservation_requests_create');
      const prepare = () => prepareCreate(current, 'preservation', preservationKey);
      let verified = await prepare();
      await capture(current.page, 'admin-legal-preservation-form', 'Record preservation', 'legal', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      verified = await freshIfNeeded(verified, prepare);
      await review(verified);
      await confirm(current, verified, 'Confirm preservation', '/api/v1/admin/preservation-requests', 'POST', 201);
      assert(harness.fixture('admin-legal-state', { account_ref: legalFixture.deleted_account_ref }).eligible_records > 0);
    });
    await api.group(['admin-legal-attribution-form'], async () => {
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_inquiry_lookup');
      const prepare = () => prepareLookup(current);
      let verified = await prepare();
      await capture(current.page, 'admin-legal-attribution-form', 'Attribution inquiry', 'legal', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      await cancel(current.page);
    });
    await api.group(['admin-legal-attribution-review', 'admin-legal-attribution-results', 'admin-legal-attribution-table-view'], async () => {
      const current = await open('combined', '/admin/legal', 'DPO and Legal', 'legal_inquiry_lookup');
      const prepare = async () => review(await prepareLookup(current));
      let verified = await prepare();
      await capture(current.page, 'admin-legal-attribution-review', 'Attribution inquiry', 'legal', true, 'combined', {
        prepare: async () => { verified = await freshIfNeeded(verified, prepare); },
      });
      verified = await freshIfNeeded(verified, prepare);
      await verified.dialog.getByRole('checkbox', { name: localizedText(/^I reviewed /) }).check();
      await submit(current.page, '/api/v1/admin/legal-inquiry/lookup', 'POST', () => button(verified.dialog, 'Confirm lookup').click());
      await current.page.getByTestId('legal-coverage').waitFor();
      await current.page.getByTestId('legal-result-row').first().waitFor();
      await capture(current.page, 'admin-legal-attribution-results', 'Current attribution page', 'legal');
      await capture(current.page, 'admin-legal-attribution-table-view', 'Current attribution page', 'legal');
    });
  } finally {
    const results = await Promise.allSettled(contexts.map(async context => {
      await context.close();
      api.contexts?.delete(context);
    }));
    assert(results.every(result => result.status === 'fulfilled'), 'Owned admin contexts did not close');
  }
}
