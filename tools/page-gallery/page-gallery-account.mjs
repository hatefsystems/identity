import assert from 'node:assert/strict';
import { localizedText, setBrowserTheme, assertOnlyPreferenceCookies } from '../../.github/scripts/browser-localization.mjs';
import { newContext, addAuthenticator, signIn, visit, api as portalAPI, operationResponse, clean } from '../../.github/scripts/web-portal.browser.mjs';

// Reviewed private-value regions for readable, label-preserving demo rendering.
const profileMasks = ['main dd', '[data-testid="saved-display-name"]', 'main time'];
const securityMasks = [
  '[data-testid="passkey-row"] h3', '[data-testid="passkey-row"] p',
  '[data-testid="recovery-status"]', '[data-testid="recovery-code"]',
  '[data-testid="stepup-dialog"] bdi', 'main time',
];
const sessionMasks = ['main dd', '[data-testid="session-row"] .font-mono', '[data-testid="session-dialog"] .font-mono', 'main time'];
const privacyMasks = ['main dd', 'main time', 'main bdi', 'main .font-mono', 'main input'];
const reclaimMasks = ['[data-testid="account-recovery"] input', '[data-testid="account-recovery"] bdi', '[data-testid="account-recovery"] time', '[data-testid="account-recovery"] .font-mono'];

export async function accountViews(api, harness, browser) {
  async function owned(operation) {
    const { context, observed } = await newContext(browser, harness);
    api.contexts.add(context);
    try {
      return await operation(context, observed);
    } finally {
      await context.close();
      api.contexts.delete(context);
    }
  }

  async function signedIn(context, fixture, index = 0) {
    const page = await context.newPage();
    const authenticator = await addAuthenticator(page, fixture.credentials[index]);
    await api.beforeSignIn();
    await signIn(page, harness.origin);
    return { page, authenticator };
  }

  async function route(page, path) {
    await visit(page, harness.origin, path);
    await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  }

  async function capture(page, id, heading, masks, modal = false) {
    await api.capture(page, id, { heading, modal, sensitiveSelectors: masks, sensitive: true, role: 'ordinary' });
  }

  function response(page, path, method) {
    const pending = operationResponse(page, path, method);
    // If UI readiness fails first, context teardown must not leave an unhandled waiter.
    pending.catch(() => {});
    return pending;
  }

  async function passkeyVerification(page) {
    const dialog = page.getByTestId('stepup-dialog');
    await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
    await dialog.getByRole('button', { name: localizedText('Verify with a passkey'), exact: true }).click();
  }

  async function requestDeletion(page, fixture, includeViews = false) {
    const profile = await portalAPI(page, '/api/v1/users/me');
    assert.equal(profile.status, 200);
    assert.equal(profile.body.deletion_enabled, true, 'Disposable harness deletion is unavailable');
    await route(page, '/dashboard/privacy');
    if (includeViews) await capture(page, 'privacy-baseline', 'Privacy', privacyMasks);
    await page.getByRole('checkbox', {
      name: localizedText('I understand the account-deletion consequences and the 30-day recovery window.'), exact: true,
    }).check();
    if (includeViews) await capture(page, 'privacy-deletion-enabled', 'Privacy', privacyMasks);
    await setBrowserTheme(page, 'system');
    await page.getByRole('button', { name: localizedText('Delete my account'), exact: true }).click();
    await page.getByRole('dialog', { name: localizedText('Confirm account deletion'), exact: true }).waitFor();
    if (includeViews) await capture(page, 'privacy-deletion-dialog', 'Confirm account deletion', privacyMasks, true);
    const deleted = response(page, '/api/v1/users/me', 'DELETE');
    await passkeyVerification(page);
    assert.equal((await deleted).status(), 204);
    const outcome = page.getByTestId('deletion-outcome');
    await outcome.waitFor();
    assert.equal(await outcome.getAttribute('data-outcome'), 'confirmed');
    await outcome.getByRole('status').waitFor();
    assert.equal(await page.getByTestId('portal-ready').count(), 0);
    assert(!(await page.context().cookies(harness.origin)).some(cookie => cookie.name === '__Host-session'));
    if (includeViews) await capture(page, 'privacy-deletion-confirmed', 'Account deletion requested', privacyMasks);
    const pending = harness.fixture('deletion-state', { user_id: fixture.user_id });
    assert.equal(pending.status, 'pending_deletion');
    assert.equal(pending.requests, 1);
    return pending;
  }

  async function recover(fixture, notice, credential, totpOnly) {
    await owned(async (context, observed) => {
      // An emailed bearer link is opened only in a fresh, keyless context.
      const page = await context.newPage();
      if (credential) await addAuthenticator(page, credential);
      assertOnlyPreferenceCookies(await context.cookies(harness.origin));
      assert.equal(new URL(notice.link).origin, harness.origin);
      assert.equal(new URL(notice.link).pathname, '/recover-account');
      await visit(page, harness.origin, notice.link.slice(harness.origin.length));
      await page.waitForURL(harness.origin + '/recover-account');
      const start = page.getByRole('button', { name: localizedText('Start account recovery'), exact: true });
      await start.waitFor();
      await page.waitForFunction(button => !button.disabled, await start.elementHandle());
      const prepared = response(page, '/api/v1/auth/deletion/reclaim/options', 'POST');
      const options = harness.captureJSON('/api/v1/auth/deletion/reclaim/options', 'POST', 200);
      options.catch(() => {});
      await start.click();
      assert.equal((await prepared).status(), 200);
      const selected = await options;
      assert.equal(selected.factor, totpOnly ? 'totp' : 'webauthn');
      if (totpOnly) {
        await page.getByRole('form', { name: localizedText('Account recovery verification'), exact: true }).waitFor();
        assert.equal(await page.getByRole('button', { name: localizedText('Recover with a passkey'), exact: true }).count(), 0);
        await capture(page, 'recover-account-totp-entry', 'Recover your account', reclaimMasks);
        // Acquire the live factor only after all four entry captures, never pin a code across them.
        const factor = harness.fixture('reclaim-totp-code', { user_id: fixture.user_id });
        assert.match(factor.code, /^[0-9]{6}$/);
        await page.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(factor.code);
        factor.code = '';
      } else {
        assert.equal(selected.webauthn.publicKey.userVerification, 'required');
        await page.getByRole('button', { name: localizedText('Recover with a passkey'), exact: true }).waitFor();
        await capture(page, 'recover-account-passkey-challenge', 'Recover your account', reclaimMasks);
      }
      const completed = response(page, '/api/v1/auth/deletion/reclaim/', 'POST');
      await page.getByRole('button', {
        name: localizedText(totpOnly ? 'Recover account' : 'Recover with a passkey'), exact: true,
      }).click();
      assert.equal((await completed).status(), 204);
      const outcome = page.getByTestId('reclaim-outcome');
      await outcome.waitFor();
      assert.equal(await outcome.getAttribute('data-outcome'), 'confirmed');
      await outcome.getByRole('status').waitFor();
      assert.equal(await outcome.getByRole('link', { name: localizedText('Sign in to your account'), exact: true }).getAttribute('href'), '/login');
      assert.equal(page.url(), harness.origin + '/recover-account');
      assertOnlyPreferenceCookies(await context.cookies(harness.origin));
      assert.equal(await page.getByLabel(localizedText('Authenticator code'), { exact: true }).count(), 0);
      if (!totpOnly) await capture(page, 'recover-account-confirmed', 'Account recovered', reclaimMasks);
      assert.equal(harness.fixture('deletion-state', { user_id: fixture.user_id }).status, 'active');
      await clean(page, observed, true);
    });
  }

  await api.group(['dashboard-baseline', 'dashboard-navigation-closed', 'dashboard-navigation-open', 'profile-baseline', 'profile-editing', 'profile-conflict'], async () => {
    const fixture = harness.fixture('seed');
    await owned(async (context, observed) => {
      const { page } = await signedIn(context, fixture);
      await page.getByRole('link', { name: localizedText('Manage recovery codes'), exact: true }).waitFor();
      await capture(page, 'dashboard-baseline', 'Account overview', [
        ...profileMasks,
        '#overview-profile',
        'section[aria-labelledby="overview-passkeys"] > p:first-of-type',
        'section[aria-labelledby="overview-sessions"] > p:first-of-type',
        'section[aria-labelledby="overview-recovery"] > p',
      ]);
      for (const id of ['dashboard-navigation-closed', 'dashboard-navigation-open'])
        await capture(page, id, 'Account overview', [...profileMasks, '#overview-profile',
          'section[aria-labelledby="overview-passkeys"] > p:first-of-type',
          'section[aria-labelledby="overview-sessions"] > p:first-of-type', 'section[aria-labelledby="overview-recovery"] > p']);
      await route(page, '/dashboard/profile');
      const input = page.getByLabel(localizedText('Display name'), { exact: true });
      await input.waitFor();
      const saved = await portalAPI(page, '/api/v1/users/me');
      assert.equal(saved.status, 200);
      assert.match(saved.body.lifecycle_revision, /^(0|[1-9][0-9]*)$/);
      const form = page.getByRole('form', { name: localizedText('Edit profile'), exact: true });
      await capture(page, 'profile-baseline', 'Profile', profileMasks);
      const draft = 'Gallery unsaved profile';
      const competingName = 'Gallery competing profile';
      harness.secrets.push(draft, competingName);
      await input.fill(draft);
      await capture(page, 'profile-editing', 'Profile', profileMasks);
      // Pin the original decimal revision; the competing write must advance that same source.
      const competing = await portalAPI(page, '/api/v1/users/me', {
        method: 'PATCH', sessionID: saved.body.session.id,
        body: { display_name: competingName, expected_revision: saved.body.lifecycle_revision },
      });
      assert.equal(competing.status, 200);
      assert(competing.body.id === saved.body.id && competing.body.session.id === saved.body.session.id);
      assert(BigInt(competing.body.lifecycle_revision) > BigInt(saved.body.lifecycle_revision));
      const conflict = response(page, '/api/v1/users/me', 'PATCH');
      await page.getByRole('button', { name: localizedText('Save profile'), exact: true }).click();
      const rejected = await conflict;
      assert.equal(rejected.status(), 409);
      await form.getByRole('alert').filter({ hasText: localizedText('The saved profile changed. Refresh the saved profile, review your draft, then save again.') }).waitFor();
      await page.getByText(localizedText('Your draft is preserved. Refresh the current saved name and revision before saving again.'), { exact: true }).waitFor();
      assert.equal(await input.inputValue(), draft);
      assert.equal(await form.getByRole('button', { name: localizedText('Save profile'), exact: true }).isEnabled(), false);
      await form.getByRole('button', { name: localizedText('Refresh saved profile'), exact: true }).waitFor();
      await capture(page, 'profile-conflict', 'Profile', profileMasks);
      await clean(page, observed);
    });
  });

  await api.group(['security-baseline', 'security-passkey-rename', 'security-step-up-totp'], async () => {
    const fixture = harness.fixture('seed', { totp: true });
    await owned(async (context, observed) => {
      const { page } = await signedIn(context, fixture);
      await route(page, '/dashboard/security');
      const row = page.getByTestId('passkey-row').first();
      await row.waitFor();
      await page.getByTestId('recovery-status').waitFor();
      await capture(page, 'security-baseline', 'Security', securityMasks);
      await row.getByRole('button', { name: localizedText(/^Rename /) }).click();
      const name = 'Gallery renamed passkey';
      harness.secrets.push(name);
      await row.getByLabel(localizedText('Passkey name'), { exact: true }).fill(name);
      await capture(page, 'security-passkey-rename', 'Security', securityMasks);
      await setBrowserTheme(page, 'system');
      await row.getByRole('button', { name: localizedText('Save passkey name'), exact: true }).click();
      const dialog = page.getByTestId('stepup-dialog');
      await dialog.getByRole('button', { name: localizedText('Continue to verification'), exact: true }).click();
      await dialog.getByRole('button', { name: localizedText('Use authenticator code'), exact: true }).click();
      await dialog.getByRole('form', { name: localizedText('Step-up authenticator verification'), exact: true }).waitFor();
      await capture(page, 'security-step-up-totp', 'Rename passkey', securityMasks, true);
      const factor = harness.fixture('totp-code', { user_id: fixture.user_id });
      assert.match(factor.code, /^[0-9]{6}$/);
      await dialog.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(factor.code);
      factor.code = '';
      const renamed = response(page, `/api/v1/auth/webauthn/keys/${await row.getAttribute('data-key-id')}`, 'PATCH');
      await dialog.getByRole('button', { name: localizedText('Verify code'), exact: true }).click();
      assert.equal((await renamed).status(), 200);
      await dialog.waitFor({ state: 'hidden' });
      await page.getByRole('status').filter({ hasText: localizedText('Passkey name saved.') }).waitFor();
      await clean(page, observed);
    });
  });

  await api.group(['security-recovery-code-viewer'], async () => {
    // Independent fixture, so a cleared/expired rename cannot restore an old ceremony.
    const fixture = harness.fixture('seed');
    await owned(async (context, observed) => {
      const { page } = await signedIn(context, fixture);
      await route(page, '/dashboard/security');
      await page.getByTestId('passkey-row').first().waitFor();
      await page.getByTestId('recovery-status').waitFor();
      const generated = response(page, '/api/v1/auth/recovery-codes/generate', 'POST');
      await setBrowserTheme(page, 'system');
      await page.getByRole('button', { name: localizedText(/^(?:Generate new recovery codes|Replace recovery codes|Generate or replace recovery codes)$/), exact: true }).click();
      await passkeyVerification(page);
      assert.equal((await generated).status(), 200);
      const viewer = page.getByTestId('recovery-viewer');
      await viewer.waitFor();
      await page.getByTestId('stepup-dialog').waitFor({ state: 'hidden' });
      await page.getByTestId('recovery-status').waitFor();
      assert.equal(await viewer.getByTestId('recovery-code').count(), 10);
      await capture(page, 'security-recovery-code-viewer', 'Save your new recovery codes', securityMasks);
      // No copy/download, backgrounding, navigation, locale change or deadline adjustment.
      await viewer.getByRole('button', { name: localizedText('Done'), exact: true }).click();
      await viewer.waitFor({ state: 'hidden' });
      await clean(page, observed);
    });
  });

  await api.group(['sessions-baseline', 'sessions-remote-revoke-dialog'], async () => {
    const fixture = harness.fixture('seed', { credentials: 2 });
    await owned(async (context, observed) => {
      const { page } = await signedIn(context, fixture);
      await owned(async (remoteContext, remoteObserved) => {
        const { page: remotePage } = await signedIn(remoteContext, fixture, 1);
        const remote = await portalAPI(remotePage, '/api/v1/users/me');
        assert.equal(remote.status, 200);
        await route(page, '/dashboard/sessions');
        const row = page.locator(`[data-session-id="${remote.body.session.id}"]`);
        await row.waitFor();
        assert.equal(await page.getByTestId('session-row').count(), 2);
        await capture(page, 'sessions-baseline', 'Sessions', sessionMasks);
        await setBrowserTheme(page, 'system');
        await row.getByRole('button', { name: localizedText('Revoke session'), exact: true }).click();
        await page.getByTestId('session-dialog').waitFor();
        await capture(page, 'sessions-remote-revoke-dialog', 'Revoke this session?', sessionMasks, true);
        const revoked = response(page, `/api/v1/users/me/sessions/${remote.body.session.id}`, 'DELETE');
        await page.getByTestId('session-dialog').getByRole('button', { name: localizedText('Confirm revocation'), exact: true }).click();
        assert.equal((await revoked).status(), 204);
        await row.waitFor({ state: 'detached' });
        assert.equal((await portalAPI(remotePage, '/api/v1/users/me')).status, 401);
        await clean(remotePage, remoteObserved);
      });
      await clean(page, observed);
    });
  });

  await api.group(['privacy-baseline', 'privacy-deletion-enabled', 'privacy-deletion-dialog', 'privacy-deletion-confirmed', 'recover-account-passkey-challenge', 'recover-account-confirmed'], async () => {
    const fixture = harness.fixture('seed');
    await owned(async (context, observed) => {
      const { page, authenticator } = await signedIn(context, fixture);
      const pending = await requestDeletion(page, fixture, true);
      await clean(page, observed);
      const { credentials } = await authenticator.cdp.send('WebAuthn.getCredentials', { authenticatorId: authenticator.authenticatorId });
      // Carry the authenticator's advanced signature counter, not the original seed bytes.
      const credential = credentials.find(value => value.credentialId === fixture.credentials[0].credentialId);
      assert(credential, 'Disposable recovery credential unavailable');
      const notice = await harness.mail.waitFor(fixture.email, 1);
      assert.equal(notice.locale, api.locale);
      assert.equal(Date.parse(notice.expires_at), Date.parse(pending.expires_at));
      await harness.waitForNoticeCleanup(fixture.user_id, 1);
      await recover(fixture, notice, credential, false);
    });
  });

  await api.group(['recover-account-totp-entry'], async () => {
    // A distinct pending legacy fixture is required because passkey recovery spends its link.
    const fixture = harness.fixture('seed', { totp: true });
    await owned(async (context, observed) => {
      const { page } = await signedIn(context, fixture);
      const pending = await requestDeletion(page, fixture);
      await clean(page, observed);
      const notice = await harness.mail.waitFor(fixture.email, 1);
      assert.equal(notice.locale, api.locale);
      assert.equal(Date.parse(notice.expires_at), Date.parse(pending.expires_at));
      await harness.waitForNoticeCleanup(fixture.user_id, 1);
      // Match the existing fixture workflow: finish delivery before preparing the legacy factor.
      assert.equal(harness.fixture('reclaim-totp-only', { user_id: fixture.user_id }).totp_only, true);
      await recover(fixture, notice, null, true);
    });
  });
}
