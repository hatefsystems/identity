import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fixtureSecretValues } from './portal-harness.mjs';
import { addAuthenticator, api, clean, freshTOTP, newContext, signIn, visit } from './web-portal.browser.mjs';
import { assertOnlyPreferenceCookies, browserLocale, exercisePreferenceSwitch, localizedText, screenshotName, setBrowserTheme, waitForFonts } from './browser-localization.mjs';

const loginRoot = '/api/v1/auth/login';
export const loginJourneys = Object.freeze([
  { credentials: 'password-only', method: 'password', mfa: false, role: 'ordinary' },
  { credentials: 'password-only', method: 'email', mfa: false, role: 'ordinary' },
  { credentials: 'passkey-only', method: 'email', mfa: false, role: 'ordinary' },
  { credentials: 'passkey-only', method: 'passkey', mfa: true, role: 'support' },
  { credentials: 'dual', method: 'password', mfa: true, role: 'support' },
  { credentials: 'dual', method: 'email', mfa: true, role: 'support' },
]);

export function assertLoginChallenge(value, stage) {
  assert(['mfa', 'delivered'].includes(stage), 'Unknown login challenge stage');
  const mfa = stage === 'mfa';
  const handle = mfa ? 'preauthentication' : 'challenge';
  assert(value && Object.keys(value).sort().join(',') === [handle, 'expires_at', 'status'].sort().join(','),
    'Login challenge has unexpected public fields');
  assert(value.status === (mfa ? 'mfa_required' : 'code_requested') && /^[A-Za-z0-9_-]{43}$/.test(value[handle]) &&
    Buffer.from(value[handle], 'base64url').toString('base64url') === value[handle] &&
    Number.isFinite(Date.parse(value.expires_at)), 'Invalid bounded login challenge');
  return value;
}

function response(page, path, status) {
  return page.waitForResponse((result) => new URL(result.url()).pathname === path && result.request().method() === 'POST' &&
    !result.headers()['dpop-nonce'] && (status === undefined || result.status() === status));
}

async function noSession(page, harness, result) {
  if (result) assert(!(await result.allHeaders())['set-cookie'], 'Failed or preauthentication response set a normal cookie');
  assertOnlyPreferenceCookies(await page.context().cookies(harness.origin));
  assert.equal((await api(page, '/api/v1/users/me')).status, 401, 'First factor granted protected access');
}

async function capture(page, harness, path, status, submit) {
  const body = harness.captureJSON(path, 'POST', status);
  const completed = response(page, path, status);
  await submit();
  const result = await completed;
  const value = await body;
  harness.secrets.push(...fixtureSecretValues(value));
  return { result, value };
}

async function layout(page, state, viewport, dark, directory) {
  await waitForFonts(page);
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Login overflowed viewport');
  if (directory) await page.screenshot({ path: resolve(directory, screenshotName(`integrated-login-${state}`, viewport, dark)),
    fullPage: true, animations: 'disabled', mask: [page.locator('input, textarea, [data-private], [data-testid="portal-ready"]')] });
}

async function assertPrivate(page, observed, harness) {
  await clean(page, observed);
  assert(await page.evaluate((secrets) => {
    const state = JSON.stringify(history.state) || '';
    return secrets.every((secret) => !secret || !state.includes(secret) && !state.includes(encodeURIComponent(secret)));
  }, harness.secrets), 'Login private material entered history state');
}

async function credentials(page, fixture, method) {
  await page.getByLabel(localizedText('Username'), { exact: true }).fill(fixture.username);
  if (method === 'password') await page.getByLabel(localizedText('Password'), { exact: true }).fill(fixture.password);
}

async function requestEmail(page, harness, fixture, channel = 'email') {
  await page.getByRole('button', { name: localizedText('Username and delivered code'), exact: true }).click();
  await credentials(page, fixture, 'email');
  await page.getByLabel(localizedText('Delivery channel'), { exact: true }).selectOption(channel);
  const captured = await capture(page, harness, loginRoot + '/code/request', 202, () =>
    page.getByRole('button', { name: localizedText('Request sign-in code'), exact: true }).click());
  assertLoginChallenge(captured.value, 'delivered');
  await page.getByLabel(localizedText('Delivered sign-in code'), { exact: true }).waitFor();
  await noSession(page, harness, captured.result);
  assert.equal(await page.getByLabel(localizedText('Authenticator code'), { exact: true }).count(), 0);
  return captured.value;
}

async function totp(page, harness, fixture) {
  const factor = await freshTOTP(harness, fixture);
  await page.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(factor.code);
  const completed = response(page, loginRoot + '/mfa', 204);
  await page.getByRole('button', { name: localizedText('Verify code'), exact: true }).click();
  await completed;
}

export async function validateIntegratedLogin(browser, harness, { artifactDirectory } = {}) {
  const results = [];
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
    for (const journey of loginJourneys) {
      const fixture = harness.fixture('login-seed', { scenario: journey.credentials, totp: journey.mfa, role: journey.role });
      const { context, observed } = await newContext(browser, harness);
      try {
        const page = await context.newPage();
        await page.setViewportSize(viewport);
        const dark = viewport.width === 390;
        await visit(page, harness.origin, '/login');
        await setBrowserTheme(page, dark ? 'dark' : 'light');
        let challenge;
        if (journey.method === 'passkey') {
          await addAuthenticator(page, fixture.credentials[0]);
          await signIn(page, harness.origin, '/login/webauthn', { harness, fixture, mfa: true });
        } else if (journey.method === 'password') {
          await credentials(page, fixture, 'password');
          await exercisePreferenceSwitch(page, { privateSelector: 'input', settings: true });
          await layout(page, journey.credentials + '-password', viewport, dark, artifactDirectory);
          if (journey.mfa) {
            const captured = await capture(page, harness, loginRoot, 200, () =>
              page.getByRole('button', { name: localizedText('Sign in with password'), exact: true }).click());
            challenge = assertLoginChallenge(captured.value, 'mfa');
            await noSession(page, harness, captured.result);
          } else {
            const completed = response(page, loginRoot, 204);
            await page.getByRole('button', { name: localizedText('Sign in with password'), exact: true }).click();
            await completed;
          }
        } else {
          const requested = await requestEmail(page, harness, fixture);
          const notice = await harness.mail.waitFor(fixture.email, 1, 'login');
          assert(Date.parse(requested.expires_at) <= Date.parse(notice.expires_at) &&
            Date.parse(notice.expires_at) - Date.parse(requested.expires_at) < 20000,
          'Uniform public deadline exceeded the original sender deadline');
          assert(!(await page.locator('body').innerText()).includes(fixture.email), 'Login disclosed a private destination');
          await page.getByLabel(localizedText('Delivered sign-in code'), { exact: true }).fill(notice.code);
          await exercisePreferenceSwitch(page, { privateSelector: 'input', settings: true });
          await layout(page, journey.credentials + '-delivered', viewport, dark, artifactDirectory);
          const submit = () => page.getByRole('button', { name: localizedText('Verify delivered code'), exact: true }).click();
          if (journey.mfa) {
            const captured = await capture(page, harness, loginRoot + '/code/verify', 200, submit);
            challenge = assertLoginChallenge(captured.value, 'mfa');
            await noSession(page, harness, captured.result);
          } else {
            const completed = response(page, loginRoot + '/code/verify', 204);
            await submit();
            await completed;
          }
        }
        if (challenge) {
          await page.getByLabel(localizedText('Authenticator code'), { exact: true }).waitFor();
          await exercisePreferenceSwitch(page, { privateSelector: 'input', settings: true });
          await layout(page, journey.credentials + '-' + journey.method + '-mfa', viewport, dark, artifactDirectory);
          await totp(page, harness, fixture);
        }
        await page.waitForURL(harness.origin + '/dashboard');
        await page.getByTestId('portal-ready').waitFor();
        const profile = await api(page, '/api/v1/users/me');
        assert.equal(profile.status, 200);
        const state = harness.fixture('login-session-state', { user_id: fixture.user_id, session_id: profile.body.session.id });
        assert.equal(state.auth_version, fixture.auth_version, 'Session did not capture authority after role provisioning');
        assert.equal(state.primary_method, journey.method === 'email' ? 'contact_code' : journey.method);
        assert.equal(state.uv, journey.method === 'passkey' ? 'verified' : 'not_applicable');
        assert.equal(state.totp, journey.mfa);
        assert.equal(state.totp_set, true);
        assert(Number.isFinite(Date.parse(state.authenticated_at)), 'Session has no earned authentication time');
        const refreshed = await api(page, '/api/v1/users/me');
        const again = harness.fixture('login-session-state', { user_id: fixture.user_id, session_id: refreshed.body.session.id });
        assert.equal(again.authenticated_at, state.authenticated_at, 'Session use advanced authentication time');
        const allowed = journey.role === 'support' && journey.method !== 'email';
        assert.equal((await api(page, '/api/v1/admin/capabilities')).status, allowed ? 200 : 403,
          'Contact-code plus TOTP must never earn administrative eligibility');
        await visit(page, harness.origin, '/admin');
        if (allowed) await page.getByTestId('admin-ready').waitFor();
        else {
          await page.getByRole('main').getByRole('alert').waitFor();
          assert.equal(await page.getByTestId('admin-ready').count(), 0);
          assert.equal((await api(page, '/api/v1/users/me')).status, 200, 'Admin denial erased normal login authority');
        }
        await assertPrivate(page, observed, harness);
        results.push({ locale: browserLocale(), viewport, credentials: journey.credentials, method: journey.method, mfa: journey.mfa,
          admin: allowed ? 'allowed' : 'denied', earnedEvidence: true, postGrantVersion: true, stableAuthenticationTime: true });
      } finally { await context.close(); }
    }
  }
  await loginBoundaries(browser, harness);
  return { journeys: results, emailWithSMSDisabled: true, disabledEmailUniformResponse: true,
    preferenceDeadline: true, failedCompletionNoCookie: true, roleChangeBetweenFactors: true,
    enrolledUVDoesNotReplaceActualUV: true,
    manualGates: ['Observed delivery through production email and SMS providers remains unperformed; local TLS sender is not production delivery evidence'] };
}

async function loginBoundaries(browser, harness) {
  const presenceOnly = harness.fixture('login-seed', { scenario: 'passkey-only' });
  const uvProbe = await newContext(browser, harness);
  try {
    const page = await uvProbe.context.newPage();
    const authenticator = await addAuthenticator(page, presenceOnly.credentials[0]);
    await authenticator.cdp.send('WebAuthn.setResponseOverrideBits', { authenticatorId: authenticator.authenticatorId, isBadUV: true });
    await visit(page, harness.origin, '/login/webauthn');
    const rejected = response(page, '/api/v1/auth/webauthn/login/verify', 401);
    await page.getByTestId('passkey-login').click();
    await noSession(page, harness, await rejected);
    await assertPrivate(page, uvProbe.observed, harness);
  } finally { await uvProbe.context.close(); }

  const fixture = harness.fixture('login-seed', { scenario: 'dual', totp: true, role: 'support' });
  const { context, observed } = await newContext(browser, harness);
  try {
    const page = await context.newPage();
    await visit(page, harness.origin, '/login');
    await credentials(page, fixture, 'password');
    const captured = await capture(page, harness, loginRoot, 200, () =>
      page.getByRole('button', { name: localizedText('Sign in with password'), exact: true }).click());
    const preauth = assertLoginChallenge(captured.value, 'mfa');
    await noSession(page, harness, captured.result);
    // Wrong completion must be definitive, private, and retain only the original
    // challenge. Choose a code distinct from the actual current TOTP.
    const current = harness.fixture('totp-code', { user_id: fixture.user_id });
    const wrong = current.code === '000000' ? '111111' : '000000';
    await page.getByLabel(localizedText('Authenticator code'), { exact: true }).fill(wrong);
    const rejected = response(page, loginRoot + '/mfa', 401);
    await page.getByRole('button', { name: localizedText('Verify code'), exact: true }).click();
    await noSession(page, harness, await rejected);
    await exercisePreferenceSwitch(page, { privateSelector: 'input', settings: true });
    harness.fixture('admin-grant', { user_id: fixture.user_id, role: 'dpo' });
    const factor = await freshTOTP(harness, fixture);
    const stale = await api(page, loginRoot + '/mfa', { method: 'POST', body: { preauthentication: preauth.preauthentication, code: factor.code } });
    assert.equal(stale.status, 401, 'Role change between factors did not reject captured authority');
    await noSession(page, harness);
    await assertPrivate(page, observed, harness);
  } finally { await context.close(); }

  const expiring = harness.fixture('login-seed', { scenario: 'password-only', totp: true });
  const pending = await newContext(browser, harness);
  try {
    const page = await pending.context.newPage();
    await visit(page, harness.origin, '/login');
    await page.clock.install();
    await credentials(page, expiring, 'password');
    const captured = await capture(page, harness, loginRoot, 200, () =>
      page.getByRole('button', { name: localizedText('Sign in with password'), exact: true }).click());
    const original = assertLoginChallenge(captured.value, 'mfa');
    await page.getByLabel(localizedText('Authenticator code'), { exact: true }).waitFor();
    await exercisePreferenceSwitch(page, { privateSelector: 'input', settings: true });
    await page.clock.fastForward(Math.max(1, Date.parse(original.expires_at) - Date.now() + 2000));
    await page.getByText(localizedText('This verification is no longer usable. Start a new sign-in when you are ready.'), { exact: true }).waitFor();
    assert.equal(await page.getByLabel(localizedText('Authenticator code'), { exact: true }).count(), 0);
    assertOnlyPreferenceCookies(await pending.context.cookies(harness.origin));
    await assertPrivate(page, pending.observed, harness);
  } finally { await pending.context.close(); }

  const disabled = harness.fixture('login-seed', { scenario: 'passkey-only' });
  for (const channel of ['sms', 'email']) {
    if (channel === 'email') await harness.setLoginEmail(false);
    const probe = await newContext(browser, harness);
    try {
      const page = await probe.context.newPage();
      await visit(page, harness.origin, '/login');
      const before = harness.mail.messages.length;
      const challenge = await requestEmail(page, harness, disabled, channel);
      assert.equal(harness.mail.messages.length, before, 'Disabled alternate channel sent a message');
      const result = await api(page, loginRoot + '/code/verify', { method: 'POST', body: { challenge: challenge.challenge, code: '000000' } });
      assert.equal(result.status, 401, 'Disabled-channel decoy authenticated an account');
      await noSession(page, harness);
      await assertPrivate(page, probe.observed, harness);
    } finally {
      await probe.context.close();
      if (channel === 'email') await harness.setLoginEmail(true);
    }
  }
}
