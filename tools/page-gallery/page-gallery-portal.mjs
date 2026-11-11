import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { startPortalHarness } from '../../.github/scripts/portal-harness.mjs';
import { newContext, visit } from '../../.github/scripts/web-portal.browser.mjs';
import { localizedText } from '../../.github/scripts/browser-localization.mjs';
import { accountViews } from './page-gallery-account.mjs';
import { adminViews } from './page-gallery-admin.mjs';

export async function portalPhase(api) {
  let harness, browser;
  try {
    harness = await startPortalHarness({ admin: true });
    api.privateValues = () => [...harness.secrets];
    api.cleanups.push(() => harness.close());
    browser = await chromium.launch({ headless: true, args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`] });
    api.cleanups.push(() => browser.close());
    const { context } = await newContext(browser, harness);
    api.contexts.add(context);
    try {
      const page = await context.newPage();
      const ids = ['home', 'login', 'passkey', 'forgot-password', 'reset-password', 'verify-totp', 'recover-account'];
      for (const prefix of ids) {
        const view = api.views.find(v => v.id === `${prefix}-baseline`);
        await api.group([view.id], async () => {
          await visit(page, harness.origin, view.route);
          if (prefix === 'passkey') await page.getByTestId('passkey-login').waitFor();
          if (prefix === 'recover-account') await page.getByRole('alert').filter({ hasText: localizedText('This page no longer holds a usable recovery link. Reopen the link in your recovery email to continue.') }).waitFor();
          if (['login', 'forgot-password', 'reset-password', 'verify-totp'].includes(prefix))
            assert.equal(await page.locator('input, textarea').count(), 0, 'Availability/login page has a disconnected form');
          await page.getByRole('link', { name: localizedText('Hatef Identity home'), exact: true }).waitFor();
          await api.capture(page, view.id, { role: 'anonymous' });
        });
      }
      await api.group(['home-display-settings'], async () => {
        await visit(page, harness.origin, '/');
        await page.locator('[data-ui-preferences] summary').click();
        await page.getByRole('combobox', { name: localizedText('Calendar'), exact: true }).waitFor();
        await api.capture(page, 'home-display-settings', { role: 'anonymous' });
      });
      await api.group(['passkey-app-cancelled'], async () => {
        await visit(page, harness.origin, '/login/webauthn');
        const cdp = await context.newCDPSession(page);
        try {
          await cdp.send('WebAuthn.enable');
          await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
            protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
            hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
            automaticPresenceSimulation: false,
          } });
          await page.getByTestId('passkey-login').click();
          await page.getByRole('button', { name: localizedText('Cancel sign in'), exact: true }).click();
          await page.getByRole('status').filter({ hasText: localizedText('Sign-in cancelled here before passkey verification was sent. Start again when you are ready.') }).waitFor();
          assert.equal(await page.getByTestId('passkey-login').locator('..').getByRole('alert').count(), 0);
          await api.capture(page, 'passkey-app-cancelled', { role: 'anonymous' });
        } finally { await cdp.detach(); }
      });
      await api.group(['not-found'], async () => {
        const response = await page.goto(harness.origin + '/gallery-unknown-page', { waitUntil: 'load' });
        assert.equal(response.status(), 404);
        await page.getByRole('link', { name: localizedText('Hatef Identity home'), exact: true }).waitFor();
        await api.capture(page, 'not-found', { heading: 'Page not found', role: 'anonymous' });
      });
    } finally { await context.close(); api.contexts.delete(context); }
    await accountViews(api, harness, browser);
    await adminViews(api, harness, browser);
    harness.assertHealthy();
    try { harness.assertPrivateLogs(); }
    catch { api.finding('service-log-privacy-guard', 'portal'); }
  } finally {
    try { if (browser) await browser.close(); }
    finally { if (harness) await harness.close(); }
  }
}
