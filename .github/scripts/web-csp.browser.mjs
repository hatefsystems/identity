import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { smokeImage, webDocumentNonce } from './smoke-image.mjs';

async function waitForExternalCss(page) {
  await page.waitForFunction(() => {
    const externalStylesheet = [...document.querySelectorAll('link[rel="stylesheet"]')].some(
      (link) =>
        link.href.startsWith(`${location.origin}/_next/static/`) && link.sheet?.cssRules.length > 0
    );
    return (
      externalStylesheet &&
      getComputedStyle(document.documentElement).getPropertyValue('--background').trim() ===
        '0 0% 100%'
    );
  });
}

export async function validateWebCsp({
  baseURL,
  notFoundPaths = [`/__csp-browser-${randomUUID()}`, `/__csp-browser-${randomUUID()}.html`],
}) {
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ bypassCSP: false, serviceWorkers: 'block' });
    context.setDefaultTimeout(15_000);
    context.setDefaultNavigationTimeout(30_000);
    // Init/evaluate scripts only observe the page; executable attack probes come from parsed HTML.
    await context.addInitScript(() => {
      globalThis.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (event) => {
        globalThis.__cspViolations.push({
          directive: event.effectiveDirective,
          blockedURI: event.blockedURI,
          disposition: event.disposition,
          policy: event.originalPolicy,
        });
      });
    });

    const page = await context.newPage();
    const baselineErrors = [];
    const expected404s = new Set(notFoundPaths.map((path) => new URL(path, baseURL).href));
    page.on('pageerror', (error) => baselineErrors.push(error.message));
    page.on('console', (message) => {
      const text = message.text();
      if (message.type() !== 'error' && !/hydration|Content Security Policy/i.test(text)) return;
      if (
        text === 'Failed to load resource: the server responded with a status of 404 (Not Found)' &&
        expected404s.has(message.location().url)
      ) {
        return;
      }
      baselineErrors.push(`${message.type()}: ${text} (${message.location().url})`);
    });
    const seenNonces = new Set();
    const assertCleanBaseline = async () => {
      assert.deepEqual(
        await page.evaluate(() => globalThis.__cspViolations),
        [],
        'Normal-page CSP violations'
      );
      assert.deepEqual(baselineErrors, [], 'Normal-page runtime, hydration or console errors');
    };
    const visit = async (path, status, heading) => {
      const response = await page.goto(new URL(path, baseURL).href, { waitUntil: 'load' });
      assert(response, `${path} has no document response`);
      assert.equal(response.status(), status, `${path} browser HTTP status`);
      webDocumentNonce(new Headers(await response.allHeaders()), await response.text(), seenNonces);
      await page
        .getByRole('heading', { name: heading, level: 1, exact: true })
        .waitFor({ state: 'visible' });
      await waitForExternalCss(page);
      await assertCleanBaseline();
    };

    await visit('/', 200, 'Hatef Identity Platform');
    assert.equal(
      await page
        .getByRole('heading', { name: 'Hatef Identity Platform', exact: true })
        .evaluate((heading) => getComputedStyle(heading).fontSize),
      '36px',
      'Homepage Tailwind typography must be applied'
    );
    for (const path of notFoundPaths) {
      await visit(path, 404, 'Page not found');
      const home = page.getByRole('link', { name: 'Return home', exact: true });
      // Avoid clicking before React attaches Next Link's handler, which would cause a full load.
      await page.waitForFunction(() => {
        const link = document.querySelector('a[href="/"]');
        return (
          link &&
          Object.keys(link).some(
            (key) => key.startsWith('__reactProps$') && typeof link[key]?.onClick === 'function'
          )
        );
      });
      const marker = randomUUID();
      await page.evaluate((value) => {
        document.__cspNavigationMarker = value;
      }, marker);
      await Promise.all([page.waitForURL(new URL('/', baseURL).href), home.click()]);
      await page
        .getByRole('heading', { name: 'Hatef Identity Platform', exact: true })
        .waitFor({ state: 'visible' });
      assert.equal(
        await page.evaluate(() => document.__cspNavigationMarker),
        marker,
        'Return home must navigate on the client without replacing the document'
      );
      await waitForExternalCss(page);
      await assertCleanBaseline();
    }
    await assertCleanBaseline();
    await page.close();

    // A separate page keeps intentional CSP violations out of the clean application baseline.
    const attack = await context.newPage();
    const attackErrors = [];
    attack.on('pageerror', (error) => attackErrors.push(error.message));
    attack.on('console', (message) => {
      if (message.type() === 'error' && !/Content Security Policy/i.test(message.text())) {
        attackErrors.push(message.text());
      }
    });
    const attackURL = new URL('/', baseURL);
    attackURL.searchParams.set('__csp_fixture', randomUUID());
    let fixturePolicy;
    await attack.route(attackURL.href, async (route) => {
      const response = await route.fetch({ maxRedirects: 0 });
      assert.equal(
        response.status(),
        200,
        'Attack fixture must start from a real production document'
      );
      const html = await response.text();
      const headers = new Headers(response.headers());
      const nonce = webDocumentNonce(headers, html, seenNonces);
      fixturePolicy = headers.get('content-security-policy');
      const wrongNonce = randomBytes(32).toString('base64');
      assert.notEqual(wrongNonce, nonce);
      const headProbes = `
        <script nonce="${nonce}">globalThis.__cspProbe = { allowed: true, unnonced: false, wrongNonce: false, handler: false };</script>
        <script>globalThis.__cspProbe.unnonced = true;</script>
        <script nonce="${wrongNonce}">globalThis.__cspProbe.wrongNonce = true;</script>
        <style nonce="${nonce}">#csp-style-probe { --csp-allowed: applied; }</style>
        <style>#csp-style-probe { --csp-unnonced: applied; }</style>
        <style nonce="${wrongNonce}">#csp-style-probe { --csp-wrong-nonce: applied; }</style>
      `;
      const bodyProbes = `
        <section aria-label="CSP attack fixture">
          <button type="button" onclick="globalThis.__cspProbe.handler = true">CSP handler probe</button>
          <div id="csp-style-probe" style="--csp-attribute: applied">CSP style probe</div>
        </section>
      `;
      assert.match(html, /<\/head>/i);
      assert.match(html, /<\/body>/i);
      // Baseline hydration used unmodified HTML. Omit framework scripts only here so React
      // cannot replace the parser-inserted probes before we exercise them.
      const fixture = html
        .replace(/<script\b(?:[^"'<>]|"[^"]*"|'[^']*')*>[\s\S]*?<\/script\s*>/gi, '')
        .replace(/<\/head>/i, `${headProbes}</head>`)
        .replace(/<\/body>/i, `${bodyProbes}</body>`);
      await route.fulfill({ response, body: fixture });
    });
    const attackResponse = await attack.goto(attackURL.href, { waitUntil: 'load' });
    assert(attackResponse);
    assert.equal(attackResponse.status(), 200);
    assert.equal(
      await attackResponse.headerValue('content-security-policy'),
      fixturePolicy,
      'Preserve the real enforcing CSP'
    );
    await waitForExternalCss(attack);
    await attack.getByRole('button', { name: 'CSP handler probe', exact: true }).click();
    await attack.waitForFunction(() => {
      const count = (directive) =>
        globalThis.__cspViolations.filter((event) => event.directive === directive).length;
      return (
        count('script-src-elem') >= 2 &&
        count('script-src-attr') >= 1 &&
        count('style-src-elem') >= 2 &&
        count('style-src-attr') >= 1
      );
    });
    const result = await attack.evaluate(() => {
      const style = getComputedStyle(document.getElementById('csp-style-probe'));
      return {
        scripts: globalThis.__cspProbe,
        styles: Object.fromEntries(
          ['allowed', 'unnonced', 'wrong-nonce', 'attribute'].map((key) => [
            key,
            style.getPropertyValue(`--csp-${key}`).trim(),
          ])
        ),
        violations: globalThis.__cspViolations,
      };
    });
    assert.deepEqual(
      result.scripts,
      { allowed: true, unnonced: false, wrongNonce: false, handler: false },
      'Only the matching-nonce parser-inserted script may execute'
    );
    assert.deepEqual(
      result.styles,
      { allowed: 'applied', unnonced: '', 'wrong-nonce': '', attribute: '' },
      'Only external and matching-nonce styles may apply'
    );
    assert.deepEqual(result.violations.map((event) => event.directive).sort(), [
      'script-src-attr',
      'script-src-elem',
      'script-src-elem',
      'style-src-attr',
      'style-src-elem',
      'style-src-elem',
    ]);
    for (const violation of result.violations) {
      assert.equal(violation.blockedURI, 'inline');
      assert.equal(violation.disposition, 'enforce');
      assert.equal(violation.policy, fixturePolicy);
    }
    assert.deepEqual(attackErrors, [], 'Unexpected attack-fixture errors');
    console.log('Production browser CSP, CSS and client navigation checks passed');
  } finally {
    await browser.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  smokeImage('web', process.argv[2], validateWebCsp).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
