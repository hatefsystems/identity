import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { parse } from '@formatjs/icu-messageformat-parser';
import { createTranslator } from 'use-intl/core';

export const browserLocales = ['en', 'fa-IR'];
export const uiPreferenceCookie = '__Host-hatef-ui';
const catalogRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../apps/web/messages');
const cache = new Map();
let activeLocale = 'en';
let leaves;
let faTranslator;

// Evaluate only checked-in static catalogs, with type-only imports erased. Node's
// browser runner deliberately does not import Next server/client application code.
function catalog(file) {
  const path = resolve(catalogRoot, file.endsWith('.ts') ? file : file + '.ts');
  assert(path.startsWith(catalogRoot + sep), 'Catalog import escaped its static directory');
  if (cache.has(path)) return cache.get(path);
  const module = { exports: {} };
  const input = readFileSync(path, 'utf8');
  // Compile and load dependencies outside the VM deadline. Nested transpilation
  // under a parent's timer made literal catalog evaluation CPU-load dependent.
  const imports = new Map();
  const syntax = ts.createSourceFile(path, input, ts.ScriptTarget.ES2022, false);
  for (const statement of syntax.statements) {
    if (!ts.isImportDeclaration(statement) || statement.importClause?.isTypeOnly) continue;
    assert(ts.isStringLiteral(statement.moduleSpecifier), 'Catalog import must be static');
    const specifier = statement.moduleSpecifier.text;
    assert(specifier.startsWith('./'), 'Browser catalogs may only import sibling catalogs');
    imports.set(specifier, catalog(specifier));
  }
  const source = ts.transpileModule(input, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(source, {
    module, exports: module.exports,
    require(specifier) {
      assert(imports.has(specifier), 'Browser catalog dependency must be preloaded');
      return imports.get(specifier);
    },
  }, { filename: path, timeout: 1000 });
  cache.set(path, module.exports);
  return module.exports;
}

function catalogs() {
  if (!leaves) {
    const en = catalog('en').default;
    const fa = catalog('fa-IR').default;
    faTranslator = createTranslator({ locale: 'fa-IR', messages: fa });
    leaves = [];
    function walk(base, translation, prefix = '') {
      for (const [key, value] of Object.entries(base)) {
        const path = prefix ? prefix + '.' + key : key;
        if (typeof value === 'string') {
          assert(typeof translation[key] === 'string', 'Incomplete browser translation catalog');
          leaves.push({ key: path, en: value, fa: translation[key] });
        } else walk(value, translation[key], path);
      }
    }
    walk(en, fa);
  }
  return leaves;
}

const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
function pattern(message, capture = false) {
  const names = new Set();
  const slots = new Set();
  function walk(elements) {
    return elements.map((element) => {
      if (element.type === 0) return escape(element.value);
      if (element.type === 5 || element.type === 6)
        return '(?:' + Object.values(element.options).map((option) => walk(option.value)).join('|') + ')';
      if (element.type === 7) return '[0-9۰-۹٠-٩.,]+';
      if (element.type === 8) {
        slots.add(element.value);
        return element.children.length ? walk(element.children) : '[\\s\\S]*?';
      }
      if (capture && !names.has(element.value)) {
        names.add(element.value);
        return `(?<${element.value}>[\\s\\S]+?)`;
      }
      return '[\\s\\S]+?';
    }).join('');
  }
  return { source: walk(parse(message)), slots };
}

export function browserLocale() { return activeLocale; }


export function expectedPageTitle(pathname, locale) {
  assert(browserLocales.includes(locale), 'Unsupported metadata validation locale');
  const messages = catalog(locale === 'fa-IR' ? 'fa-IR' : 'en').default;
  if (pathname === '/') return messages.metadata.title;
  const auth = {
    '/login': 'login', '/register': 'register', '/forgot-password': 'forgot',
    '/reset-password': 'reset', '/verify-totp': 'totp',
    '/login/webauthn': 'passkey', '/recover-account': 'reclaim',
  }[pathname];
  if (auth) return messages.auth.pages[auth].metadata;
  const dashboard = {
    '/dashboard': 'overview', '/dashboard/profile': 'profile',
    '/dashboard/security': 'security', '/dashboard/sessions': 'sessions',
    '/dashboard/privacy': 'privacy',
  }[pathname];
  if (dashboard) return `${messages.portal.metadata[dashboard]} | ${messages.auth.brand}`;
  const admin = {
    '/admin/users': messages.admin.metadata.accounts,
    '/admin/audit-logs': messages.audit.metadata,
    '/admin/integrity': messages.integrity.metadata,
    '/admin/legal': messages.legal.title,
  }[pathname];
  if (admin) return messages.admin.metadata.template.replace('%s', admin);
  if (pathname === '/admin' || /^\/admin\/users\/[0-9a-f-]{36}$/.test(pathname)) return messages.admin.metadata.title;
  assert.fail('Preference metadata check requires an owned route');
}
export function setBrowserLocale(locale) {
  assert(browserLocales.includes(locale), 'Unsupported browser validation locale');
  activeLocale = locale;
}

// Existing tests keep their explicit English accessible expectations. Persian
// executes the corresponding exact catalog names, including interpolated IDs.
// Raw fixture values and protocol labels remain byte-for-byte unchanged.
export function localizedText(value, { exact = true } = {}) {
  if (activeLocale === 'en') return value;
  const matches = [];
  for (const leaf of catalogs()) {
    const en = pattern(leaf.en, true);
    if (value instanceof RegExp) {
      value.lastIndex = 0;
      const sample = leaf.en.replace(/\{[^{}]+\}/g, 'example').replace(/<\/?[a-zA-Z]+>/g, '');
      if (value.test(sample)) matches.push(pattern(leaf.fa).source);
    } else if (typeof value === 'string') {
      const found = new RegExp('^' + en.source + '$', 'u').exec(value);
      if (found) {
        const values = { ...found.groups };
        for (const slot of en.slots) values[slot] = (chunks) => chunks;
        matches.push(escape(faTranslator.rich(leaf.key, values)));
      }
    }
  }
  const unique = [...new Set(matches)];
  if (unique.length === 0) return value;
  return new RegExp((exact ? '^' : '') + '(?:' + unique.join('|') + ')' + (exact ? '$' : ''), 'u');
}

export async function configureBrowserPreferences(context, origin, locale = activeLocale) {
  if (locale === 'en') return;
  assert(browserLocales.includes(locale));
  await context.addCookies([{
    name: uiPreferenceCookie, value: `1~${locale}~auto~UTC`, url: origin,
    secure: true, httpOnly: true, sameSite: 'Lax', expires: Math.floor(Date.now() / 1000) + 31536000,
  }]);
}

export function decodePreferenceCookieValue(value) {
  assert(typeof value === 'string' && value.length <= 384, 'Unbounded preference cookie');
  let decoded;
  try { decoded = decodeURIComponent(value); } catch { assert.fail('Malformed preference-cookie encoding'); }
  // Next's cookie serializer percent-encodes IANA slashes. Fixture setup may use
  // literal separators. Permit these exact representations, decoding once only.
  assert(decoded.length <= 128 && (value === decoded || value === encodeURIComponent(decoded)),
    'Noncanonical preference-cookie encoding');
  assert.match(decoded, /^1~(?:en|fa-IR)~(?:auto|gregory|persian)~[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+){0,2}$/);
  const zone = decoded.split('~')[3];
  assert.equal(Intl.DateTimeFormat('en', { timeZone: zone }).resolvedOptions().timeZone, zone,
    'Noncanonical preference-cookie zone');
  return decoded;
}

export function assertOnlyPreferenceCookies(cookies) {
  assert(cookies.length <= 1, 'Anonymous document has unexpected browser cookies');
  for (const cookie of cookies) {
    assert.equal(cookie.name, uiPreferenceCookie);
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'Lax');
    assert.equal(cookie.path, '/');
    assert.equal(cookie.domain, 'localhost');
    decodePreferenceCookieValue(cookie.value);
  }
}

export async function waitForFonts(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

export function screenshotName(state, viewport, dark) {
  assert(/^[a-z][a-z0-9-]*$/.test(state), 'Unsafe screenshot state');
  return `${state}-${activeLocale}-${viewport.width}x${viewport.height}-${dark ? 'dark' : 'light'}.png`;
}

// Real Server Actions, without navigation/refresh, run under the current strict
// nonce CSP. Private snapshots stay in the same document only and are discarded.
export async function exercisePreferenceSwitch(page, { privateSelector = '', settings = false, onOtherLocale = async () => {} } = {}) {
  const initialLocale = await page.locator('html').getAttribute('lang');
  const otherLocale = initialLocale === 'en' ? 'fa-IR' : 'en';
  const origin = new URL(page.url()).origin;
  const initialURL = page.url();
  const initialTitle = expectedPageTitle(new URL(initialURL).pathname, initialLocale);
  // App Router metadata may settle after the visible route heading. Establish
  // the exact route baseline before saving, then check each action's result.
  await page.waitForFunction((title) => document.title === title, initialTitle);
  const marker = await page.evaluate((selector) => {
    const marker = crypto.randomUUID();
    document.__localizationMarker = marker;
    document.__localizationPrivate = selector
      ? [...document.querySelectorAll(selector)].map((node) => 'value' in node ? node.value : node.textContent)
      : [];
    return marker;
  }, privateSelector);
  const calls = [];
  const observe = (request) => {
    if (new URL(request.url()).pathname.startsWith('/api/')) calls.push(request.method());
  };
  page.on('request', observe);
  async function chooseLanguage(locale) {
    const current = await page.locator('html').getAttribute('lang');
    const control = page.getByRole('combobox', { name: current === 'en' ? 'Language' : 'زبان', exact: true });
    await control.waitFor({ state: 'visible' });
    const actions = [];
    const observeAction = (request) => {
      if (request.method() === 'POST' && request.headers()['next-action']) actions.push(request);
    };
    page.on('request', observeAction);
    try {
      await control.selectOption(locale);
      await page.waitForFunction((locale) => document.documentElement.lang === locale, locale);
      await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
      await page.waitForFunction((title) => document.title === title, expectedPageTitle(new URL(initialURL).pathname, locale));
      await waitForFonts(page);
      if (page.url() !== initialURL) {
        const before = new URL(initialURL), after = new URL(page.url());
        console.error(JSON.stringify({ check: 'preference-url-invariance',
          sameOrigin: before.origin === after.origin, samePath: before.pathname === after.pathname,
          sameQuery: before.search === after.search, hadFragment: Boolean(before.hash), hasFragment: Boolean(after.hash) }));
      }
      assert.equal(page.url(), initialURL, 'Language changed pathname, search or fragment');
      assert.equal(await page.locator('html').getAttribute('dir'), locale === 'fa-IR' ? 'rtl' : 'ltr');
      assert.equal(actions.length, 1, 'Preference change must use one state-preserving Server Action');
      assert.equal(actions[0].url(), initialURL.split('#')[0], 'Preference action left its current route');
      assert.equal(await page.evaluate(() => document.__localizationMarker), marker, 'Preference save replaced the document');
      assert(await page.evaluate((selector) => {
        const values = selector ? [...document.querySelectorAll(selector)]
          .map((node) => 'value' in node ? node.value : node.textContent) : [];
        return JSON.stringify(values) === JSON.stringify(document.__localizationPrivate);
      }, privateSelector), 'Preference change reset a draft or one-time private value');
      const cookie = (await page.context().cookies(origin)).filter((cookie) => cookie.name === uiPreferenceCookie);
      assertOnlyPreferenceCookies(cookie);
      assert.equal(cookie.length, 1);
      assert(cookie[0].value.startsWith(`1~${locale}~`));
      assert(!(await page.evaluate(() => document.cookie)).includes(uiPreferenceCookie));
    } finally { page.off('request', observeAction); }
  }
  try {
    await chooseLanguage(otherLocale);
    assert.notEqual(await page.title(), initialTitle, 'Server-owned metadata did not change with language');
    await onOtherLocale(otherLocale);
    if (settings) {
      const summary = page.locator('[data-ui-preferences] summary');
      if (!(await summary.evaluate((node) => node.parentElement.open))) await summary.click();
      await page.getByRole('combobox', { name: otherLocale === 'en' ? 'Calendar' : 'تقویم', exact: true }).selectOption('gregory');
      await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
      await page.getByRole('combobox', { name: otherLocale === 'en' ? 'Time zone' : 'منطقهٔ زمانی', exact: true }).selectOption('Asia/Tehran');
      await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
      await chooseLanguage(initialLocale);
      assert.equal(await page.getByRole('combobox', { name: initialLocale === 'en' ? 'Calendar' : 'تقویم', exact: true }).inputValue(), 'gregory');
      assert.equal(await page.getByRole('combobox', { name: initialLocale === 'en' ? 'Time zone' : 'منطقهٔ زمانی', exact: true }).inputValue(), 'Asia/Tehran');
      await page.getByRole('combobox', { name: initialLocale === 'en' ? 'Calendar' : 'تقویم', exact: true }).selectOption('auto');
      await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
      await page.getByRole('combobox', { name: initialLocale === 'en' ? 'Time zone' : 'منطقهٔ زمانی', exact: true }).selectOption('UTC');
      await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
      await summary.click();
    } else await chooseLanguage(initialLocale);
    assert.equal(await page.title(), initialTitle);
    assert.deepEqual(calls, [], 'Display preferences reauthenticated, rebootstrapped or replayed API work');
  } finally {
    page.off('request', observe);
    await page.evaluate(() => { delete document.__localizationMarker; delete document.__localizationPrivate; });
  }
}

// Image smoke remains an independent image gate. Its browser phase reaches that
// exact container through ephemeral local HTTPS so Secure host cookies and Next
// same-origin actions are tested with their production attributes intact.
export async function localHTTPSProxy(baseURL) {
  const upstream = new URL(baseURL);
  assert(upstream.protocol === 'http:' && upstream.hostname === '127.0.0.1' && upstream.port && upstream.pathname === '/' && !upstream.search && !upstream.hash,
    'Image browser TLS proxy requires one canonical loopback upstream');
  const parent = resolve(tmpdir(), 'kilo');
  await mkdir(parent, { recursive: true });
  const directory = await mkdtemp(resolve(parent, 'image-browser-tls-'));
  let key, cert;
  try {
    const keyPath = resolve(directory, 'key.pem');
    const certPath = resolve(directory, 'cert.pem');
    const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
    { encoding: 'utf8', timeout: 15000, maxBuffer: 16384 });
    assert(!result.error && result.status === 0, 'Ephemeral image-browser certificate generation failed');
    [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  } finally { await rm(directory, { recursive: true, force: true }); }
  const tlsSPKI = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  let origin;
  const ingress = httpsServer({ key, cert, minVersion: 'TLSv1.2' }, (request, response) => {
    const forwarded = httpRequest({ hostname: upstream.hostname, port: upstream.port,
      method: request.method, path: request.url,
      headers: { ...request.headers, host: new URL(origin).host,
        'x-forwarded-host': new URL(origin).host, 'x-forwarded-proto': 'https',
        'x-forwarded-for': request.socket.remoteAddress }, timeout: 15000 }, (result) => {
      response.writeHead(result.statusCode, result.headers);
      result.pipe(response);
    });
    forwarded.on('timeout', () => forwarded.destroy());
    forwarded.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { 'Cache-Control': 'private, no-store' });
      response.end();
    });
    request.on('aborted', () => forwarded.destroy());
    request.pipe(forwarded);
  });
  ingress.on('tlsClientError', () => {});
  ingress.listen(0, '127.0.0.1');
  await once(ingress, 'listening');
  origin = `https://localhost:${ingress.address().port}`;
  return { origin, tlsSPKI, certificate: cert,
    async close() {
      await new Promise((resolve) => { ingress.close(resolve); ingress.closeAllConnections(); });
      key.fill(0);
    },
  };
}

// Admit only the one public preference action envelope used by the production
// controls. Browser fault injection and request audits share this narrow scope.
export function preferenceActionInput(request, documentURL) {
  if (request.method !== 'POST' || !request.headers['next-action']) return undefined;
  assert.equal(request.url, documentURL.split('#')[0], 'Preference action changed its exact page URL');
  const url = new URL(request.url);
  assert(!url.search && !url.hash, 'Preference action included query or fragment data');
  assert.equal(request.type, 'fetch');
  assert(typeof request.body === 'string' && Buffer.byteLength(request.body) <= 512, 'Unbounded preference action');
  const args = JSON.parse(request.body);
  assert(Array.isArray(args) && args.length === 1, 'Unexpected preference action arguments');
  const preference = args[0];
  assert(preference && typeof preference === 'object' && !Array.isArray(preference));
  assert.deepEqual(Object.keys(preference).sort(), ['calendar', 'locale', 'timeZone']);
  assert(browserLocales.includes(preference.locale));
  assert(['auto', 'gregory', 'persian'].includes(preference.calendar));
  assert(typeof preference.timeZone === 'string' && preference.timeZone.length <= 64);
  assert(Intl.DateTimeFormat('en', { timeZone: preference.timeZone }).resolvedOptions().timeZone === preference.timeZone);
  return preference;
}

export async function exercisePreferenceFailure(page, expectResourceFailure = () => {}) {
  const initialURL = page.url();
  const initialLocale = await page.locator('html').getAttribute('lang');
  const otherLocale = initialLocale === 'en' ? 'fa-IR' : 'en';
  const initialTitle = await page.title();
  const initialCookies = (await page.context().cookies(new URL(initialURL).origin))
    .filter((cookie) => cookie.name === uiPreferenceCookie);
  const marker = await page.evaluate(() => {
    document.__failedPreferenceMarker = crypto.randomUUID();
    return document.__failedPreferenceMarker;
  });
  let release, arrived;
  const waiting = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { arrived = resolve; });
  let attempts = 0;
  let interceptionFailed = false;
  const pending = [];
  const matcher = (url) => url.href === initialURL.split('#')[0];
  const handler = (route) => {
    const request = route.request();
    if (request.method() !== 'POST' || !request.headers()['next-action']) return route.fallback();
    const operation = (async () => {
      try {
        const input = preferenceActionInput({ url: request.url(), method: request.method(),
          type: request.resourceType(), headers: request.headers(), body: request.postData() }, initialURL);
        assert.equal(input.locale, otherLocale);
        attempts++;
        arrived();
        await waiting;
        expectResourceFailure(request.url(), 503);
        await route.fulfill({ status: 503, contentType: 'text/plain; charset=utf-8', body: 'Preference save unavailable.' });
      } catch {
        interceptionFailed = true;
        arrived();
        await route.abort().catch(() => {});
      }
    })();
    pending.push(operation);
    return operation;
  };
  await page.route(matcher, handler);
  const control = page.getByRole('combobox', { name: initialLocale === 'en' ? 'Language' : 'زبان', exact: true });
  try {
    await control.selectOption(otherLocale);
    await Promise.race([started, page.waitForTimeout(5000).then(() => { throw new Error('Preference action fault did not reach its exact request'); })]);
    assert(!interceptionFailed, 'Preference failure injection escaped its exact action envelope');
    assert(await page.locator('[data-ui-preferences] select, [data-ui-preferences] button')
      .evaluateAll((controls) => controls.length >= 4 && controls.every((control) => control.disabled)),
    'Overlapping preference saves were not disabled');
    // Deliberately dispatch repeated changes against the real hydrated handler
    // while the network operation is held. The native disabled state above is
    // checked separately; the synchronous ownership lock must also hold.
    await control.evaluate((select, locale) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      for (const value of [locale, locale === 'en' ? 'fa-IR' : 'en', locale]) {
        setter.call(select, value);
        select.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }, otherLocale);
    await page.waitForTimeout(100);
    assert.equal(attempts, 1, 'Rapid preference changes transmitted overlapping saves');
    release();
    const failed = initialLocale === 'en'
      ? 'Preferences could not be saved. Your previous settings are unchanged.'
      : 'ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.';
    await page.locator('[data-ui-preferences] [role="status"]').filter({ hasText: failed }).waitFor({ state: 'visible' });
    await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
    assert.equal(await control.inputValue(), initialLocale, 'Failed preference save changed the selected language');
    assert.equal(await page.locator('html').getAttribute('lang'), initialLocale);
    assert.equal(await page.locator('html').getAttribute('dir'), initialLocale === 'en' ? 'ltr' : 'rtl');
    assert.equal(await page.title(), initialTitle);
    assert.equal(page.url(), initialURL);
    assert.equal(await page.evaluate(() => document.__failedPreferenceMarker), marker);
    assert.deepEqual((await page.context().cookies(new URL(initialURL).origin))
      .filter((cookie) => cookie.name === uiPreferenceCookie), initialCookies,
    'Failed preference action changed browser persistence');
    assert.equal(attempts, 1, 'Failed preference save automatically replayed');
    assert(!interceptionFailed);
  } finally {
    release();
    await Promise.all(pending);
    await page.unroute(matcher, handler);
    await page.evaluate(() => { delete document.__failedPreferenceMarker; });
  }
}
