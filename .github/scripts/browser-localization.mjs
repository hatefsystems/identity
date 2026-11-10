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
export const browserThemes = ['system', 'light', 'dark'];
export const browserViewports = [
  { width: 320, height: 568 }, { width: 390, height: 844 }, { width: 768, height: 1024 },
  { width: 1280, height: 800 }, { width: 320, height: 256 },
];
export const focusedBrowserViewports = [320, 375, 390, 430, 768, 1024, 1280, 1440, 1920]
  .map((width) => ({ width, height: 800 }));
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
  if (pathname === '/register/verify-email') return messages.registration.verifyMetadata;
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

export async function configureBrowserPreferences(context, origin, locale = activeLocale, theme = 'system') {
  assert(browserLocales.includes(locale));
  assert(browserThemes.includes(theme), 'Unsupported browser theme');
  if (locale === 'en' && theme === 'system') return;
  await context.addCookies([{
    name: uiPreferenceCookie, value: `2~${locale}~auto~UTC~${theme}`, url: origin,
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
  assert.match(decoded, /^(?:1~(?:en|fa-IR)~(?:auto|gregory|persian)~[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+){0,2}|2~(?:en|fa-IR)~(?:auto|gregory|persian)~[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+){0,2}~(?:system|light|dark))$/);
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

export async function waitForFonts(page, { animationFrames = true, timeout = 15000 } = {}) {
  assert(typeof animationFrames === 'boolean' && Number.isInteger(timeout) && timeout > 0 && timeout <= 30000);
  let timer;
  try {
    await Promise.race([
      animationFrames
        ? page.evaluate(async () => {
          await document.fonts.ready;
          await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        })
        : page.waitForFunction(() => document.fonts.status === 'loaded', undefined, { polling: 100, timeout }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Browser font and render readiness timed out')), timeout); }),
    ]);
  } finally { clearTimeout(timer); }
}

export function browserThemeMatchesDocument(theme) {
  const root = document.documentElement;
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  const scheme = dark ? 'dark' : 'light';
  const computedScheme = getComputedStyle(root).colorScheme;
  // Forced-color adjustment may override color-scheme to the UA's light/dark pair.
  const schemeMatches = computedScheme === scheme ||
    (matchMedia('(forced-colors: active)').matches && computedScheme === 'light dark');
  return root.getAttribute('data-theme') === theme && root.classList.contains('dark') === dark && schemeMatches &&
    [...document.querySelectorAll('input, select, textarea, button')]
      .filter((node) => node.checkVisibility({ checkVisibilityCSS: true }))
      .every((node) => getComputedStyle(node).colorScheme === computedScheme) &&
    document.getAnimations().filter((animation) => animation.effect?.getTiming().iterations !== Infinity)
      .every((animation) => animation.playState === 'finished' || animation.playState === 'idle');
}

export async function assertBrowserTheme(page, theme) {
  assert(browserThemes.includes(theme), 'Unsupported browser theme');
  await page.waitForFunction(browserThemeMatchesDocument, theme);
}

// Shared by the real registration/account/admin suites. Never fake a theme by
// changing classes: one explicit save owns persistence and the stable controller.
export async function setBrowserTheme(page, theme) {
  assert(browserThemes.includes(theme), 'Unsupported browser theme');
  const locale = await page.locator('html').getAttribute('lang');
  assert(browserLocales.includes(locale));
  const details = page.locator('[data-ui-preferences] details');
  const summary = page.locator('[data-ui-preferences] summary');
  const wasOpen = await details.evaluate((node) => node.open);
  const initialURL = page.url();
  const actions = [], apiCalls = [];
  const observe = (request) => {
    if (new URL(request.url()).pathname.startsWith('/api/')) apiCalls.push(request.method());
    if (request.method() === 'POST' && request.headers()['next-action']) actions.push(request);
  };
  page.on('request', observe);
  try {
    if (!wasOpen) await summary.click();
    const control = page.getByRole('combobox', { name: locale === 'en' ? 'Appearance' : 'ظاهر', exact: true });
    await control.waitFor({ state: 'visible' });
    await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
    const changed = await control.inputValue() !== theme;
    await page.evaluate(() => {
      document.__themeSnapshot = [...document.querySelectorAll('input, textarea, [data-testid="recovery-code"]')]
        .map((node) => ({ node, value: 'value' in node ? node.value : node.textContent }));
      document.__themeDocument = crypto.randomUUID();
    });
    const marker = await page.evaluate(() => document.__themeDocument);
    if (changed) await control.selectOption(theme);
    await page.waitForFunction(({ theme }) => {
      const control = document.querySelector('[data-ui-preferences] select[id$="-theme"]');
      return control?.value === theme && !control.disabled;
    }, { theme });
    await assertBrowserTheme(page, theme);
    await waitForFonts(page);
    assert.equal(page.url(), initialURL, 'Appearance save navigated or changed a private URL');
    assert.equal(await page.evaluate(() => document.__themeDocument), marker, 'Appearance save replaced the document');
    assert(await page.evaluate(() => document.__themeSnapshot.every(({ node, value }) =>
      node.isConnected && ('value' in node ? node.value : node.textContent) === value)),
    'Appearance save remounted or cleared a draft/one-time viewer');
    assert.equal(actions.length, changed ? 1 : 0, 'Appearance save replayed or omitted its explicit action');
    if (changed) {
      const request = actions[0];
      const input = preferenceActionInput({ url: request.url(), method: request.method(),
        type: request.resourceType(), headers: request.headers(), body: request.postData() }, initialURL);
      assert.equal(input.theme, theme);
      const cookies = (await page.context().cookies(new URL(initialURL).origin)).filter((cookie) => cookie.name === uiPreferenceCookie);
      assertOnlyPreferenceCookies(cookies);
      assert.equal(cookies.length, 1);
      assert.equal(decodePreferenceCookieValue(cookies[0].value),
        `2~${input.locale}~${input.calendar}~${input.timeZone}~${theme}`);
    }
    assert.deepEqual(apiCalls, [], 'Appearance save reauthenticated, rebootstrapped or replayed API work');
  } finally {
    page.off('request', observe);
    if (await details.evaluate((node) => node.open) !== wasOpen) await summary.click();
    await page.evaluate(() => { delete document.__themeSnapshot; delete document.__themeDocument; });
  }
}

export async function withTextResize(page, check) {
  const before = await page.evaluate(() => getComputedStyle(document.documentElement).fontSize);
  try {
    await page.evaluate(() => {
      const nonce = document.querySelector('script[nonce]')?.nonce;
      if (!nonce || document.getElementById('browser-text-resize')) throw new Error('Missing request nonce or duplicate text-resize probe');
      const style = document.createElement('style');
      style.id = 'browser-text-resize';
      style.nonce = nonce;
      style.textContent = ':root{font-size:200% !important}';
      document.head.append(style);
    });
    await waitForFonts(page);
    assert.equal(Number.parseFloat(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize)),
      Number.parseFloat(before) * 2, 'Text resize did not double the root font');
    await check();
  } finally {
    await page.evaluate(() => document.getElementById('browser-text-resize')?.remove());
    await waitForFonts(page);
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize), before);
  }
}

export async function exerciseThemeChoices(page, check = async () => {}) {
  const originalTheme = await page.locator('html').getAttribute('data-theme');
  const originalOS = await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const calls = [], saves = [], combinations = [];
  const observe = (request) => {
    if (new URL(request.url()).pathname.startsWith('/api/')) calls.push(request.method());
    if (request.method() === 'POST' && request.headers()['next-action']) saves.push(true);
  };
  page.on('request', observe);
  try {
    for (const theme of browserThemes) {
      await setBrowserTheme(page, theme);
      for (const os of ['light', 'dark']) {
        const before = saves.length;
        await page.emulateMedia({ colorScheme: os });
        await assertBrowserTheme(page, theme);
        await waitForFonts(page);
        await check({ theme, os });
        assert.equal(saves.length, before, 'OS appearance changes must not persist a preference');
        combinations.push({ theme, os });
      }
    }
    assert.deepEqual(calls, [], 'Theme choices or OS changes replayed API work');
    return combinations;
  } finally {
    try {
      await setBrowserTheme(page, originalTheme);
      const before = saves.length;
      await page.emulateMedia({ colorScheme: originalOS });
      await assertBrowserTheme(page, originalTheme);
      assert.equal(saves.length, before, 'Restoring the OS appearance saved a preference');
      assert.deepEqual(calls, [], 'Restoring appearance replayed API work');
    } finally { page.off('request', observe); }
  }
}

export async function exercisePortalNavigation(page, audit, capture = async () => {}) {
  const toggle = page.locator('[data-portal-navigation-toggle]');
  if (!(await toggle.count())) return; // Public reclaim has no account/admin navigation.
  const admin = new URL(page.url()).pathname.startsWith('/admin');
  const locale = await page.locator('html').getAttribute('lang');
  const messages = catalog(locale === 'en' ? 'en' : 'fa-IR').default.portal.shell;
  const nav = page.getByRole('navigation', { name: messages[admin ? 'adminNavigation' : 'accountNavigation'], exact: true });
  const links = nav.locator('[data-portal-navigation-links]');
  const calls = [];
  const observe = (request) => { if (new URL(request.url()).pathname.startsWith('/api/')) calls.push(request.method()); };
  await page.evaluate(() => { document.__navigationReady = document.querySelector('[data-testid="portal-ready"], [data-testid="admin-ready"]'); });
  page.on('request', observe);
  try {
    const active = links.locator('[aria-current="page"]');
    const section = await active.count() ? (await active.textContent()).trim() : messages[admin ? 'adminTitle' : 'accountTitle'];
    assert.equal((await toggle.textContent()).trim(), messages.currentSection.replace('{section}', section),
      'Compact navigation does not name the current section');
    assert.equal(await toggle.getAttribute('aria-controls'), await links.getAttribute('id'));
    for (const viewport of focusedBrowserViewports) {
      await page.setViewportSize(viewport);
      await waitForFonts(page);
      if (viewport.width < 1024) {
        assert(await toggle.isVisible(), 'Compact navigation disclosure is missing');
        if (await toggle.getAttribute('aria-expanded') === 'true') await toggle.click();
        assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
        assert(!(await links.isVisible()), 'Collapsed navigation retains visible destinations');
        await capture('navigation-closed', viewport);
        await toggle.focus();
        await page.keyboard.press('Space');
        await links.waitFor({ state: 'visible' });
        assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
        const destinations = links.getByRole('link');
        assert(await destinations.count() > 0);
        for (let index = 0; index < await destinations.count(); index++) {
          await page.keyboard.press('Tab');
          assert(await destinations.nth(index).evaluate((node) => node === document.activeElement),
            'Compact navigation keyboard order skipped a visible destination');
          if (audit) await audit();
        }
        await capture('navigation-open', viewport);
        await toggle.focus();
        await page.keyboard.press('Space');
        await page.keyboard.press('Tab');
        assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('href')), admin ? '/dashboard' : '/admin',
          'Collapsed navigation trapped focus in a hidden destination');
      } else {
        assert(!(await toggle.isVisible()), 'Desktop retained the compact disclosure');
        assert(await links.isVisible(), 'Desktop navigation rail is hidden');
        await capture('navigation-rail', viewport);
      }
    }
    await page.setViewportSize({ width: 1280, height: 800 });
    await (await active.count() ? active : links.getByRole('link').first()).focus();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(() => document.activeElement === document.querySelector('[data-portal-navigation-toggle]'));
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    await page.setViewportSize({ width: 1024, height: 800 });
    await page.waitForFunction(() => document.querySelector('[data-portal-navigation-links]')?.contains(document.activeElement));
    assert(await page.evaluate(() => document.__navigationReady?.isConnected && document.__navigationReady ===
      document.querySelector('[data-testid="portal-ready"], [data-testid="admin-ready"]')),
    'Navigation presentation remounted the security view');
    assert.deepEqual(calls, [], 'Navigation disclosure or breakpoint changes replayed API work');
  } finally {
    page.off('request', observe);
    await page.evaluate(() => { delete document.__navigationReady; });
    await page.setViewportSize({ width: 1280, height: 800 });
  }
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
      assert(decodePreferenceCookieValue(cookie[0].value).startsWith(`2~${locale}~`));
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
    // Calendar/time-zone actions can finish their controls before streamed metadata.
    await page.waitForFunction((title) => document.title === title, initialTitle);
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
  const sockets = new Set();
  const forwards = new Set();
  let closing;
  const ingress = httpsServer({ key, cert, minVersion: 'TLSv1.2' }, (request, response) => {
    const forwarded = httpRequest({ hostname: upstream.hostname, port: upstream.port,
      method: request.method, path: request.url,
      headers: { ...request.headers, host: new URL(origin).host,
        'x-forwarded-host': new URL(origin).host, 'x-forwarded-proto': 'https',
        'x-forwarded-for': request.socket.remoteAddress }, timeout: 15000 }, (result) => {
      response.writeHead(result.statusCode, result.headers);
      result.pipe(response);
    });
    forwards.add(forwarded);
    forwarded.once('close', () => forwards.delete(forwarded));
    forwarded.on('timeout', () => forwarded.destroy());
    forwarded.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { 'Cache-Control': 'private, no-store' });
      response.end();
    });
    request.on('aborted', () => forwarded.destroy());
    request.pipe(forwarded);
  });
  ingress.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  ingress.on('tlsClientError', () => {});
  ingress.listen(0, '127.0.0.1');
  await once(ingress, 'listening');
  origin = `https://localhost:${ingress.address().port}`;
  return { origin, tlsSPKI, certificate: cert,
    close() {
      return closing ||= (async () => {
        const stopped = new Promise((resolve, reject) => ingress.close((error) => error ? reject(error) : resolve()));
        // HTTPS preconnects may never reach the HTTP parser. Own raw sockets
        // as well as HTTP requests so teardown cannot wait for their timeout.
        ingress.closeAllConnections();
        for (const request of forwards) request.destroy();
        for (const socket of sockets) socket.destroy();
        try { await stopped; } finally { key.fill(0); }
        return { completed: true };
      })();
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
  assert.deepEqual(Object.keys(preference).sort(), ['calendar', 'locale', 'theme', 'timeZone']);
  assert(browserLocales.includes(preference.locale));
  assert(['auto', 'gregory', 'persian'].includes(preference.calendar));
  assert(browserThemes.includes(preference.theme));
  assert(typeof preference.timeZone === 'string' && preference.timeZone.length <= 64);
  assert(Intl.DateTimeFormat('en', { timeZone: preference.timeZone }).resolvedOptions().timeZone === preference.timeZone);
  return preference;
}

export async function exercisePreferenceFailure(page, expectResourceFailure = () => {}, { theme } = {}) {
  if (theme !== undefined) assert(browserThemes.includes(theme), 'Unsupported failed-save theme');
  const initialURL = page.url();
  const initialLocale = await page.locator('html').getAttribute('lang');
  const otherLocale = initialLocale === 'en' ? 'fa-IR' : 'en';
  const initialTheme = await page.locator('html').getAttribute('data-theme');
  const initialAppearance = await page.evaluate(() => ({ dark: document.documentElement.classList.contains('dark'),
    scheme: getComputedStyle(document.documentElement).colorScheme }));
  const details = page.locator('[data-ui-preferences] details');
  const summary = page.locator('[data-ui-preferences] summary');
  const wasOpen = await details.evaluate((node) => node.open);
  if (theme !== undefined && !wasOpen) await summary.click();
  const initialTitle = expectedPageTitle(new URL(initialURL).pathname, initialLocale);
  await page.waitForFunction((title) => document.title === title, initialTitle);
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
  const apiCalls = [];
  const observe = (request) => { if (new URL(request.url()).pathname.startsWith('/api/')) apiCalls.push(request.method()); };
  page.on('request', observe);
  const matcher = (url) => url.href === initialURL.split('#')[0];
  const handler = (route) => {
    const request = route.request();
    if (request.method() !== 'POST' || !request.headers()['next-action']) return route.fallback();
    const operation = (async () => {
      try {
        const input = preferenceActionInput({ url: request.url(), method: request.method(),
          type: request.resourceType(), headers: request.headers(), body: request.postData() }, initialURL);
        assert.equal(input.locale, theme === undefined ? otherLocale : initialLocale);
        assert.equal(input.theme, theme === undefined ? initialTheme : theme);
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
  const control = page.getByRole('combobox', { name: theme === undefined
    ? initialLocale === 'en' ? 'Language' : 'زبان'
    : initialLocale === 'en' ? 'Appearance' : 'ظاهر', exact: true });
  const nextValue = theme ?? otherLocale;
  const previousValue = theme === undefined ? initialLocale : initialTheme;
  try {
    await control.selectOption(nextValue);
    await Promise.race([started, page.waitForTimeout(5000).then(() => { throw new Error('Preference action fault did not reach its exact request'); })]);
    assert(!interceptionFailed, 'Preference failure injection escaped its exact action envelope');
    assert(await page.locator('[data-ui-preferences] select, [data-ui-preferences] button')
      .evaluateAll((controls) => controls.length >= 5 && controls.every((control) => control.disabled)),
    'Overlapping preference saves were not disabled');
    // Deliberately dispatch repeated changes against the real hydrated handler
    // while the network operation is held. The native disabled state above is
    // checked separately; the synchronous ownership lock must also hold.
    await control.evaluate((select, { nextValue, previousValue }) => {
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      for (const value of [nextValue, previousValue, nextValue]) {
        setter.call(select, value);
        select.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }, { nextValue, previousValue });
    await page.waitForTimeout(100);
    assert.equal(attempts, 1, 'Rapid preference changes transmitted overlapping saves');
    release();
    const failed = initialLocale === 'en'
      ? 'Preferences could not be saved. Your previous settings are unchanged.'
      : 'ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.';
    await page.locator('[data-ui-preferences] [role="status"]').filter({ hasText: failed }).waitFor({ state: 'visible' });
    await page.waitForFunction(() => !document.querySelector('[data-ui-preferences] select')?.disabled);
    assert.equal(await control.inputValue(), previousValue, 'Failed preference save changed the selected setting');
    assert.equal(await page.locator('html').getAttribute('lang'), initialLocale);
    assert.equal(await page.locator('html').getAttribute('dir'), initialLocale === 'en' ? 'ltr' : 'rtl');
    assert.equal(await page.locator('html').getAttribute('data-theme'), initialTheme);
    assert.deepEqual(await page.evaluate(() => ({ dark: document.documentElement.classList.contains('dark'),
      scheme: getComputedStyle(document.documentElement).colorScheme })), initialAppearance,
    'Failed preference save changed the applied appearance');
    await page.waitForFunction((title) => document.title === title, initialTitle);
    assert.equal(await page.title(), initialTitle);
    assert.equal(page.url(), initialURL);
    assert.equal(await page.evaluate(() => document.__failedPreferenceMarker), marker);
    assert.deepEqual((await page.context().cookies(new URL(initialURL).origin))
      .filter((cookie) => cookie.name === uiPreferenceCookie), initialCookies,
    'Failed preference action changed browser persistence');
    assert.equal(attempts, 1, 'Failed preference save automatically replayed');
    assert.deepEqual(apiCalls, [], 'Failed preferences replayed API work');
    assert(!interceptionFailed);
  } finally {
    release();
    page.off('request', observe);
    await Promise.all(pending);
    await page.unroute(matcher, handler);
    if (await details.evaluate((node) => node.open) !== wasOpen) await summary.click();
    await page.evaluate(() => { delete document.__failedPreferenceMarker; });
  }
}
