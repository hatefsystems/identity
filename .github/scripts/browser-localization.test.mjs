import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { runInNewContext } from 'node:vm';
import { createServer } from 'node:http';
import { get } from 'node:https';
import { createConnection } from 'node:net';
import { readFile } from 'node:fs/promises';
import { assertPublicStorageUnchanged, assertSafeRequests, assertThemeDocument, assertUnavailable, authRoutes, fetchPinnedCspDocument, storageSnapshot } from './web-csp.browser.mjs';
import {
  assertOnlyPreferenceCookies,
  browserLocale,
  browserThemes,
  browserViewports,
  focusedBrowserViewports,
  configureBrowserPreferences,
  decodePreferenceCookieValue,
  expectedPageTitle,
  exercisePreferenceSwitch,
  exercisePreferenceFailure,
  localizedText,
  localHTTPSProxy,
  preferenceActionInput,
  screenshotName,
  setBrowserLocale,
  setBrowserTheme,
} from './browser-localization.mjs';

test('preference switches verify exact request-aware titles for owned routes and inherited layouts', () => {
  assert.equal(expectedPageTitle('/', 'en'), 'Hatef Identity Platform');
  assert.equal(expectedPageTitle('/login', 'en'), 'Sign in | Hatef Identity');
  assert.equal(expectedPageTitle('/register/verify-email', 'en'), 'Verify registration email | Hatef Identity');
  assert.equal(expectedPageTitle('/register/verify-email', 'fa-IR'), 'تأیید ایمیل ثبت‌نام | هویت هاتف');
  assert.equal(expectedPageTitle('/dashboard/profile', 'en'), 'Profile | Hatef Identity');
  assert.equal(expectedPageTitle('/admin/integrity', 'en'), 'Admin Integrity Verification | Hatef Identity');
  assert.notEqual(expectedPageTitle('/recover-account', 'fa-IR'), expectedPageTitle('/recover-account', 'en'));
  assert.equal(expectedPageTitle('/admin/users/00000000-0000-4000-8000-000000000001', 'fa-IR'), expectedPageTitle('/admin', 'fa-IR'));
  assert.throws(() => expectedPageTitle('/unowned', 'en'));
  assert.throws(() => expectedPageTitle('/', 'untrusted'));
});

test('explicit prose substrings do not relax exact accessible-name expectations', () => {
  try {
    setBrowserLocale('fa-IR');
    const notice = 'This form is not connected yet. Do not enter real credentials.';
    const paragraph = 'پیش‌نمایش رابط کاربری این فرم هنوز متصل نیست. اطلاعات ورود واقعی را وارد نکنید.';
    assert.doesNotMatch(paragraph, localizedText(notice));
    assert.match(paragraph, localizedText(notice, { exact: false }));
    assert.doesNotMatch('پیشوند زبان پسوند', localizedText('Language'));
  } finally { setBrowserLocale('en'); }
});

test('browser locale expectations retain exact English/Persian accessible names and raw fixture bytes', () => {
  try {
    setBrowserLocale('en');
    assert.equal(localizedText('Verify code'), 'Verify code');
    assert.equal(browserLocale(), 'en');
    setBrowserLocale('fa-IR');
    assert.match('تأیید کد', localizedText('Verify code'));
    assert.doesNotMatch('Verify code', localizedText('Verify code'));
    assert.match('زبان', localizedText('Language'));
    assert.match('تعلیق', localizedText('Suspend'));
    assert.match('مشاهدهٔ حساب 9007199254740993', localizedText('View account 9007199254740993'));
    assert.match('حذف Browser key', localizedText(/^Remove /));
    assert.equal(localizedText('private@example.test'), 'private@example.test');
    assert.equal(
      localizedText('00000000-0000-4000-8000-000000000001'),
      '00000000-0000-4000-8000-000000000001'
    );
    assert.throws(() => setBrowserLocale('../en'));
    assert.equal(
      screenshotName('legal-holds', { width: 320, height: 256 }, true),
      'legal-holds-fa-IR-320x256-dark.png'
    );
    assert.throws(() =>
      screenshotName('../private@example.test', { width: 320, height: 256 }, false)
    );
  } finally {
    setBrowserLocale('en');
  }
});

test('username presentation has explicit bilingual browser names and remains structurally masked in artifacts', async () => {
  assert.equal(localizedText('Username', { locale: 'en' }), 'Username');
  try {
    setBrowserLocale('fa-IR');
    assert.match('نام کاربری', localizedText('Username'));
    assert.match('بررسی نام کاربری', localizedText('Check username'));
  } finally { setBrowserLocale('en'); }
  const csp = await readFile(new URL('./web-csp.browser.mjs', import.meta.url), 'utf8');
  const masks = csp.match(/mask: \[page\.locator\('[^']*'\)\]/g);
  assert(masks?.length > 0);
  for (const mask of masks) {
    assert(mask.includes('input, textarea'));
    assert(mask.includes('[data-username-private]'));
  }
  const portal = await readFile(new URL('./web-portal.browser.mjs', import.meta.url), 'utf8');
  const accountMasks = portal.match(/page\.locator\('input, textarea, main dd[^']*'\)/g);
  assert(accountMasks?.length >= 3, 'Account username must remain inside the existing structural dd masks');
});

test('preference setup uses only the secure browser cookie and anonymous document assertions reject session authority', async () => {
  const calls = [];
  const context = { addCookies: async (cookies) => calls.push(...cookies) };
  await configureBrowserPreferences(context, 'https://localhost:43210', 'en');
  assert.deepEqual(calls, []);
  await configureBrowserPreferences(context, 'https://localhost:43210', 'fa-IR');
  assert.equal(calls.length, 1);
  const [cookie] = calls;
  assert.equal(cookie.name, '__Host-hatef-ui');
  assert.equal(cookie.value, '2~fa-IR~auto~UTC~system');
  assert.equal(cookie.url, 'https://localhost:43210');
  assert(cookie.secure && cookie.httpOnly && cookie.sameSite === 'Lax');
  const browserCookie = { ...cookie, path: '/', domain: 'localhost' };
  assertOnlyPreferenceCookies([]);
  assertOnlyPreferenceCookies([browserCookie]);
  assertOnlyPreferenceCookies([{ ...browserCookie, value: '2~fa-IR~gregory~Asia%2FTehran~dark' }]);
  assertOnlyPreferenceCookies([{ ...browserCookie, value: '1~fa-IR~gregory~Asia%2FTehran' }]);
  assert.equal(
    decodePreferenceCookieValue('1~fa-IR~gregory~Asia%2FTehran'),
    '1~fa-IR~gregory~Asia/Tehran'
  );
  for (const encoded of [
    '1~fa-IR~auto~Asia%252FTehran',
    '1~fa-IR~auto~Asia%2fTehran',
    '1~fa-IR~auto~Asia%2FTehran%',
    '1~fa-IR~auto~US%2FEastern',
  ])
    assert.throws(() => decodePreferenceCookieValue(encoded));
  for (const bad of [
    { ...browserCookie, name: '__Host-session' },
    { ...browserCookie, secure: false },
    { ...browserCookie, httpOnly: false },
    { ...browserCookie, sameSite: 'None' },
    { ...browserCookie, path: '/recover-account' },
    { ...browserCookie, value: '1~fa-IR~auto~UTC\r\nSecret' },
  ])
    assert.throws(() => assertOnlyPreferenceCookies([bad]));
  assert.throws(() => assertOnlyPreferenceCookies([browserCookie, browserCookie]));
});

test('image browser HTTPS proxy retains verified local TLS and exact same-origin forwarded host', async () => {
  for (const invalid of [
    'https://127.0.0.1:43210',
    'http://remote.example.test:43210',
    'http://127.0.0.1:43210/path',
  ])
    await assert.rejects(() => localHTTPSProxy(invalid));
  const upstream = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json');
    response.end(
      JSON.stringify({
        host: request.headers.host,
        protocol: request.headers['x-forwarded-proto'],
        forwarded: request.headers['x-forwarded-host'],
        path: request.url,
      })
    );
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  let proxy;
  try {
    proxy = await localHTTPSProxy(`http://127.0.0.1:${upstream.address().port}`);
    const result = await new Promise((resolve, reject) => {
      const request = get(
        proxy.origin.replace('localhost', '127.0.0.1') + '/login',
        { ca: proxy.certificate },
        (response) => {
          let text = '';
          response.setEncoding('utf8');
          response.on('data', (chunk) => {
            text += chunk;
          });
          response.on('end', () => resolve(JSON.parse(text)));
        }
      );
      request.on('error', reject);
    });
    const host = new URL(proxy.origin).host;
    assert.deepEqual(result, { host, protocol: 'https', forwarded: host, path: '/login' });
    assert.match(proxy.tlsSPKI, /^[A-Za-z0-9+/]{43}=$/);
  } finally {
    await proxy?.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('preference fault injection permits only exact public Next action envelopes', () => {
  const page = 'https://localhost:43210/login';
  const values = { locale: 'fa-IR', calendar: 'auto', timeZone: 'UTC', theme: 'system' };
  const request = {
    method: 'POST',
    url: page,
    type: 'fetch',
    headers: { 'next-action': 'owned-action-id' },
    body: JSON.stringify([values]),
  };
  assert.deepEqual(preferenceActionInput(request, page), values);
  assert.deepEqual(preferenceActionInput(request, page + '#unchanged'), values);
  assert.equal(preferenceActionInput({ ...request, method: 'GET' }, page), undefined);
  assert.equal(preferenceActionInput({ ...request, headers: {} }, page), undefined);
  for (const change of [
    { url: 'https://remote.example.test/login' },
    { url: page + '?token=private' },
    { url: page + '#private' },
    { url: 'https://localhost:43210/api/v1/users/me' },
    { type: 'document' },
    { body: 'null' },
    { body: JSON.stringify(values) },
    { body: JSON.stringify([values, values]) },
    { body: JSON.stringify([{ ...values, token: 'PRIVATE' }]) },
    { body: JSON.stringify([{ ...values, locale: '../fa-IR' }]) },
    { body: JSON.stringify([{ ...values, calendar: 'hijri' }]) },
    { body: JSON.stringify([{ ...values, theme: 'untrusted' }]) },
    { body: JSON.stringify([{ locale: values.locale, calendar: values.calendar, timeZone: values.timeZone }]) },
    { body: JSON.stringify([{ ...values, timeZone: 'not-a-zone' }]) },
    { body: JSON.stringify([{ ...values, timeZone: 'US/Eastern' }]) },
    { body: JSON.stringify([{ ...values, timeZone: 'x'.repeat(512) }]) },
  ])
    assert.throws(() => preferenceActionInput({ ...request, ...change }, page));
});

test('CSP attack probe retrieves its real document only through the pinned local CA', async () => {
  const upstream = createServer((request, response) => {
    if (request.url.endsWith('000000000002')) {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('x'.repeat(2 * 1024 * 1024 + 1));
      return;
    }
    if (request.url.endsWith('000000000003')) {
      response.writeHead(302, { Location: 'https://example.test/' });
      response.end();
      return;
    }
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'",
    });
    response.end('<!doctype html><html><head></head><body>Public probe</body></html>');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  let proxy;
  try {
    proxy = await localHTTPSProxy(`http://127.0.0.1:${upstream.address().port}`);
    const url = new URL('/?__csp_fixture=00000000-0000-4000-8000-000000000001', proxy.origin);
    const result = await fetchPinnedCspDocument(url, proxy.certificate);
    assert.equal(result.status, 200);
    assert.equal(result.headers['content-security-policy'], "default-src 'self'");
    assert.match(result.body, /<body>Public probe<\/body>/);
    await assert.rejects(
      fetchPinnedCspDocument(url, undefined),
      /^Error: Pinned public CSP document retrieval failed$/
    );
    await assert.rejects(
      fetchPinnedCspDocument(
        new URL('/?__csp_fixture=00000000-0000-4000-8000-000000000002', proxy.origin),
        proxy.certificate
      ),
      /^Error: Pinned public CSP document retrieval failed$/
    );
    const redirect = await fetchPinnedCspDocument(
      new URL('/?__csp_fixture=00000000-0000-4000-8000-000000000003', proxy.origin),
      proxy.certificate
    );
    assert.equal(redirect.status, 302, 'Pinned retrieval must never follow a redirect');
    assert.throws(() =>
      fetchPinnedCspDocument(
        new URL('https://example.test/?__csp_fixture=00000000-0000-4000-8000-000000000001'),
        proxy.certificate
      )
    );
    assert.throws(() =>
      fetchPinnedCspDocument(new URL('/?token=private', proxy.origin), proxy.certificate)
    );
  } finally {
    await proxy?.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

for (const initialLocale of ['en', 'fa-IR']) {
  test(`preference round-trip waits for late streamed ${initialLocale} metadata without replaying API work`, async () => {
    const url = 'https://localhost:43210/dashboard/profile';
    const listeners = new Set();
    const document = {
      title: expectedPageTitle('/dashboard/profile', initialLocale), cookie: '',
      documentElement: { lang: initialLocale, dir: initialLocale === 'en' ? 'ltr' : 'rtl' },
      fonts: { ready: Promise.resolve() },
      querySelector: () => ({ disabled: false }), querySelectorAll: () => [],
    };
    let fontChecks = 0, delayedTitle = null, observedDelayedTitle = false;
    const realm = { document, crypto: { randomUUID: () => 'owned-document-marker' }, requestAnimationFrame: (done) => done() };
    const page = {
      url: () => url,
      title: async () => document.title,
      locator: () => ({ getAttribute: async (name) => document.documentElement[name] }),
      on: (_event, callback) => listeners.add(callback), off: (_event, callback) => listeners.delete(callback),
      getByRole: () => ({
        waitFor: async () => {},
        selectOption: async (locale) => {
          for (const callback of listeners) callback({ method: () => 'POST', headers: () => ({ 'next-action': 'owned-action' }), url: () => url });
          document.documentElement = { lang: locale, dir: locale === 'en' ? 'ltr' : 'rtl' };
          document.title = expectedPageTitle('/dashboard/profile', locale);
        },
      }),
      context: () => ({ cookies: async () => [{
        name: '__Host-hatef-ui', value: `2~${document.documentElement.lang}~auto~UTC~system`,
        secure: true, httpOnly: true, sameSite: 'Lax', path: '/', domain: 'localhost',
      }] }),
      evaluate: async (callback, argument) => {
        const value = await runInNewContext(`(${callback})(argument)`, { ...realm, argument });
        if (String(callback).includes('document.fonts.ready') && ++fontChecks === 2) {
          delayedTitle = document.title;
          document.title = 'metadata still streaming';
          observedDelayedTitle = true;
        }
        return value;
      },
      waitForFunction: async (callback, argument) => {
        if (delayedTitle) { document.title = delayedTitle; delayedTitle = null; }
        assert(await runInNewContext(`(${callback})(argument)`, { ...realm, argument }));
      },
    };
    await exercisePreferenceSwitch(page);
    assert(observedDelayedTitle, 'The regression must exercise metadata after the control transition');
    assert.equal(document.title, expectedPageTitle('/dashboard/profile', initialLocale));
    assert.equal(listeners.size, 0);
  });
}

test('image TLS proxy closes an owned preconnect before it sends a TLS handshake or HTTP request', { timeout: 10000 }, async () => {
  const upstream = createServer((_request, response) => response.end('owned'));
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  let ingress, socket, timer;
  try {
    ingress = await localHTTPSProxy(`http://127.0.0.1:${upstream.address().port}`);
    socket = createConnection({ host: '127.0.0.1', port: Number(new URL(ingress.origin).port) });
    await once(socket, 'connect');
    await new Promise((resolve) => setImmediate(resolve));
    const closed = once(socket, 'close');
    const first = ingress.close();
    assert.strictEqual(ingress.close(), first, 'Concurrent proxy close must share one teardown');
    const timeout = new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Owned TLS preconnect prevented teardown')), 2000); });
    assert.deepEqual(await Promise.race([first, timeout]), { completed: true });
    await closed;
  } finally {
    clearTimeout(timer);
    socket?.destroy();
    await ingress?.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});


test('public auth storage snapshots have a bounded deadline and never retry a stalled browser probe', async () => {
  let calls = 0;
  const stalled = { context: () => ({ storageState: () => { calls++; return new Promise(() => {}); } }) };
  await assert.rejects(storageSnapshot(stalled, 10), /snapshot timed out/);
  assert.equal(calls, 1);
  const complete = { context: () => ({ storageState: async () => ({ cookies: [], origins: [] }) }), evaluate: async () => [] };
  assert.deepEqual(await storageSnapshot(complete), { persistent: { cookies: [], origins: [] }, session: [] });
  const failure = new Error('unit-private-diagnostic');
  await assert.rejects(storageSnapshot({ context: () => ({ storageState: async () => { throw failure; } }) }), (error) => error === failure);
});

test('public CSP routes require passkey-only entry and availability notices, never disconnected form actions', () => {
  assert.deepEqual(authRoutes.map((route) => route.path), [
    '/login', '/register', '/login/webauthn', '/verify-totp', '/forgot-password', '/reset-password',
  ]);
  for (const route of authRoutes) {
    assert.equal([route.passkey, route.registration, route.availability].filter(Boolean).length, 1);
    if (route.registration) assert.deepEqual(route.fields.map((field) => field.name), ['email', 'phone', 'username']);
    else assert.deepEqual(route.fields, []);
    if (route.availability) {
      assert.equal(route.submit, undefined);
      assert.equal(route.back, 'Continue with a passkey');
      assert.match(route.heading, /unavailable$/);
    }
  }
});

test('CSP availability assertions use exact localized headings and safe real link actions in both locales', async () => {
  const notice = 'Use a passkey to sign in to an existing account, or create an account with email, phone and passkey verification.';
  const translatedNotice = 'برای ورود به حساب موجود از کلید عبور استفاده کنید، یا با تأیید ایمیل، تلفن و کلید عبور حساب بسازید.';
  const names = { en: ['Continue with a passkey', 'Create an account'], 'fa-IR': ['ادامه با کلید عبور', 'ایجاد حساب'] };
  try {
    for (const locale of ['en', 'fa-IR']) for (const route of authRoutes.filter((route) => route.availability)) {
      setBrowserLocale(locale);
      const heading = locale === 'en' ? route.heading : route.path === '/verify-totp'
        ? 'ورود با رمزساز در دسترس نیست' : 'بازنشانی گذرواژه در دسترس نیست';
      const expectedHeading = localizedText(route.heading);
      if (expectedHeading instanceof RegExp) assert.match(heading, expectedHeading);
      else assert.equal(heading, expectedHeading);
      let controls = 0, status = 0, alert = 0, destination = '/login';
      const main = {
        getByText: (expected, { exact }) => {
          assert.equal(exact, true);
          const actual = locale === 'en' ? notice : translatedNotice;
          if (expected instanceof RegExp) assert.match(actual, expected);
          else assert.equal(actual, expected);
          return { waitFor: async () => {} };
        },
        locator: (selector) => {
          assert.equal(selector, 'form, input, textarea, button');
          return { count: async () => controls };
        },
        getByRole: (role, options) => {
          if (role === 'status') return { count: async () => status };
          if (role === 'alert') return { count: async () => alert };
          assert.equal(role, 'link');
          assert.equal(options.exact, true);
          const index = names[locale].findIndex((name) => options.name instanceof RegExp
            ? options.name.test(name) : options.name === name);
          assert(index >= 0, 'A supported action has no exact localized accessible name');
          return { waitFor: async () => {}, getAttribute: async () => index === 0 ? destination : '/register' };
        },
      };
      const page = { getByRole: (role) => { assert.equal(role, 'main'); return main; } };
      for (const noScript of [false, true]) await assertUnavailable(page, route, noScript);
      controls = 1;
      await assert.rejects(assertUnavailable(page, route), /disconnected form/);
      controls = 0; status = 1;
      await assert.rejects(assertUnavailable(page, route), /progress\/success/);
      status = 0; alert = 1;
      await assert.rejects(assertUnavailable(page, route), /simulated authentication failure/);
      alert = 0; destination = '/forgot-password';
      await assert.rejects(assertUnavailable(page, route), /supported next action/);
    }
  } finally { setBrowserLocale('en'); }
});

test('passive CSP passkey entry keeps no-JS controls disabled and rejects disconnected fields, links or outcomes', async () => {
  try {
    for (const locale of ['en', 'fa-IR']) for (const route of authRoutes.filter((route) => route.passkey)) {
      setBrowserLocale(locale);
      let disabled = true, fields = 0, forgot = 0, forms = 0, status = '', alerts = 0;
      const main = {
        locator: (selector) => ({ count: async () => selector === 'form, input, textarea' ? fields : forgot }),
        getByRole: (role) => ({ count: async () => role === 'alert' ? alerts : 1, textContent: async () => status }),
      };
      const action = { waitFor: async () => {}, getAttribute: async () => 'button', isDisabled: async () => disabled };
      const page = {
        getByTestId: (id) => { assert.equal(id, 'passkey-login'); return action; },
        waitForFunction: async () => { assert.equal(disabled, false); },
        getByRole: (role, options) => {
          if (role === 'main') return main;
          if (role === 'form') return { count: async () => forms };
          assert.equal(role, 'button');
          assert.equal(options.exact, true);
          const actual = locale === 'en' ? route.submit : route.path === '/login' ? 'ادامه با کلید عبور' : 'استفاده از کلید عبور';
          if (options.name instanceof RegExp) assert.match(actual, options.name);
          else assert.equal(actual, options.name);
          return { count: async () => 1 };
        },
      };
      await assertUnavailable(page, route, true);
      disabled = false;
      await assertUnavailable(page, route);
      await assert.rejects(assertUnavailable(page, route, true), /disabled without JavaScript/);
      forms = 1;
      await assert.rejects(assertUnavailable(page, route), /no native submission/);
      forms = 0; fields = 1;
      await assert.rejects(assertUnavailable(page, route), /disconnected credential fields/);
      fields = 0; forgot = 1;
      await assert.rejects(assertUnavailable(page, route), /unsupported password recovery/);
      forgot = 0; alerts = 1;
      await assert.rejects(assertUnavailable(page, route), /authentication outcome/);
      alerts = 0; status = 'Sign-in completed.';
      await assert.rejects(assertUnavailable(page, route), /progress or success/);
    }
  } finally { setBrowserLocale('en'); }
});

test('CSP public request guards reject auth work, malformed preference actions and credential leakage', () => {
  const origin = 'https://localhost:43210';
  const paths = new Set(['/', ...authRoutes.map((route) => route.path)]);
  const navigation = { url: origin + '/login', method: 'GET', type: 'document', headers: {}, body: null };
  const observed = (request = navigation) => ({ requests: [request], navigations: [], consoleMessages: [] });
  assertSafeRequests(observed(), origin, paths, ['synthetic-secret']);
  assertSafeRequests(observed({ ...navigation, type: 'fetch', headers: { rsc: '1' }, url: origin + '/register?_rsc=safe' }), origin, paths, []);
  assertSafeRequests(observed({ ...navigation, method: 'POST', type: 'fetch', headers: { 'next-action': 'owned-action' },
    body: JSON.stringify([{ locale: 'en', calendar: 'auto', timeZone: 'UTC', theme: 'system' }]) }), origin, paths, []);
  for (const change of [
    { url: 'https://external.example.test/login' },
    { url: origin + '/api/v1/auth/webauthn/login/generate-options' },
    { method: 'POST', body: '{}' },
    { body: 'credential' },
    { type: 'fetch' },
    { type: 'fetch', headers: { rsc: '1' }, url: origin + '/login?_rsc=safe&password=synthetic-secret' },
    { method: 'POST', type: 'fetch', headers: { 'next-action': 'owned-action' }, body: '[{"token":"synthetic-secret"}]' },
  ]) assert.throws(() => assertSafeRequests(observed({ ...navigation, ...change }), origin, paths, ['synthetic-secret']));
  for (const encoded of ['synthetic-secret', encodeURIComponent('secret value'), 'secret+value']) {
    const state = observed();
    state.consoleMessages.push(encoded);
    assert.throws(() => assertSafeRequests(state, origin, paths, ['synthetic-secret', 'secret value']), /exposed a synthetic credential/);
  }
});

test('forced colors permit only the UA light/dark pair and keep selected mode and native widget consistency strict', async () => {
  const { browserThemeMatchesDocument } = await import('./browser-localization.mjs');
  const keys = ['document', 'getComputedStyle', 'matchMedia'];
  const originals = keys.map((key) => Object.getOwnPropertyDescriptor(globalThis, key));
  let mode, osDark, forced, rootScheme, controlScheme, classDark, animations = [];
  const root = { getAttribute: () => mode, classList: { contains: () => classDark } };
  const control = { checkVisibility: () => true };
  try {
    Object.defineProperty(globalThis, 'document', { configurable: true, value: {
      documentElement: root, querySelectorAll: () => [control], getAnimations: () => animations,
    } });
    Object.defineProperty(globalThis, 'getComputedStyle', { configurable: true, value: (node) => ({ colorScheme: node === root ? rootScheme : controlScheme }) });
    Object.defineProperty(globalThis, 'matchMedia', { configurable: true, value: (query) => ({ matches: query === '(forced-colors: active)' ? forced : osDark }) });
    for (mode of ['system', 'light', 'dark']) for (osDark of [false, true]) for (forced of [false, true]) {
      classDark = mode === 'dark' || (mode === 'system' && osDark);
      rootScheme = controlScheme = forced ? 'light dark' : classDark ? 'dark' : 'light';
      assert.equal(browserThemeMatchesDocument(mode), true);
    }
    mode = 'light'; osDark = classDark = forced = false;
    rootScheme = controlScheme = 'light dark';
    assert.equal(browserThemeMatchesDocument(mode), false);
    forced = true; controlScheme = 'light';
    assert.equal(browserThemeMatchesDocument(mode), false);
    controlScheme = rootScheme; classDark = true;
    assert.equal(browserThemeMatchesDocument(mode), false);
    classDark = false; animations = [{ playState: 'running', effect: { getTiming: () => ({ iterations: 1 }) } }];
    assert.equal(browserThemeMatchesDocument(mode), false);
  } finally {
    keys.forEach((key, index) => originals[index] ? Object.defineProperty(globalThis, key, originals[index]) : Reflect.deleteProperty(globalThis, key));
  }
});

test('no-JS font readiness observes loaded CSS fonts without scheduling page animation callbacks', async () => {
  const { waitForFonts } = await import('./browser-localization.mjs');
  const calls = [];
  await waitForFonts({
    evaluate: async () => { throw new Error('No-JS readiness must not schedule page callbacks'); },
    waitForFunction: async (predicate, argument, options) => { calls.push({ source: predicate.toString(), argument, options }); },
  }, { animationFrames: false, timeout: 50 });
  assert.equal(calls.length, 1);
  assert.match(calls[0].source, /document\.fonts\.status === 'loaded'/);
  assert(!calls[0].source.includes('requestAnimationFrame'));
  assert.deepEqual(calls[0].options, { polling: 100, timeout: 50 });
});

test('font/render readiness has one Node deadline and never retries a stalled page callback', async () => {
  const { waitForFonts } = await import('./browser-localization.mjs');
  let calls = 0;
  await assert.rejects(waitForFonts({ evaluate: () => { calls += 1; return new Promise(() => {}); } }, { timeout: 20 }), /Browser font and render readiness timed out/);
  assert.equal(calls, 1);
});

test('appearance failure diagnostics expose fixed categories and numeric counts, never control text', async () => {
  const { authAppearanceCounts } = await import('./web-csp.browser.mjs');
  const privateValue = 'private-fixture-mailbox@example.test';
  const result = authAppearanceCounts([
    'Horizontal document scrolling',
    'Application inline style attribute',
    `${privateValue}: outside the document's usable width/top`,
    `${privateValue}: clipped by SECTION`,
    `${privateValue}: touch area 20x20, need 44x44`,
    `Text ${privateValue}: 2.00:1, need 4.5:1`,
    `${privateValue}: missing a 3:1, 2px keyboard focus indicator`,
    privateValue,
  ]);
  assert.deepEqual(result, { total: 8, horizontal: 1, inlineStyle: 1, geometry: 2, targets: 1, contrast: 1, focus: 1, other: 1 });
  assert(!JSON.stringify(result).includes(privateValue));
  assert.deepEqual(authAppearanceCounts([]), { total: 0, horizontal: 0, inlineStyle: 0, geometry: 0, targets: 0, contrast: 0, focus: 0, other: 0 });
});

test('appearance documents require validated SSR mode and the exact nonce-bound constant System head initializer', () => {
  const initializer = "(function(){document.documentElement.getAttribute('data-theme')})()";
  const document = (theme, script = '', classes = theme === 'dark' ? 'dark' : '') =>
    `<html data-theme="${theme}" class="${classes}"><head>${script}</head><body></body></html>`;
  for (const theme of browserThemes) {
    const script = theme === 'system' ? `<script nonce="owned">${initializer}</script>` : '';
    assertThemeDocument(document(theme, script), { theme, nonce: 'owned', initializer });
  }
  for (const html of [document('system'), document('system', `<script nonce="wrong">${initializer}</script>`),
    document('system', `<script nonce="owned">${initializer}/*changed*/</script>`),
    document('system', `<script nonce="owned">${initializer}</script>`, 'dark'),
    document('dark', `<script nonce="owned">${initializer}</script>`), document('dark', '', ''),
    document('system', `<script nonce="owned">${initializer}</script><script nonce="owned">${initializer}</script>`),
  ]) assert.throws(() => assertThemeDocument(html, { theme: html.includes('data-theme="dark"') ? 'dark' : 'system', nonce: 'owned', initializer }));
  assert.deepEqual(focusedBrowserViewports.map((viewport) => viewport.width), [320, 375, 390, 430, 768, 1024, 1280, 1440, 1920]);
  assert(browserViewports.some((viewport) => viewport.width === 320 && viewport.height === 256));
});

test('public storage comparisons allow only explicit preference lifetime renewal, never changed values or proof authority', () => {
  const cookie = { name: '__Host-hatef-ui', value: '2~en~auto~UTC~system', secure: true, httpOnly: true, sameSite: 'Lax', path: '/', domain: 'localhost', expires: 100 };
  const state = { persistent: { cookies: [cookie], origins: [] }, session: [] };
  assertPublicStorageUnchanged(state, { ...state, persistent: { ...state.persistent, cookies: [{ ...cookie, expires: 200 }] } });
  for (const after of [
    { ...state, session: [['PRIVATE', 'unexpected']] },
    { ...state, persistent: { ...state.persistent, origins: [{ origin: 'https://localhost', indexedDB: [{}] }] } },
    { ...state, persistent: { ...state.persistent, cookies: [{ ...cookie, value: '2~en~auto~UTC~dark' }] } },
    { ...state, persistent: { ...state.persistent, cookies: [{ ...cookie, name: '__Host-session' }] } },
  ]) assert.throws(() => assertPublicStorageUnchanged(state, after));
});

test('real Appearance helper saves all six choice/OS combinations in both locales and restores disclosure without API replay', async () => {
  const fixture = ({ locale, os, open, initial, clearDraft = false, apiReplay = false }) => {
    const listeners = new Set();
    const requests = [];
    const details = { open };
    const control = { value: initial, disabled: false };
    const input = { value: 'PRIVATE-FIXTURE-DRAFT', isConnected: true, checkVisibility: () => true };
    const root = { theme: initial, lang: locale, getAttribute: (name) => name === 'data-theme' ? root.theme : root.lang,
      classList: { contains: () => root.theme === 'dark' || (root.theme === 'system' && os === 'dark') } };
    const document = { documentElement: root, fonts: { ready: Promise.resolve() },
      querySelector: () => control, querySelectorAll: () => [input], getAnimations: () => [] };
    const realm = { document, crypto: { randomUUID: () => 'owned-theme-document' },
      matchMedia: () => ({ matches: os === 'dark' }),
      getComputedStyle: () => ({ colorScheme: root.classList.contains('dark') ? 'dark' : 'light' }),
      requestAnimationFrame: (done) => done() };
    const evaluate = (callback, argument, node) => runInNewContext(`(${callback})(argument)`, { ...realm, argument: node ?? argument });
    const url = 'https://localhost:43210/dashboard/profile';
    const page = {
      url: () => url, on: (_event, callback) => listeners.add(callback), off: (_event, callback) => listeners.delete(callback),
      locator: (selector) => selector === 'html' ? { getAttribute: async (name) => root.getAttribute(name) }
        : selector.endsWith('details') ? { evaluate: async (callback) => evaluate(callback, undefined, details) }
          : { click: async () => { details.open = !details.open; } },
      context: () => ({ cookies: async () => [{ name: '__Host-hatef-ui', value: `2~${locale}~auto~UTC~${root.theme}`,
        secure: true, httpOnly: true, sameSite: 'Lax', path: '/', domain: 'localhost' }] }),
      evaluate: async (callback, argument) => structuredClone(await evaluate(callback, argument)),
      waitForFunction: async (callback, argument) => { assert(await evaluate(callback, argument)); },
      getByRole: (role, options) => {
        assert.equal(role, 'combobox'); assert.equal(options.name, locale === 'en' ? 'Appearance' : 'ظاهر'); assert(options.exact);
        return { waitFor: async () => {}, inputValue: async () => control.value, selectOption: async (theme) => {
          root.theme = control.value = theme;
          if (clearDraft) input.value = '';
          const request = { url: () => url, method: () => 'POST', headers: () => ({ 'next-action': 'owned' }),
            resourceType: () => 'fetch', postData: () => JSON.stringify([{ locale, calendar: 'auto', timeZone: 'UTC', theme }]) };
          requests.push(request);
          for (const callback of listeners) callback(request);
          if (apiReplay) for (const callback of listeners) callback({ ...request, url: () => 'https://localhost:43210/api/v1/users/me', method: () => 'GET', headers: () => ({}) });
        } };
      },
    };
    return { page, details, document, listeners, requests };
  };
  for (const locale of ['en', 'fa-IR']) for (const os of ['light', 'dark']) for (const theme of browserThemes) for (const open of [false, true]) {
    const current = fixture({ locale, os, open, initial: theme === 'dark' ? 'light' : 'dark' });
    await setBrowserTheme(current.page, theme);
    assert.equal(current.details.open, open);
    assert.equal(current.requests.length, 1);
    await setBrowserTheme(current.page, theme);
    assert.equal(current.requests.length, 1, 'Selecting the current mode must not manufacture a save');
    assert.equal(current.listeners.size, 0);
    assert.equal(current.document.__themeSnapshot, undefined);
  }
  for (const fault of [{ clearDraft: true }, { apiReplay: true }]) {
    const current = fixture({ locale: 'en', os: 'light', open: false, initial: 'system', ...fault });
    await assert.rejects(setBrowserTheme(current.page, 'dark'), /(?:cleared a draft|replayed API work)/);
    assert.equal(current.details.open, false);
    assert.equal(current.listeners.size, 0);
  }
  await assert.rejects(setBrowserTheme({}, '../dark'), /Unsupported browser theme/);
});

for (const locale of ['en', 'fa-IR']) test(`failed theme save waits for initial and late streamed ${locale} metadata and keeps the exact title`, async () => {
  class Select {
    get value() { return this.current; }
    set value(value) { this.current = value; }
    dispatchEvent() { return true; }
  }
  const control = new Select(); control.value = 'system'; control.disabled = false;
  const details = { open: false };
  const root = { lang: locale, dir: locale === 'en' ? 'ltr' : 'rtl', theme: 'system', classList: { contains: () => false } };
  const document = { title: 'initial metadata streaming', documentElement: root, fonts: { ready: Promise.resolve() }, querySelector: () => control };
  const realm = { document, crypto: { randomUUID: () => 'owned-failed-document' }, HTMLSelectElement: Select,
    Event: class {}, getComputedStyle: () => ({ colorScheme: 'light' }), requestAnimationFrame: (done) => done() };
  const url = 'https://localhost:43210/login';
  const expected = expectedPageTitle('/login', locale);
  const listeners = new Set();
  let handler, completion, initialWait = false, finalWait = false;
  const evaluate = (callback, argument) => runInNewContext(`(${callback})(argument)`, { ...realm, argument });
  const page = {
    url: () => url, title: async () => document.title,
    on: (_event, callback) => listeners.add(callback), off: (_event, callback) => listeners.delete(callback),
    locator: (selector) => selector === 'html' ? { getAttribute: async (name) => name === 'data-theme' ? root.theme : root[name] }
      : selector.endsWith('details') ? { evaluate: async (callback) => evaluate(callback, details) }
        : selector.endsWith('summary') ? { click: async () => { details.open = !details.open; } }
          : { evaluateAll: async (callback) => evaluate(callback, Array.from({ length: 5 }, () => ({ disabled: control.disabled }))),
            filter: ({ hasText }) => {
              assert.equal(hasText, locale === 'en' ? 'Preferences could not be saved. Your previous settings are unchanged.' : 'ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.');
              return { waitFor: async () => { await completion; } };
            } },
    context: () => ({ cookies: async () => [{ name: '__Host-hatef-ui', value: `2~${locale}~auto~UTC~system`,
      secure: true, httpOnly: true, sameSite: 'Lax', path: '/', domain: 'localhost' }] }),
    route: async (_matcher, callback) => { handler = callback; }, unroute: async () => { handler = undefined; },
    evaluate: async (callback, argument) => structuredClone(await evaluate(callback, argument)),
    waitForFunction: async (callback, argument) => {
      if (String(callback).includes('document.title === title') && document.title !== expected) {
        if (document.title === 'initial metadata streaming') initialWait = true; else finalWait = true;
        assert.equal(argument, expected); document.title = expected;
      }
      assert(await evaluate(callback, argument));
    },
    waitForTimeout: async () => {},
    getByRole: (_role, options) => {
      assert.equal(options.name, locale === 'en' ? 'Appearance' : 'ظاهر');
      return { inputValue: async () => control.value,
        evaluate: async (callback, argument) => runInNewContext(`(${callback})(control, argument)`, { ...realm, control, argument }),
        selectOption: async (theme) => {
          control.value = theme; control.disabled = true;
          const request = { url: () => url, method: () => 'POST', headers: () => ({ 'next-action': 'owned' }), resourceType: () => 'fetch',
            postData: () => JSON.stringify([{ locale, calendar: 'auto', timeZone: 'UTC', theme }]) };
          for (const callback of listeners) callback(request);
          completion = handler({ request: () => request, abort: async () => {}, continue: async () => {},
            fulfill: async () => { control.value = 'system'; control.disabled = false; document.title = 'late action metadata streaming'; } });
        },
      };
    },
  };
  await exercisePreferenceFailure(page, () => {}, { theme: 'dark' });
  assert(initialWait && finalWait, 'Both streamed metadata boundaries must be exercised');
  assert.equal(document.title, expected);
  assert.equal(details.open, false);
  assert.equal(listeners.size, 0);
  assert.equal(document.__failedPreferenceMarker, undefined);
});
