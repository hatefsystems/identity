import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { runInNewContext } from 'node:vm';
import { createServer } from 'node:http';
import { get } from 'node:https';
import { createConnection } from 'node:net';
import { fetchPinnedCspDocument } from './web-csp.browser.mjs';
import {
  assertOnlyPreferenceCookies,
  browserLocale,
  configureBrowserPreferences,
  decodePreferenceCookieValue,
  expectedPageTitle,
  exercisePreferenceSwitch,
  localizedText,
  localHTTPSProxy,
  preferenceActionInput,
  screenshotName,
  setBrowserLocale,
} from './browser-localization.mjs';

test('preference switches verify exact request-aware titles for owned routes and inherited layouts', () => {
  assert.equal(expectedPageTitle('/', 'en'), 'Hatef Identity Platform');
  assert.equal(expectedPageTitle('/login', 'en'), 'Sign in | Hatef Identity');
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

test('preference setup uses only the secure browser cookie and anonymous document assertions reject session authority', async () => {
  const calls = [];
  const context = { addCookies: async (cookies) => calls.push(...cookies) };
  await configureBrowserPreferences(context, 'https://localhost:43210', 'en');
  assert.deepEqual(calls, []);
  await configureBrowserPreferences(context, 'https://localhost:43210', 'fa-IR');
  assert.equal(calls.length, 1);
  const [cookie] = calls;
  assert.equal(cookie.name, '__Host-hatef-ui');
  assert.equal(cookie.value, '1~fa-IR~auto~UTC');
  assert.equal(cookie.url, 'https://localhost:43210');
  assert(cookie.secure && cookie.httpOnly && cookie.sameSite === 'Lax');
  const browserCookie = { ...cookie, path: '/', domain: 'localhost' };
  assertOnlyPreferenceCookies([]);
  assertOnlyPreferenceCookies([browserCookie]);
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
  const values = { locale: 'fa-IR', calendar: 'auto', timeZone: 'UTC' };
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
        name: '__Host-hatef-ui', value: `1~${document.documentElement.lang}~auto~UTC`,
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
