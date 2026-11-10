import {
  assertOnlyPreferenceCookies,
  browserLocale,
  browserLocales,
  browserThemes,
  browserViewports,
  focusedBrowserViewports,
  assertBrowserTheme,
  configureBrowserPreferences,
  exercisePreferenceFailure,
  exercisePreferenceSwitch,
  localHTTPSProxy,
  localizedText,
  preferenceActionInput,
  screenshotName,
  setBrowserLocale,
  setBrowserTheme,
  withTextResize,
  waitForFonts,
} from './browser-localization.mjs';
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { browserFailure } from './portal-harness.mjs';
import { smokeImage, webDocumentNonce } from './smoke-image.mjs';

const availabilityNotice = 'Use a passkey to sign in to an existing account, or create an account with email, phone and passkey verification.';
const email = { name: 'email', label: 'Email address' };
export const authRoutes = [
  {
    path: '/login',
    heading: 'Sign in to Hatef',
    submit: 'Continue with a passkey',
    passkey: true,
    fields: [],
    back: 'Create an account',
    backPath: '/register',
  },
  {
    path: '/register',
    heading: 'Create your account',
    submit: 'Start registration and send email',
    registration: true,
    fields: [email, { name: 'phone', label: 'Iranian mobile number' }],
    back: 'Sign in',
  },
  {
    path: '/login/webauthn',
    heading: 'Sign in with a passkey',
    submit: 'Use a passkey',
    passkey: true,
    fields: [],
    back: 'Return to sign in',
  },
  {
    path: '/verify-totp',
    heading: 'Authenticator sign-in unavailable',
    availability: true,
    fields: [],
    back: 'Continue with a passkey',
  },
  {
    path: '/forgot-password',
    heading: 'Password reset unavailable',
    availability: true,
    fields: [],
    back: 'Continue with a passkey',
  },
  {
    path: '/reset-password',
    heading: 'Password reset unavailable',
    availability: true,
    fields: [],
    back: 'Continue with a passkey',
  },
];
const viewports = [...browserViewports, ...focusedBrowserViewports
  .filter((viewport) => !browserViewports.some((base) => base.width === viewport.width && base.height === viewport.height))];

export function assertThemeDocument(html, { theme, nonce, initializer }) {
  assert(browserThemes.includes(theme));
  const root = html.match(/<html\b([^>]*)>/i)?.[1];
  assert(root, 'Appearance document has no root element');
  assert.equal(root.match(/\bdata-theme="([^"]*)"/)?.[1], theme, 'SSR selected theme differs from the saved choice');
  const dark = (root.match(/\bclass="([^"]*)"/)?.[1] ?? '').split(/\s+/).includes('dark');
  assert.equal(dark, theme === 'dark', 'Explicit SSR appearance is not deterministic');
  const head = html.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i)?.[1] ?? '';
  const initializers = [...head.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
    .filter((match) => match[2].includes("getAttribute('data-theme')"));
  assert.equal(initializers.length, theme === 'system' ? 1 : 0, 'System requires exactly one head initializer only');
  if (theme === 'system') {
    assert.equal(initializers[0][2], initializer, 'Appearance initializer is not the constant reviewed source');
    assert.equal(initializers[0][1].match(/\bnonce="([^"]*)"/)?.[1], nonce, 'Appearance initializer lacks the request nonce');
  }
}

async function checkPublicAppearance(browser, baseURL, documentPaths) {
  const source = await readFile(new URL('../../apps/web/i18n/theme.ts', import.meta.url), 'utf8');
  const literal = source.match(/export const themeInitializer\s*=\s*("(?:[^"\\]|\\.)*");/);
  assert(literal, 'Appearance initializer must remain a constant string');
  const initializer = JSON.parse(literal[1]);
  const results = [];
  const seenNonces = new Set();
  for (const theme of browserThemes) for (const os of ['light', 'dark']) {
    const context = await browser.newContext({ bypassCSP: false, serviceWorkers: 'block', colorScheme: os });
    try {
      await configureBrowserPreferences(context, new URL(baseURL).origin, browserLocale(), theme);
      await context.addInitScript(() => {
        globalThis.__appearanceFrames = [];
        globalThis.__appearanceCsp = [];
        globalThis.__appearanceCredentials = [];
        globalThis.__appearanceShifts = [];
        globalThis.__appearanceShiftBoundary = 0;
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) if (entry.startTime >= globalThis.__appearanceShiftBoundary)
            globalThis.__appearanceShifts.push(entry.value);
        }).observe({ type: 'layout-shift', buffered: true });
        document.addEventListener('securitypolicyviolation', (event) => globalThis.__appearanceCsp.push(event.effectiveDirective));
        for (const method of ['get', 'create', 'store', 'preventSilentAccess']) {
          const prototype = globalThis.CredentialsContainer?.prototype;
          const original = prototype?.[method];
          if (original) prototype[method] = function (...args) {
            globalThis.__appearanceCredentials.push(method);
            return Reflect.apply(original, this, args);
          };
        }
        const sample = () => {
          const root = document.documentElement;
          if (document.body && root && getComputedStyle(root).getPropertyValue('--background').trim())
            globalThis.__appearanceFrames.push({ selected: root.getAttribute('data-theme'),
              dark: root.classList.contains('dark'), scheme: getComputedStyle(root).colorScheme });
          if (!globalThis.__appearanceSettled && globalThis.__appearanceFrames.length < 120) requestAnimationFrame(sample);
        };
        requestAnimationFrame(sample);
      });
      const page = await context.newPage();
      page.setDefaultTimeout(15000);
      const observed = observePage(page);
      const cold = async () => {
        const response = await page.goto(new URL('/', baseURL).href, { waitUntil: 'load' });
        assert.equal(response.status(), 200);
        const html = await response.text();
        const nonce = webDocumentNonce(new Headers(await response.allHeaders()), html, seenNonces);
        assertThemeDocument(html, { theme, nonce, initializer });
        await assertBrowserTheme(page, theme);
        await waitForExternalCss(page);
        await waitForFonts(page);
        const frames = await page.evaluate(() => { globalThis.__appearanceSettled = true; return globalThis.__appearanceFrames; });
        assert(frames.length > 0, 'Safe public probe did not observe any styled rendering frame');
        const dark = theme === 'dark' || (theme === 'system' && os === 'dark');
        assert(frames.every((frame) => frame.selected === theme && frame.dark === dark && frame.scheme === (dark ? 'dark' : 'light')),
          'Safe public probe observed a wrong first-paint appearance frame');
        assert.deepEqual(await page.evaluate(() => globalThis.__appearanceCsp), [], 'Appearance initializer violated strict CSP');
        return frames.length;
      };
      const frames = await cold();
      if (process.env.WEB_BROWSER_ARTIFACT_DIR) {
        await mkdir(resolve(process.env.WEB_BROWSER_ARTIFACT_DIR), { recursive: true });
        await page.screenshot({
          path: resolve(process.env.WEB_BROWSER_ARTIFACT_DIR, screenshotName(`appearance-${theme}-os-${os}`, { width: 1280, height: 720 }, theme === 'dark' || (theme === 'system' && os === 'dark'))),
          fullPage: true, caret: 'initial', animations: 'disabled', mask: [page.locator('input, textarea, [data-legal-private]')],
        });
      }
      const alternate = theme === 'dark' ? 'light' : 'dark';
      await setBrowserTheme(page, alternate);
      await setBrowserTheme(page, theme);
      await exercisePreferenceFailure(page, observed.expectResourceFailure, { theme: alternate });
      await cold();
      const marker = randomUUID();
      await page.evaluate((marker) => { document.__appearanceNavigation = marker; }, marker);
      await Promise.all([page.waitForURL(new URL('/login', baseURL).href),
        page.getByRole('link', { name: localizedText('Sign in'), exact: true }).click()]);
      await assertBrowserTheme(page, theme);
      assert.equal(await page.evaluate(() => document.__appearanceNavigation), marker,
        'Theme navigation replaced the document');
      await waitForFonts(page);
      await page.evaluate(() => { globalThis.__appearanceShiftBoundary = performance.now(); globalThis.__appearanceShifts = []; });
      const before = observed.requests.length;
      await page.emulateMedia({ colorScheme: os === 'dark' ? 'light' : 'dark' });
      await assertBrowserTheme(page, theme);
      await waitForFonts(page);
      assert.equal(await page.evaluate(() => globalThis.__appearanceShifts.reduce((sum, value) => sum + value, 0)), 0,
        'An OS theme change shifted the settled safe public layout');
      assert.equal(observed.requests.slice(before).filter((request) => request.method === 'POST' || new URL(request.url).pathname.startsWith('/api/')).length, 0,
        'An OS appearance change saved preferences or replayed API work');
      assert.deepEqual(await page.evaluate(() => globalThis.__appearanceCredentials), [], 'Appearance changes started a credentials ceremony');
      assertSafeRequests(observed, baseURL, documentPaths, []);
      assert.deepEqual(observed.errors, [], 'Public appearance runtime/CSP regression');
      results.push({ theme, os, styledColdFrames: frames });
    } finally { await context.close(); }
  }
  console.log(JSON.stringify({ check: 'safe-public-appearance', locale: browserLocale(), combinations: results }));
}

// Browser SPKI trust does not configure Playwright's Node-side route.fetch.
// Retrieve only this public probe through the same ingress using its exact CA.
export function fetchPinnedCspDocument(url, certificate, cookies = []) {
  assert(
    url instanceof URL && url.protocol === 'https:' && url.hostname === 'localhost' && url.port
  );
  assert.equal(url.pathname, '/');
  assert.deepEqual([...url.searchParams.keys()], ['__csp_fixture']);
  assert.match(url.searchParams.get('__csp_fixture'), /^[a-f0-9-]{36}$/);
  assertOnlyPreferenceCookies(cookies);
  const headers = cookies.length
    ? { Cookie: cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ') }
    : {};
  return new Promise((resolve, reject) => {
    const fail = () => reject(new Error('Pinned public CSP document retrieval failed'));
    const request = httpsRequest(
      url,
      { method: 'GET', ca: certificate, headers, timeout: 30_000 },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 2 * 1024 * 1024) {
            request.destroy(new Error('Public CSP document exceeded its bound'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('error', fail);
        response.on('aborted', fail);
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          chunks.length = 0;
          resolve({
            status: response.statusCode,
            headers: Object.fromEntries(
              Object.entries(response.headers)
                .filter(([, value]) => value !== undefined)
                .map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : value])
            ),
            body,
          });
        });
      }
    );
    request.on('timeout', () =>
      request.destroy(new Error('Public CSP document retrieval timed out'))
    );
    request.on('error', fail);
    request.end();
  });
}

async function waitForExternalCss(page, dark) {
  dark ??= await page.locator('html').evaluate((root) => root.classList.contains('dark'));
  await page.waitForFunction((dark) => {
    const externalStylesheet = [...document.querySelectorAll('link[rel="stylesheet"]')].some(
      (link) =>
        link.href.startsWith(`${location.origin}/_next/static/`) && link.sheet?.cssRules.length > 0
    );
    return (
      externalStylesheet &&
      getComputedStyle(document.documentElement).getPropertyValue('--background').trim() ===
        (dark ? '222.2 84% 4.9%' : '0 0% 100%')
    );
  }, dark);
  // Palette changes can transition button colors; measure their final colors, not an intermediate frame.
  await page.waitForFunction(() => document.getAnimations()
    .filter((animation) => animation.effect?.getTiming().iterations !== Infinity)
    .every((animation) => animation.playState === 'finished' || animation.playState === 'idle'));
}

async function waitForReactHandler(locator, handler) {
  const element = await locator.elementHandle();
  assert(element, `Missing hydration target for ${handler}`);
  await locator
    .page()
    .waitForFunction(
      ({ element, handler }) =>
        Object.keys(element).some(
          (key) => key.startsWith('__reactProps$') && typeof element[key]?.[handler] === 'function'
        ),
      { element, handler }
    );
  await element.dispose();
}

function observePage(page, expected404s = new Set()) {
  const errors = [];
  const requests = [];
  const navigations = [];
  const consoleMessages = [];
  const expectedResourceFailures = [];
  const fontResources = [];
  const fontTasks = [];
  let fontFailures = 0;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    const text = message.text();
    consoleMessages.push(text);
    if (message.type() !== 'error' && !/hydration|Content Security Policy/i.test(text)) return;
    if (
      text === 'Failed to load resource: the server responded with a status of 404 (Not Found)' &&
      expected404s.has(message.location().url)
    ) {
      return;
    }
    const expected = expectedResourceFailures.find(
      (failure) =>
        !failure.observed &&
        failure.url === message.location().url &&
        failure.status === 503 &&
        text ===
          'Failed to load resource: the server responded with a status of 503 (Service Unavailable)'
    );
    if (expected) {
      expected.observed = true;
      return;
    }
    errors.push(`${message.type()}: ${text} (${message.location().url})`);
  });
  page.on('request', (request) => {
    requests.push({
      url: request.url(),
      method: request.method(),
      type: request.resourceType(),
      headers: request.headers(),
      body: request.postData(),
    });
  });
  page.on('response', (response) => {
    if (response.request().resourceType() !== 'font') return;
    fontTasks.push(
      (async () => {
        const body = await response.body();
        assert(
          body.byteLength > 0 && body.byteLength <= 1024 * 1024,
          'Invalid bounded font content'
        );
        fontResources.push({
          url: response.url(),
          status: response.status(),
          contentType: response.headers()['content-type'] || '',
          magic: body.subarray(0, 4).toString('ascii'),
          sha256: createHash('sha256').update(body).digest('hex'),
        });
      })().catch(() => {
        fontFailures++;
      })
    );
  });
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });
  return {
    errors,
    requests,
    navigations,
    consoleMessages,
    fontResources,
    fontTasks,
    get fontFailures() {
      return fontFailures;
    },
    expectResourceFailure(url, status) {
      assert.equal(status, 503);
      assert.equal(url, page.url().split('#')[0]);
      expectedResourceFailures.push({ url, status, observed: false });
    },
  };
}

async function assertInitialFontResources(page, observed) {
  await waitForFonts(page);
  await Promise.all(observed.fontTasks);
  assert.equal(observed.fontFailures, 0, 'Public font response validation failed');
  const requests = observed.requests.filter((request) => request.type === 'font');
  const family = await page.evaluate(() => getComputedStyle(document.body).fontFamily);
  if (browserLocale() === 'en') {
    assert.equal(requests.length, 0, 'English downloaded an unnecessary Persian font');
    assert.equal(observed.fontResources.length, 0);
    assert(!/persianfont/i.test(family), 'English did not retain system typography');
    return;
  }
  assert(requests.length > 0, 'Persian did not request its local font');
  assert.equal(
    observed.fontResources.length,
    requests.length,
    'A font request had no validated response'
  );
  assert(/persianfont/i.test(family), 'Persian did not apply its local font family');
  const provenance = JSON.parse(
    await readFile(new URL('../../apps/web/app/fonts/provenance.json', import.meta.url), 'utf8')
  );
  for (const font of observed.fontResources) {
    const url = new URL(font.url);
    assert.equal(
      url.origin,
      new URL(page.url()).origin,
      'Font request left the application origin'
    );
    assert(!url.search && !url.hash, 'Generated font URL included unexpected parameters');
    assert.match(
      decodeURIComponent(url.pathname),
      /^\/_next\/static\/media\/(?=[^/]*[a-f0-9]{8})[^/]+\.woff2$/i,
      'Font URL was not a fingerprinted same-origin static WOFF2'
    );
    assert.equal(font.status, 200);
    assert.match(font.contentType, /^font\/woff2(?:;|$)/i);
    assert.equal(font.magic, 'wOF2');
    assert.equal(
      font.sha256,
      provenance.fontSha256,
      'Image font differs from the pinned unmodified release'
    );
  }
}

export function assertSafeRequests(observed, baseURL, documentPaths, secrets) {
  for (const request of observed.requests) {
    const url = new URL(request.url);
    assert.equal(url.origin, new URL(baseURL).origin, 'No third-party auth or telemetry requests');
    if (request.method === 'POST' && request.headers['next-action']) {
      assert(documentPaths.has(url.pathname), 'Preference action left a rendered page');
      preferenceActionInput(request, request.url);
      continue;
    }
    assert(
      ['GET', 'HEAD'].includes(request.method),
      `Unexpected ${request.method} ${url.pathname}`
    );
    assert.equal(request.body, null, 'Public auth navigation must not carry a body');
    assert(
      documentPaths.has(url.pathname) ||
        url.pathname.startsWith('/_next/static/') ||
        url.pathname === '/favicon.ico',
      `Unexpected application request: ${url.pathname}`
    );
    if (['fetch', 'xhr'].includes(request.type)) {
      assert(documentPaths.has(url.pathname), 'Only Next document navigation/prefetch may fetch');
      assert.equal(request.headers.rsc, '1', 'No authentication fetch/XHR without an explicit action');
      assert(
        [...url.searchParams.keys()].every((key) => key === '_rsc'),
        'RSC requests must not forward form values in query parameters'
      );
    }
  }
  const serialized = JSON.stringify([
    observed.requests,
    observed.navigations,
    observed.consoleMessages,
  ]);
  for (const secret of secrets) {
    for (const encoded of [
      secret,
      encodeURIComponent(secret),
      new URLSearchParams({ v: secret }).toString().slice(2),
    ]) {
      assert(
        !serialized.includes(encoded),
        'A request, URL or console message exposed a synthetic credential'
      );
    }
  }
}

export async function assertUnavailable(page, route, noScript = false) {
  if (route.passkey) {
    const action = page.getByTestId('passkey-login');
    await action.waitFor({ state: 'visible' });
    assert.equal(await page.getByRole('button', { name: localizedText(route.submit), exact: true }).count(), 1);
    assert.equal(await action.getAttribute('type'), 'button');
    if (noScript) {
      assert(await action.isDisabled(), 'Passkey action stays disabled without JavaScript');
    } else {
      await page.waitForFunction(
        () => !document.querySelector('[data-testid="passkey-login"]')?.disabled
      );
    }
    assert.equal(
      await page.getByRole('form').count(),
      0,
      'Passkey action has no native submission'
    );
    assert.equal(await page.getByRole('main').locator('form, input, textarea').count(), 0,
      'Public sign-in must not expose disconnected credential fields');
    assert.equal(await page.getByRole('main').locator('a[href="/forgot-password"]').count(), 0,
      'Public sign-in must not offer unsupported password recovery');
    assert.equal(await page.getByRole('main').getByRole('alert').count(), 0,
      'Passive passkey entry must not claim an authentication outcome');
    assert.equal((await page.getByRole('main').getByRole('status').textContent()).trim(), '',
      'Passive passkey entry must not claim progress or success');
    return;
  }
  if (route.registration) {
    const form = page.getByRole('form', { name: localizedText('Create an account'), exact: true });
    assert.equal(await form.getAttribute('method'), 'post');
    assert.equal(
      await form.getAttribute('action'),
      null,
      'Registration has no native credential endpoint'
    );
    const submit = form.getByRole('button', { name: localizedText(route.submit), exact: true });
    const mailbox = form.getByLabel(localizedText('Email address'), { exact: true });
    assert.equal(
      await mailbox.getAttribute('type'),
      'text',
      'Unicode mailbox entry must not use ASCII-only native validity'
    );
    assert.equal(await mailbox.getAttribute('inputmode'), 'email');
    assert.equal(
      await form.locator('input[type=password]').count(),
      0,
      'Signup creates a passkey, not a password'
    );
    if (noScript) {
      assert(await submit.isDisabled(), 'Registration remains inert without JavaScript');
      for (const field of route.fields)
        assert(await form.getByLabel(localizedText(field.label), { exact: true }).isDisabled());
    } else {
      await page.waitForFunction(
        () =>
          !document.querySelector('[data-registration-form] button[type=submit]')
            ?.disabled
      );
    }
    assert.equal(
      (await page.getByRole('main').getByRole('status').textContent()).trim(),
      '',
      'No signup progress without an explicit action'
    );
    assert.equal(await page.getByRole('main').getByRole('alert').count(), 0);
    return;
  }
  assert(route.availability, 'Every public auth route requires an explicit supported state');
  const main = page.getByRole('main');
  await main.getByText(localizedText(availabilityNotice), { exact: true }).waitFor({ state: 'visible' });
  assert.equal(await main.locator('form, input, textarea, button').count(), 0,
    `${route.path}: availability notice must not expose a disconnected form`);
  assert.equal(await main.getByRole('status').count(), 0, 'No simulated authentication progress/success');
  assert.equal(await main.getByRole('alert').count(), 0, 'No simulated authentication failure');
  for (const [name, path] of [['Continue with a passkey', '/login'], ['Create an account', '/register']]) {
    const link = main.getByRole('link', { name: localizedText(name), exact: true });
    await link.waitFor({ state: 'visible' });
    assert.equal(await link.getAttribute('href'), path, 'Availability notice requires a supported next action');
  }
}

// Runs in Chromium: measured colors include translucent card/notice/footer backgrounds.
// These checks complement, rather than claim to replace, visual and assistive-technology review.
export function authAppearanceCounts(failures) {
  const counts = { total: failures.length, horizontal: 0, inlineStyle: 0, geometry: 0, targets: 0, contrast: 0, focus: 0, other: 0 };
  for (const failure of failures) {
    const category = failure === 'Horizontal document scrolling' ? 'horizontal'
      : failure === 'Application inline style attribute' ? 'inlineStyle'
      : typeof failure !== 'string' ? 'other'
      : /focus-visible|keyboard focus indicator/.test(failure) ? 'focus'
      : /outside the document|clipped by/.test(failure) ? 'geometry'
      : /touch area/.test(failure) ? 'targets'
      : /:1, need/.test(failure) ? 'contrast' : 'other';
    counts[category] += 1;
  }
  return counts;
}

function auditAuthAppearance({ focusedOnly = false } = {}) {
  const failures = [];
  const describe = (element) =>
    element.getAttribute('aria-label') ||
    element.labels?.[0]?.textContent ||
    element.textContent.trim().slice(0, 70) ||
    element.tagName;
  const color = (value) => {
    const match = value.match(/^rgba?\(([^)]+)\)$/);
    if (!match) throw new Error(`Unsupported computed color: ${value}`);
    const channels = match[1].split(/[,\s/]+/).map(Number);
    return [...channels.slice(0, 3), channels[3] ?? 1];
  };
  const composite = (foreground, background) =>
    foreground
      .slice(0, 3)
      .map((channel, i) => channel * foreground[3] + background[i] * (1 - foreground[3]));
  const background = (element) =>
    element
      ? composite(
          color(getComputedStyle(element).backgroundColor),
          background(element.parentElement)
        )
      : [255, 255, 255];
  const luminance = (rgb) =>
    rgb.slice(0, 3).reduce((sum, value, index) => {
      const channel = value / 255;
      return (
        sum +
        (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4) *
          [0.2126, 0.7152, 0.0722][index]
      );
    }, 0);
  const ratio = (foreground, backdrop) => {
    const a = luminance(composite(foreground, backdrop));
    const b = luminance(backdrop);
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  };
  const contrast = (foreground, backdrop, minimum, label) => {
    const measured = ratio(color(foreground), backdrop);
    if (measured < minimum) failures.push(`${label}: ${measured.toFixed(2)}:1, need ${minimum}:1`);
  };
  const geometry = (element, rect, viewport = false) => {
    const label = describe(element);
    if (rect.left < -1 || rect.right > innerWidth + 1 || rect.top + scrollY < -1) {
      failures.push(`${label}: outside the document's usable width/top`);
    }
    if (viewport && (rect.top < -1 || rect.bottom > innerHeight + 1)) {
      failures.push(`${label}: action/focus is clipped by the viewport`);
    }
    for (let ancestor = element.parentElement; ancestor; ancestor = ancestor.parentElement) {
      const style = getComputedStyle(ancestor);
      const bounds = ancestor.getBoundingClientRect();
      if (
        (/(hidden|clip|auto|scroll)/.test(style.overflowX) &&
          (rect.left < bounds.left - 1 || rect.right > bounds.right + 1)) ||
        (/(hidden|clip)/.test(style.overflowY) &&
          (rect.top < bounds.top - 1 || rect.bottom > bounds.bottom + 1))
      )
        failures.push(`${label}: clipped by ${ancestor.tagName}`);
    }
  };

  if (focusedOnly) {
    const element = document.activeElement;
    const style = getComputedStyle(element);
    const backdrop = background(element.parentElement);
    if (!element.matches(':focus-visible'))
      failures.push(`${describe(element)}: not focus-visible`);
    geometry(element, element.getBoundingClientRect(), true);
    const forcedColors = matchMedia('(forced-colors: active)').matches;
    const ring = !forcedColors && [...style.boxShadow.matchAll(/(rgba?\([^)]+\)) 0px 0px 0px ([\d.]+)px/g)].some(
      (match) => Number(match[2]) >= 2 && ratio(color(match[1]), backdrop) >= 3
    );
    const outline = !['none', 'hidden'].includes(style.outlineStyle) && Number.parseFloat(style.outlineWidth) >= 2 &&
      ratio(color(style.outlineColor), backdrop) >= 3;
    if (!ring && !outline) failures.push(`${describe(element)}: missing a 3:1, 2px keyboard focus indicator`);
    return failures;
  }

  if (document.documentElement.scrollWidth > document.documentElement.clientWidth + 1) {
    failures.push('Horizontal document scrolling');
  }
  // Next owns a CSSOM-styled announcer host outside the application. SSR is checked without exceptions.
  if (document.querySelector('[style]:not(next-route-announcer)')) {
    failures.push('Application inline style attribute');
  }
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const element = node.parentElement;
    if (
      !node.textContent.trim() ||
      !element ||
      element.closest('script, style, noscript, option, [aria-hidden="true"], :disabled') ||
      !element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })
    )
      continue;
    const style = getComputedStyle(element);
    const size = Number.parseFloat(style.fontSize);
    const large = size >= 24 || (size >= 18.66 && Number.parseInt(style.fontWeight, 10) >= 700);
    contrast(
      style.color,
      background(element),
      large ? 3 : 4.5,
      `Text ${node.textContent.trim().slice(0, 60)}`
    );
    const range = document.createRange();
    range.selectNodeContents(node);
    for (const rect of range.getClientRects()) geometry(element, rect);
  }
  for (const element of document.querySelectorAll(
    'header a, main a, main button, main input, main select, main textarea, [data-ui-preferences] button, [data-ui-preferences] select, [data-ui-preferences] summary'
  )) {
    if (!element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    geometry(element, rect);
    if (rect.width < 44 || rect.height < 44)
      failures.push(`${describe(element)}: touch area ${rect.width}x${rect.height}, need 44x44`);
    if (
      element instanceof HTMLInputElement ||
      element instanceof HTMLSelectElement ||
      element instanceof HTMLTextAreaElement
    ) {
      if (
        element instanceof HTMLInputElement &&
        innerWidth < 768 &&
        Number.parseFloat(style.fontSize) < 16
      )
        failures.push(`${describe(element)}: mobile input text below 16px`);
      if (Number.parseFloat(style.borderTopWidth) < 1)
        failures.push(`${describe(element)}: missing field boundary`);
      contrast(style.color, background(element), 4.5, `${describe(element)} input text`);
      contrast(style.borderTopColor, background(element), 3, `${describe(element)} field boundary`);
      contrast(
        style.borderTopColor,
        background(element.parentElement),
        3,
        `${describe(element)} outer field boundary`
      );
    }
  }
  return failures;
}

async function assertKeyboardTraversal(page, label) {
  await page.bringToFront();
  const candidates = page.locator(
    'a[href], button, input, select, textarea, summary, [tabindex], [contenteditable="true"]'
  );
  const stops = await candidates.evaluateAll((elements) =>
    elements.flatMap((element, index) => {
      if (
        element.tabIndex < 0 ||
        element.matches(':disabled, input[type="hidden"]') ||
        element.closest('[hidden], [inert]') ||
        !element.getClientRects().length ||
        // Closed native details may retain layout rects after being opened.
        // Chromium skips those descendants in the sequential focus order.
        !element.checkVisibility({ checkVisibilityCSS: true }) ||
        getComputedStyle(element).visibility === 'hidden'
      )
        return [];
      return [index];
    })
  );
  assert(stops.length >= 2, `${label}: expected home and return/navigation links`);
  const first = candidates.nth(stops[0]);
  const home = localizedText('Hatef Identity home');
  const homeLabel = await first.getAttribute('aria-label');
  assert(home instanceof RegExp ? home.test(homeLabel) : homeLabel === home);
  await first.focus();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Shift+Tab');
  for (let i = 0; i < stops.length; i++) {
    if (i) await page.keyboard.press('Tab');
    const target = candidates.nth(stops[i]);
    const reachable = await target.evaluate(
      (element) =>
        element === document.activeElement &&
        element.tabIndex === 0 &&
        !element.closest('[aria-hidden="true"]') &&
        element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })
    );
    if (!reachable) {
      const controls = await target.evaluate((element) => ({
        expected: {
          tag: element.tagName,
          tabIndex: element.tabIndex,
          visible: element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }),
          detailsOpen: element.closest('details')?.open ?? null,
        },
        active: {
          tag: document.activeElement?.tagName,
          tabIndex: document.activeElement?.tabIndex,
        },
      }));
      console.error(
        JSON.stringify({ check: 'keyboard-target', context: label, index: i, controls })
      );
    }
    assert(reachable, `${label}: skipped, hidden or out-of-order tab stop ${i}`);
    assert.deepEqual(
      await page.evaluate(auditAuthAppearance, { focusedOnly: true }),
      [],
      `${label}: keyboard focus`
    );
  }
  // Leaving either edge must reach browser chrome/the other edge, never a hidden trap.
  for (const [key, edge] of [
    ['Tab', first],
    ['Shift+Tab', candidates.nth(stops.at(-1))],
  ]) {
    await page.keyboard.press(key);
    const atExpectedEdge = await edge.evaluate((element) => element === document.activeElement);
    if (!atExpectedEdge && await page.evaluate(() => document.activeElement === document.body || !document.hasFocus()))
      await page.keyboard.press(key);
    if (await edge.evaluate((element) => element === document.activeElement && !document.hasFocus())) await page.bringToFront();
    const reachedEdge = await edge.evaluate((element) => element === document.activeElement && document.hasFocus());
    if (!reachedEdge) {
      const state = await edge.evaluate((element) => ({ expectedTag: element.tagName, activeTag: document.activeElement?.tagName, activeTabIndex: document.activeElement?.tabIndex, documentFocused: document.hasFocus(), expectedActive: element === document.activeElement }));
      console.error(JSON.stringify({ check: 'keyboard-edge', context: label, key, state }));
    }
    assert(
      reachedEdge,
      `${label}: cannot leave keyboard traversal edge`
    );
  }
  for (let i = stops.length - 2; i >= 0; i--) {
    await page.keyboard.press('Shift+Tab');
    assert(
      await candidates.nth(stops[i]).evaluate((element) => element === document.activeElement),
      `${label}: reverse traversal skipped/trapped at ${i}`
    );
  }
}

async function checkAuthViewports(page, route) {
  const originalTheme = await page.locator('html').getAttribute('data-theme');
  for (const dark of [false, true]) {
    await setBrowserTheme(page, dark ? 'dark' : 'light');
    await waitForExternalCss(page, dark);
    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      await page.evaluate(() => scrollTo(0, 0));
      const label = `${route.path} ${dark ? 'dark' : 'light'} ${viewport.width}x${viewport.height}`;
      await waitForFonts(page);
      assert.deepEqual(await page.evaluate(auditAuthAppearance), [], label);
      await assertKeyboardTraversal(page, label);
      if (process.env.WEB_BROWSER_ARTIFACT_DIR) {
        const directory = resolve(process.env.WEB_BROWSER_ARTIFACT_DIR);
        await mkdir(directory, { recursive: true });
        const state = route.path.slice(1).replaceAll('/', '-') || 'home';
        await page.screenshot({
          path: resolve(directory, screenshotName(state, viewport, dark)),
          fullPage: true,
          // Carets are already hidden by these structural masks. Playwright's
          // default caret hiding mutates input.style and leaves empty attributes.
          caret: 'initial',
          animations: 'disabled',
          mask: [page.locator('input, textarea, [data-legal-private]')],
        });
      }
      const action = route.availability
        ? page.getByRole('link', { name: localizedText(route.back), exact: true })
        : page.getByRole('button', { name: localizedText(route.submit), exact: true });
      await action.scrollIntoViewIfNeeded();
      await action.evaluate((element) => element.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' }));
      const bounds = await action.evaluate((element) => {
        const rect = element.getBoundingClientRect();
        return { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right, width: rect.width, height: rect.height, viewportWidth: innerWidth, viewportHeight: innerHeight };
      });
      const reachable = bounds.top >= 0 && bounds.bottom <= bounds.viewportHeight && bounds.left >= 0 && bounds.right <= bounds.viewportWidth;
      if (!reachable) console.log(JSON.stringify({ check: 'auth-action-geometry-failure', locale: browserLocale(), route: route.path, viewport, bounds }));
      assert(
        reachable,
        `${label}: supported action must remain scroll-reachable`
      );
    }
  }
  await withTextResize(page, async () => {
    for (const viewport of [{ width: 320, height: 568 }, { width: 1280, height: 800 }]) {
      await page.setViewportSize(viewport);
      const failures = await page.evaluate(auditAuthAppearance);
      if (failures.length) console.log(JSON.stringify({ check: 'auth-text-resize-failure', locale: browserLocale(), route: route.path, viewport, counts: authAppearanceCounts(failures) }));
      assert.deepEqual(failures, [], `${route.path}: 200% root-font text resize`);
      await assertKeyboardTraversal(page, `${route.path}: 200% text resize`);
    }
  });
  await page.emulateMedia({ forcedColors: 'active' });
  try {
    await page.setViewportSize({ width: 390, height: 844 });
    await waitForFonts(page);
    assert.deepEqual(await page.evaluate(auditAuthAppearance), [], `${route.path}: forced colors`);
    await assertKeyboardTraversal(page, `${route.path}: forced colors`);
  } finally { await page.emulateMedia({ forcedColors: 'none' }); }
  await setBrowserTheme(page, originalTheme);
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function checkExpandedDisplaySettings(page, route) {
  const originalTheme = await page.locator('html').getAttribute('data-theme');
  const summary = page.locator('[data-ui-preferences] summary');
  const details = page.locator('[data-ui-preferences] details');
  if (!(await details.evaluate((node) => node.open))) await summary.click();
  try {
    for (const dark of [false, true]) {
      await setBrowserTheme(page, dark ? 'dark' : 'light');
      await waitForExternalCss(page, dark);
      for (const viewport of [
        { width: 320, height: 568 },
        { width: 320, height: 256 },
      ]) {
        await page.setViewportSize(viewport);
        await waitForFonts(page);
        const label = `${route.path} expanded display preferences ${browserLocale()} ${dark ? 'dark' : 'light'} ${viewport.width}x${viewport.height}`;
        const failures = await page.evaluate(auditAuthAppearance);
        if (failures.length) {
          const categories = {};
          for (const failure of failures) {
            const category = /outside the document/.test(failure)
              ? 'document-bounds'
              : /clipped by the viewport/.test(failure)
                ? 'viewport-focus-bounds'
                : /clipped by/.test(failure)
                  ? 'ancestor-clipping'
                  : /touch area/.test(failure)
                    ? 'touch-target'
                    : /Horizontal document/.test(failure)
                      ? 'document-overflow'
                      : /need [0-9.]+:1/.test(failure)
                        ? 'contrast'
                        : /mobile input/.test(failure)
                          ? 'mobile-font'
                          : /focus/.test(failure)
                            ? 'focus'
                            : /Application inline style/.test(failure)
                              ? 'inline-style'
                              : 'other';
            categories[category] = (categories[category] || 0) + 1;
          }
          const geometry = await page.evaluate(() => ({
            viewport: {
              width: innerWidth,
              height: innerHeight,
              scrollX,
              scrollY,
              scrollWidth: document.documentElement.scrollWidth,
            },
            controls: [
              ...document.querySelectorAll(
                '[data-ui-preferences] summary, [data-ui-preferences] select, [data-ui-preferences] button, main input'
              ),
            ].map((element, index) => {
              const rect = element.getBoundingClientRect();
              return {
                index,
                tag: element.tagName,
                visible: element.checkVisibility(),
                x: Math.round(rect.x),
                y: Math.round(rect.y),
                width: Math.round(rect.width),
                height: Math.round(rect.height),
              };
            }),
            inlineStyles: [...document.querySelectorAll('[style]:not(next-route-announcer)')].map(
              (element) => ({
                tag: element.tagName,
                properties: Array.from(element.style),
                length: element.getAttribute('style').length,
              })
            ),
          }));
          console.error(
            JSON.stringify({
              check: 'expanded-display-settings',
              locale: browserLocale(),
              dark,
              viewport,
              categories,
              geometry,
            })
          );
        }
        assert.deepEqual(failures, [], label);
        await assertKeyboardTraversal(page, label);
        for (const name of ['Appearance', 'Calendar', 'Time zone']) {
          const control = page.getByRole('combobox', { name: localizedText(name), exact: true });
          assert(await control.isVisible(), 'Expanded display control is hidden');
          assert.equal(await control.inputValue(), name === 'Appearance' ? dark ? 'dark' : 'light' : name === 'Calendar' ? 'auto' : 'UTC');
        }
        assert.equal(
          await page
            .getByRole('button', { name: localizedText('Use device time zone'), exact: true })
            .getAttribute('type'),
          'button'
        );
        if (process.env.WEB_BROWSER_ARTIFACT_DIR) {
          const directory = resolve(process.env.WEB_BROWSER_ARTIFACT_DIR);
          await mkdir(directory, { recursive: true });
          await page.screenshot({
            path: resolve(directory, screenshotName('login-display-settings', viewport, dark)),
            fullPage: true,
            caret: 'initial',
            animations: 'disabled',
            mask: [page.locator('input, textarea, [data-legal-private]')],
          });
        }
      }
    }
  } finally {
    if (await details.evaluate((node) => node.open)) await summary.click();
    await setBrowserTheme(page, originalTheme);
    await page.setViewportSize({ width: 1280, height: 800 });
  }
}

export async function storageSnapshot(page, timeout = 15000) {
  assert(Number.isInteger(timeout) && timeout > 0 && timeout <= 30000);
  let timer;
  try {
    return await Promise.race([
      (async () => ({
        persistent: await page.context().storageState({ indexedDB: true }),
        session: await page.evaluate(() => Object.entries(sessionStorage).sort()),
      }))(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('CSP storage snapshot timed out')), timeout); }),
    ]);
  } finally { clearTimeout(timer); }
}

export function assertPublicStorageUnchanged(before, after) {
  const normalize = (snapshot) => {
    assertOnlyPreferenceCookies(snapshot.persistent.cookies);
    return { ...snapshot, persistent: { ...snapshot.persistent,
      cookies: snapshot.persistent.cookies.map((cookie) => ({ ...cookie, expires: 0 })) } };
  };
  // Explicit appearance saves renew only the public preference-cookie lifetime.
  // Every cookie attribute/value, database record and session-storage value stays exact.
  assert.deepEqual(normalize(after), normalize(before), 'Appearance changed public auth storage beyond its preference-cookie lifetime');
}
async function assertInertInteraction(page, route, observed, beforeStorage, noScript = false) {
  await waitForFonts(page, { animationFrames: !noScript });
  const actionRequests = () => observed.requests.filter((request) =>
    !['GET', 'HEAD'].includes(request.method) || new URL(request.url).pathname.startsWith('/api/')).length;
  const marker = randomUUID();
  const before = {
    url: page.url(),
    navigations: observed.navigations.length,
    marker,
    storage: beforeStorage,
    actionRequests: actionRequests(),
  };
  await page.evaluate((marker) => {
    document.__authDocumentMarker = marker;
  }, marker);
  for (const field of route.fields)
    await page.getByLabel(localizedText(field.label), { exact: true }).press('Enter');
  if (!route.availability) {
    const submit = page.getByRole('button', { name: localizedText(route.submit), exact: true });
    assert(await submit.isDisabled());
    await submit.scrollIntoViewIfNeeded();
    const bounds = await submit.boundingBox();
    assert(bounds);
    // A physical click tests the disabled control without enabled-state retry/force.
    await page.mouse.click(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
  }
  await page.evaluate(
    () => document.activeElement instanceof HTMLElement && document.activeElement.blur()
  );
  await page.keyboard.press('Enter');
  // Bounded negative observation, not a simulated authentication delay or mocked response.
  await page.waitForTimeout(250);
  assert.deepEqual(
    {
      url: page.url(),
      navigations: observed.navigations.length,
      marker: await page.evaluate(() => document.__authDocumentMarker),
      storage: await storageSnapshot(page),
      actionRequests: actionRequests(),
    },
    before,
    `${route.path}: passive Enter/disabled click must not request, navigate, replace the document or persist credentials`
  );
  await assertUnavailable(page, route, noScript);
}

export async function validateWebCsp({
  baseURL,
  notFoundPaths = [`/__csp-browser-${randomUUID()}`, `/__csp-browser-${randomUUID()}.html`],
}) {
  const ingress = await localHTTPSProxy(baseURL);
  baseURL = ingress.origin;
  let browser;
  try {
    browser = await chromium.launch({
      channel: 'chromium',
      args: [`--ignore-certificate-errors-spki-list=${ingress.tlsSPKI}`],
    });
    const context = await browser.newContext({
      bypassCSP: false,
      serviceWorkers: 'block',
      locale: 'fa-IR',
      colorScheme: 'light',
    });
    await configureBrowserPreferences(context, new URL(baseURL).origin);
    context.setDefaultTimeout(15_000);
    context.setDefaultNavigationTimeout(30_000);
    // Init/evaluate scripts only observe the page; executable attack probes come from parsed HTML.
    await context.addInitScript(() => {
      globalThis.__cspViolations = [];
      globalThis.__authObservations = {
        credentialCalls: [],
        submissions: 0,
      };
      document.addEventListener('securitypolicyviolation', (event) => {
        globalThis.__cspViolations.push({
          directive: event.effectiveDirective,
          blockedURI: event.blockedURI,
          disposition: event.disposition,
          policy: event.originalPolicy,
        });
      });
      // Transparent call-through observers: no auth implementation, result, or request is mocked.
      for (const method of ['get', 'create', 'store', 'preventSilentAccess']) {
        const prototype = globalThis.CredentialsContainer?.prototype;
        const original = prototype?.[method];
        if (original)
          prototype[method] = function (...args) {
            globalThis.__authObservations.credentialCalls.push(method);
            return Reflect.apply(original, this, args);
          };
      }
      document.addEventListener(
        'submit',
        () => {
          globalThis.__authObservations.submissions++;
        },
        true
      );
    });

    const page = await context.newPage();
    const expected404s = new Set(notFoundPaths.map((path) => new URL(path, baseURL).href));
    const observed = observePage(page, expected404s);
    const documentPaths = new Set([
      '/',
      ...notFoundPaths,
      ...authRoutes.map((route) => route.path),
    ]);
    await checkPublicAppearance(browser, baseURL, documentPaths);
    const canary = `browser-only-${randomUUID()}`;
    const values = {
      email: `${canary}@example.test`,
      phone: '+989123456789',
    };
    const secrets = Object.values(values);
    const seenNonces = new Set();
    let expectedSubmissions = 0;
    const assertCleanBaseline = async () => {
      assert.deepEqual(
        await page.evaluate(() => globalThis.__cspViolations),
        [],
        'Normal-page CSP violations'
      );
      assert.deepEqual(observed.errors, [], 'Normal-page runtime, hydration or console errors');
      const auth = await page.evaluate(() => globalThis.__authObservations);
      assert.deepEqual(
        auth.credentialCalls,
        [],
        'No navigator.credentials calls during load/navigation'
      );
      assert.equal(
        auth.submissions,
        expectedSubmissions,
        'No unexpected form submission during load/navigation'
      );
      assertSafeRequests(observed, baseURL, documentPaths, secrets);
    };
    const visit = async (path, status, heading) => {
      expectedSubmissions = 0;
      const response = await page.goto(new URL(path, baseURL).href, { waitUntil: 'load' });
      assert(response, `${path} has no document response`);
      assert.equal(response.status(), status, `${path} browser HTTP status`);
      const html = await response.text();
      assert.match(
        html,
        new RegExp(`<html\\b[^>]*lang="${browserLocale()}"`),
        'Initial production HTML locale'
      );
      assert.match(
        html,
        new RegExp(`<html\\b[^>]*dir="${browserLocale() === 'fa-IR' ? 'rtl' : 'ltr'}"`),
        'Initial production HTML direction'
      );
      webDocumentNonce(new Headers(await response.allHeaders()), html, seenNonces);
      await page
        .getByRole('heading', { name: localizedText(heading), level: 1, exact: true })
        .waitFor({ state: 'visible' });
      await waitForExternalCss(page);
      await assertCleanBaseline();
    };
    const navigate = async (name, path) => {
      const link = page.getByRole('link', { name: localizedText(name), exact: true });
      assert.equal(await link.getAttribute('href'), path, `Real ${name} link destination`);
      await waitForReactHandler(link, 'onClick');
      const marker = randomUUID();
      await page.evaluate((value) => {
        document.__cspNavigationMarker = value;
      }, marker);
      console.log(JSON.stringify({ check: 'auth-navigation', locale: browserLocale(), route: path, stage: 'click' }));
      await Promise.all([page.waitForURL(new URL(path, baseURL).href), link.click()]);
      const route = authRoutes.find((route) => route.path === path);
      await page
        .getByRole('heading', {
          name: localizedText(route?.heading || 'Hatef Identity Platform'),
          level: 1,
          exact: true,
        })
        .waitFor({ state: 'visible' });
      assert.equal(
        await page.evaluate(() => document.__cspNavigationMarker),
        marker,
        `${name} must navigate without replacing the document`
      );
      console.log(JSON.stringify({ check: 'auth-navigation', locale: browserLocale(), route: path, stage: 'loaded' }));
      await waitForExternalCss(page);
      console.log(JSON.stringify({ check: 'auth-navigation', locale: browserLocale(), route: path, stage: 'css-ready' }));
      if (route) await assertUnavailable(page, route);
      await assertCleanBaseline();
    };

    await visit('/', 200, 'Hatef Identity Platform');
    assert.equal(await page.locator('html').getAttribute('lang'), browserLocale());
    await assertInitialFontResources(page, observed);
    await exercisePreferenceSwitch(page, { settings: true });
    await assertCleanBaseline();
    assert.equal(
      await page
        .getByRole('heading', { name: localizedText('Hatef Identity Platform'), exact: true })
        .evaluate((heading) => getComputedStyle(heading).fontSize),
      '36px',
      'Homepage Tailwind typography must be applied'
    );
    for (const path of notFoundPaths) {
      await visit(path, 404, 'Page not found');
      await navigate('Return home', '/');
    }

    // Public login is passkey-only. Unavailable URLs remain notices with supported
    // actions; real authentication belongs to the separately gated API suite.
    await navigate('Sign in', '/login');
    await visit('/login/webauthn', 200, 'Sign in with a passkey');
    await navigate('Return to sign in', '/login');
    await navigate('Hatef Identity home', '/');
    await navigate('Create an account', '/register');
    await navigate('Hatef Identity home', '/');

    for (const route of authRoutes) {
      console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'visit' }));
      await visit(route.path, 200, route.heading);
      await assertUnavailable(page, route);
      if (!route.availability) await waitForReactHandler(
        route.passkey ? page.getByTestId('passkey-login') : page.getByRole('form'),
        route.passkey ? 'onClick' : 'onSubmit'
      );
      assert(
        await page.evaluate(() => document.activeElement === document.body),
        `${route.path}: no autofocus on direct load`
      );
      if (route.path === '/login') {
        await exercisePreferenceFailure(page, observed.expectResourceFailure);
        await assertUnavailable(page, route);
        await checkExpandedDisplaySettings(page, route);
      }

      // Measure untouched boundaries as well as the invalid fields used in the reflow matrix.
      const originalTheme = await page.locator('html').getAttribute('data-theme');
      for (const dark of [false, true]) {
        await setBrowserTheme(page, dark ? 'dark' : 'light');
        await waitForExternalCss(page, dark);
        const appearance = await page.evaluate(auditAuthAppearance);
        if (appearance.length) {
          const categories = appearance.map((failure) =>
            /inline style/.test(failure) ? 'inline-style' : /outside|clipped|scrolling/.test(failure) ? 'geometry'
              : /need [0-9.]+:1/.test(failure) ? 'contrast' : /touch area/.test(failure) ? 'target-size' : 'other');
          console.error(JSON.stringify({ check: 'untouched-auth-appearance', path: route.path, locale: browserLocale(), dark, categories }));
          if (process.env.WEB_BROWSER_ARTIFACT_DIR) await page.screenshot({
            path: resolve(process.env.WEB_BROWSER_ARTIFACT_DIR, `appearance-failure-${browserLocale()}.png`),
            fullPage: true, caret: 'initial', mask: [page.locator('input, textarea, [data-legal-private]')],
          });
        }
        assert.deepEqual(
          appearance,
          [],
          `${route.path}: untouched ${dark ? 'dark' : 'light'} palette`
        );
      }
      await setBrowserTheme(page, originalTheme);
      if (route.registration) {
        // Registration has its own baseline before invalid submissions; the
        // passive-entry baseline below is outside this branch's lifetime.
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'registration-baseline' }));
        const beforeStorage = await storageSnapshot(page);
        // Valid signup sends mail and belongs to the separately gated real-API
        // suite. Here only explicit invalid submissions may run: no API work,
        // credentials ceremony or durable browser state is permitted.
        const form = page.getByRole('form', { name: localizedText('Create an account'), exact: true });
        const submit = form.getByRole('button', { name: localizedText(route.submit), exact: true });
        for (const invalid of ['', 'not-an-identity']) {
          for (const field of route.fields)
            await form.getByLabel(localizedText(field.label), { exact: true }).fill(invalid);
          expectedSubmissions++;
          await submit.click();
          for (const field of route.fields)
            await form
              .getByLabel(localizedText(field.label), { exact: true })
              .and(page.locator('[aria-invalid="true"]'))
              .waitFor({ state: 'visible' });
          await assertCleanBaseline();
        }
        await checkAuthViewports(page, route);
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'registration-layouts' }));
        for (const field of route.fields)
          await form.getByLabel(localizedText(field.label), { exact: true }).fill(values[field.name]);
        assert(await submit.isEnabled(), 'Hydrated signup requires explicit contact submission');
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'registration-storage' }));
        assertPublicStorageUnchanged(beforeStorage, await storageSnapshot(page));
        await assertCleanBaseline();
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'registration-navigation' }));
        await navigate(route.back, route.backPath || '/login');
        await navigate('Hatef Identity home', '/');
        assertPublicStorageUnchanged(beforeStorage, await storageSnapshot(page));
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'registration-complete' }));
        continue;
      }
      await exercisePreferenceSwitch(page);
      await assertUnavailable(page, route);
      await assertCleanBaseline();
      // Preference actions precede the passive-entry storage baseline.
      await checkAuthViewports(page, route);
      const beforeStorage = await storageSnapshot(page);
      assert.equal(
        page.url(),
        new URL(route.path, baseURL).href,
        'Passive auth entry and appearance checks must not navigate'
      );
      if (!route.passkey) await assertInertInteraction(page, route, observed, beforeStorage);
      await assertCleanBaseline();
      await navigate(route.back, route.backPath || '/login');
      if (route.availability) {
        await visit(route.path, 200, route.heading);
        await navigate('Create an account', '/register');
      }
      await navigate('Hatef Identity home', '/');
      assert.deepEqual(
        await storageSnapshot(page),
        beforeStorage,
        'Passive auth navigation must not persist credentials or contacts'
      );
    }
    await assertCleanBaseline();
    await page.close();

    // Unmodified, JS-disabled documents prove the action is disabled in SSR, without React prevention.
    console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), stage: 'no-js' }));
    const noScriptContext = await browser.newContext({
      javaScriptEnabled: false,
      bypassCSP: false,
      serviceWorkers: 'block',
    });
    try {
      await noScriptContext.addCookies(await context.cookies(new URL(baseURL).origin));
      noScriptContext.setDefaultTimeout(15_000);
      noScriptContext.setDefaultNavigationTimeout(30_000);
      const noScript = await noScriptContext.newPage();
      const noScriptObserved = observePage(noScript);
      for (const route of authRoutes) {
        console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), route: route.path, stage: 'no-js-visit' }));
        const response = await noScript.goto(new URL(route.path, baseURL).href, {
          waitUntil: 'load',
        });
        assert(response);
        assert.equal(response.status(), 200);
        const html = await response.text();
        webDocumentNonce(new Headers(await response.allHeaders()), html, seenNonces);
        await waitForExternalCss(noScript);
        await noScript
          .getByRole('heading', { name: localizedText(route.heading), level: 1, exact: true })
          .waitFor({ state: 'visible' });
        await assertUnavailable(noScript, route, true);
        const beforeStorage = await storageSnapshot(noScript);
        await assertInertInteraction(
          noScript,
          route.registration ? { ...route, fields: [] } : route,
          noScriptObserved,
          beforeStorage,
          true
        );
        assertSafeRequests(noScriptObserved, baseURL, documentPaths, secrets);
        assert.deepEqual(noScriptObserved.errors, [], 'JavaScript-disabled runtime/CSP errors');
      }
    } finally {
      await noScriptContext.close();
    }

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
    let attackFailed = false;
    await attack.route(attackURL.href, async (route) => {
      try {
        const response = await fetchPinnedCspDocument(
          attackURL,
          ingress.certificate,
          await context.cookies(baseURL)
        );
        assert.equal(
          response.status,
          200,
          'Attack fixture must start from a real production document'
        );
        const html = response.body;
        const headers = new Headers(response.headers);
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
        const fixtureHeaders = { ...response.headers };
        for (const header of ['content-length', 'content-encoding', 'transfer-encoding'])
          delete fixtureHeaders[header];
        await route.fulfill({ status: response.status, headers: fixtureHeaders, body: fixture });
      } catch {
        attackFailed = true;
        await route.abort().catch(() => {});
      }
    });
    const attackResponse = await attack.goto(attackURL.href, { waitUntil: 'load' }).catch(() => {
      throw new Error('Public CSP fixture navigation failed');
    });
    assert(!attackFailed, 'Public CSP fixture interception failed');
    assert(attackResponse);
    assert.equal(attackResponse.status(), 200);
    assert.equal(
      await attackResponse.headerValue('content-security-policy'),
      fixturePolicy,
      'Preserve the real enforcing CSP'
    );
    await waitForExternalCss(attack);
    await attack
      .getByRole('button', { name: localizedText('CSP handler probe'), exact: true })
      .click();
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
  } catch (error) {
    console.error(browserFailure(error, 'csp-probe'));
    throw error;
  } finally {
    console.log(JSON.stringify({ check: 'auth-csp-progress', locale: browserLocale(), stage: 'closing' }));
    try {
      await browser?.close();
    } finally {
      await ingress.close();
    }
  }
  console.log(
    'Production browser CSP, localized auth availability notices, passive passkey entry, keyboard/contrast/reflow, no-JS safety and supported client navigation checks passed'
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  smokeImage('web', process.argv[2], async (options) => {
    for (const locale of browserLocales) {
      setBrowserLocale(locale);
      await validateWebCsp(options);
    }
  }).catch((error) => {
    console.error(browserFailure(error, 'csp'));
    process.exitCode = 1;
  });
}
