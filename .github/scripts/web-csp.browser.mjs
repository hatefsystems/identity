import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { smokeImage, webDocumentNonce } from './smoke-image.mjs';

const previewNotice = 'This form is not connected yet. Do not enter real credentials.';
const email = { name: 'email', label: 'Email address' };
const password = { name: 'password', label: 'New password' };
const confirmation = { name: 'confirmation', label: 'Confirm password' };
const authRoutes = [
  {
    path: '/login',
    heading: 'Sign in to Hatef',
    submit: 'Sign in with password',
    fields: [email, { ...password, label: 'Password' }],
    back: 'Create an account',
    backPath: '/register',
  },
  {
    path: '/register',
    heading: 'Create your account',
    submit: 'Create account',
    fields: [email, password, confirmation],
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
    heading: 'Verify your authenticator code',
    submit: 'Verify code',
    fields: [{ name: 'code', label: 'Authenticator code' }],
    back: 'Return to sign in',
  },
  {
    path: '/forgot-password',
    heading: 'Reset your password',
    submit: 'Send reset link',
    fields: [email],
    back: 'Return to sign in',
  },
  {
    path: '/reset-password',
    heading: 'Set a new password',
    submit: 'Reset password',
    fields: [password, confirmation],
    back: 'Return to sign in',
  },
];
const viewports = [
  { width: 320, height: 568 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1280, height: 800 },
  // Also exercises the CSS viewport available at 400% zoom on a 1280x1024 display.
  { width: 320, height: 256 },
];

async function waitForExternalCss(page, dark = false) {
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
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getTiming().iterations !== Infinity)
        .map((animation) => animation.finished.catch(() => {}))
    )
  );
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
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });
  return { errors, requests, navigations, consoleMessages };
}

function assertSafeRequests(observed, baseURL, documentPaths, secrets) {
  for (const request of observed.requests) {
    const url = new URL(request.url);
    assert.equal(url.origin, new URL(baseURL).origin, 'No third-party auth or telemetry requests');
    assert(
      ['GET', 'HEAD'].includes(request.method),
      `Unexpected ${request.method} ${url.pathname}`
    );
    assert.equal(request.body, null, 'Preview requests must not carry a body');
    assert(
      documentPaths.has(url.pathname) ||
        url.pathname.startsWith('/_next/static/') ||
        url.pathname === '/favicon.ico',
      `Unexpected application request: ${url.pathname}`
    );
    if (['fetch', 'xhr'].includes(request.type)) {
      assert(documentPaths.has(url.pathname), 'Only Next document navigation/prefetch may fetch');
      assert.equal(request.headers.rsc, '1', 'No authentication fetch/XHR in UI previews');
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

async function assertUnavailable(page, route, noScript = false) {
  if (route.passkey) {
    const action = page.getByTestId('passkey-login');
    await action.waitFor({ state: 'visible' });
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
    return;
  }
  const form = page.getByRole('form');
  await form.getByText('UI preview', { exact: true }).waitFor({ state: 'visible' });
  await form.getByText(previewNotice).waitFor({ state: 'visible' });
  assert.equal(await form.getAttribute('method'), 'post', `${route.path} keeps POST semantics`);
  assert.equal(await form.getAttribute('action'), null, `${route.path} has no action endpoint`);
  const submit = form.getByRole('button', { name: route.submit, exact: true });
  assert(await submit.isDisabled(), `${route.path} submit must remain natively disabled`);
  assert.equal(await submit.getAttribute('type'), 'submit');
  assert.equal(
    (await form.getByRole('status').textContent()).trim(),
    '',
    'No fake progress/success'
  );
  assert.equal(await form.getByRole('alert').count(), 0, 'No simulated authentication outcome');
}

async function assertFieldError(page, field, value = '') {
  const input = page.getByLabel(field.label, { exact: true });
  await input.fill(value);
  await input.press('Tab');
  await input.and(page.locator('[aria-invalid="true"]')).waitFor({ state: 'visible' });
  assert(
    await input.evaluate((element) => {
      const ids = (element.getAttribute('aria-describedby') || '').split(/\s+/);
      const error = document.getElementById(`${element.id}-error`);
      return (
        ids.includes(error?.id) &&
        error.checkVisibility() &&
        error.textContent.trim() &&
        ids.every((id) => document.getElementById(id)?.checkVisibility()) &&
        element !== document.activeElement
      );
    }),
    `${field.label}: blur error must be visibly associated without stealing focus`
  );
}

// Runs in Chromium: measured colors include translucent card/notice/footer backgrounds.
// These checks complement, rather than claim to replace, visual and assistive-technology review.
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
    const ring = [...style.boxShadow.matchAll(/(rgba?\([^)]+\)) 0px 0px 0px ([\d.]+)px/g)].some(
      (match) => Number(match[2]) >= 2 && ratio(color(match[1]), backdrop) >= 3
    );
    if (!ring) failures.push(`${describe(element)}: missing a 3:1, 2px keyboard focus indicator`);
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
      element.closest('script, style, noscript, [aria-hidden="true"], :disabled') ||
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
  for (const element of document.querySelectorAll('header a, main a, main button, main input')) {
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    geometry(element, rect);
    if (rect.width < 44 || rect.height < 44)
      failures.push(`${describe(element)}: touch area ${rect.width}x${rect.height}, need 44x44`);
    if (element instanceof HTMLInputElement) {
      if (innerWidth < 768 && Number.parseFloat(style.fontSize) < 16)
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
  const candidates = page.locator(
    'a[href], button, input, select, textarea, [tabindex], [contenteditable="true"]'
  );
  const stops = await candidates.evaluateAll((elements) =>
    elements.flatMap((element, index) => {
      if (
        element.tabIndex < 0 ||
        element.matches(':disabled, input[type="hidden"]') ||
        element.closest('[hidden], [inert]') ||
        !element.getClientRects().length ||
        getComputedStyle(element).visibility === 'hidden'
      )
        return [];
      return [index];
    })
  );
  assert(stops.length >= 2, `${label}: expected home and return/navigation links`);
  const first = candidates.nth(stops[0]);
  assert.equal(await first.getAttribute('aria-label'), 'Hatef Identity home');
  await first.focus();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Shift+Tab');
  for (let i = 0; i < stops.length; i++) {
    if (i) await page.keyboard.press('Tab');
    const target = candidates.nth(stops[i]);
    assert(
      await target.evaluate(
        (element) =>
          element === document.activeElement &&
          element.tabIndex === 0 &&
          !element.closest('[aria-hidden="true"]') &&
          element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })
      ),
      `${label}: skipped, hidden or out-of-order tab stop ${i}`
    );
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
    if (await page.evaluate(() => document.activeElement === document.body))
      await page.keyboard.press(key);
    assert(
      await edge.evaluate((element) => element === document.activeElement),
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
  for (const dark of [false, true]) {
    await page.evaluate((dark) => document.documentElement.classList.toggle('dark', dark), dark);
    await waitForExternalCss(page, dark);
    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      await page.evaluate(() => scrollTo(0, 0));
      const label = `${route.path} ${dark ? 'dark' : 'light'} ${viewport.width}x${viewport.height}`;
      assert.deepEqual(await page.evaluate(auditAuthAppearance), [], label);
      await assertKeyboardTraversal(page, label);
      const submit = page.getByRole('button', { name: route.submit, exact: true });
      await submit.scrollIntoViewIfNeeded();
      assert(
        await submit.evaluate((element) => {
          const rect = element.getBoundingClientRect();
          return (
            rect.top >= 0 &&
            rect.bottom <= innerHeight &&
            rect.left >= 0 &&
            rect.right <= innerWidth
          );
        }),
        `${label}: disabled action must remain scroll-reachable`
      );
    }
  }
  await page.evaluate(() => document.documentElement.classList.remove('dark'));
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function storageSnapshot(page) {
  return {
    persistent: await page.context().storageState({ indexedDB: true }),
    session: await page.evaluate(() => Object.entries(sessionStorage).sort()),
  };
}

async function assertInertInteraction(page, route, observed, beforeStorage, noScript = false) {
  const marker = randomUUID();
  const before = {
    url: page.url(),
    navigations: observed.navigations.length,
    marker,
    storage: beforeStorage,
  };
  await page.evaluate((marker) => {
    document.__authDocumentMarker = marker;
  }, marker);
  for (const field of route.fields)
    await page.getByLabel(field.label, { exact: true }).press('Enter');
  const submit = page.getByRole('button', { name: route.submit, exact: true });
  assert(await submit.isDisabled());
  await submit.scrollIntoViewIfNeeded();
  const bounds = await submit.boundingBox();
  assert(bounds);
  // A physical click tests the disabled control without Playwright's enabled-state retry/force.
  await page.mouse.click(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
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
    },
    before,
    `${route.path}: disabled Enter/click must not navigate, replace the document or persist credentials`
  );
  await assertUnavailable(page, route, noScript);
}

export async function validateWebCsp({
  baseURL,
  notFoundPaths = [`/__csp-browser-${randomUUID()}`, `/__csp-browser-${randomUUID()}.html`],
}) {
  const browser = await chromium.launch({ channel: 'chromium' });
  try {
    const context = await browser.newContext({ bypassCSP: false, serviceWorkers: 'block' });
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
    const canary = `browser-only-${randomUUID()}`;
    const values = {
      email: `${canary}@example.test`,
      password: ` ${canary} password `,
      confirmation: ` ${canary} password `,
      code: '012345',
    };
    const secrets = Object.values(values);
    const seenNonces = new Set();
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
      assert.equal(auth.submissions, 0, 'No preview submission during load/navigation');
      assertSafeRequests(observed, baseURL, documentPaths, secrets);
    };
    const visit = async (path, status, heading) => {
      const response = await page.goto(new URL(path, baseURL).href, { waitUntil: 'load' });
      assert(response, `${path} has no document response`);
      assert.equal(response.status(), status, `${path} browser HTTP status`);
      const html = await response.text();
      webDocumentNonce(new Headers(await response.allHeaders()), html, seenNonces);
      await page
        .getByRole('heading', { name: heading, level: 1, exact: true })
        .waitFor({ state: 'visible' });
      await waitForExternalCss(page);
      await assertCleanBaseline();
    };
    const navigate = async (name, path) => {
      const link = page.getByRole('link', { name, exact: true });
      assert.equal(await link.getAttribute('href'), path, `Real ${name} link destination`);
      await waitForReactHandler(link, 'onClick');
      const marker = randomUUID();
      await page.evaluate((value) => {
        document.__cspNavigationMarker = value;
      }, marker);
      await Promise.all([page.waitForURL(new URL(path, baseURL).href), link.click()]);
      const route = authRoutes.find((route) => route.path === path);
      await page
        .getByRole('heading', {
          name: route?.heading || 'Hatef Identity Platform',
          level: 1,
          exact: true,
        })
        .waitFor({ state: 'visible' });
      assert.equal(
        await page.evaluate(() => document.__cspNavigationMarker),
        marker,
        `${name} must navigate without replacing the document`
      );
      await waitForExternalCss(page);
      if (route) await assertUnavailable(page, route);
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
      await navigate('Return home', '/');
    }

    // Preserve both homepage CTAs and inactive password/reset navigation. Passkey
    // authentication is now an explicit button action, tested with the real API
    // in web-portal.browser.mjs, not against this standalone image-only fixture.
    await navigate('Sign in', '/login');
    await visit('/login/webauthn', 200, 'Sign in with a passkey');
    await navigate('Return to sign in', '/login');
    await navigate('Forgot password?', '/forgot-password');
    await navigate('Return to sign in', '/login');
    await navigate('Hatef Identity home', '/');
    await navigate('Create an account', '/register');
    await navigate('Hatef Identity home', '/');

    for (const route of authRoutes) {
      await visit(route.path, 200, route.heading);
      await assertUnavailable(page, route);
      await waitForReactHandler(
        route.passkey ? page.getByTestId('passkey-login') : page.getByRole('form'),
        route.passkey ? 'onClick' : 'onSubmit'
      );
      assert(
        await page.evaluate(() => document.activeElement === document.body),
        `${route.path}: no autofocus on direct load`
      );
      const beforeStorage = await storageSnapshot(page);

      // Measure untouched boundaries as well as the invalid fields used in the reflow matrix.
      for (const dark of [false, true]) {
        await page.evaluate(
          (dark) => document.documentElement.classList.toggle('dark', dark),
          dark
        );
        await waitForExternalCss(page, dark);
        assert.deepEqual(
          await page.evaluate(auditAuthAppearance),
          [],
          `${route.path}: untouched ${dark ? 'dark' : 'light'} palette`
        );
      }
      for (const field of route.fields) await assertFieldError(page, field);
      await checkAuthViewports(page, route);

      for (const field of route.fields) {
        const input = page.getByLabel(field.label, { exact: true });
        if (field.name === 'email') await assertFieldError(page, field, 'not-an-email');
        await input.fill(values[field.name]);
        if (['password', 'confirmation'].includes(field.name)) {
          const id = await input.getAttribute('id');
          const show = `Show ${field.label.toLowerCase()}`;
          const hide = `Hide ${field.label.toLowerCase()}`;
          await input.focus();
          await page.keyboard.press('Tab');
          const toggle = page.getByRole('button', { name: show, exact: true });
          assert(await toggle.evaluate((element) => element === document.activeElement));
          assert.equal(await toggle.getAttribute('type'), 'button');
          assert.equal(await toggle.getAttribute('aria-controls'), id);
          assert.equal(await toggle.getAttribute('aria-pressed'), 'false');
          await page.keyboard.press('Space');
          const revealed = page.getByRole('button', { name: hide, exact: true });
          await revealed.waitFor({ state: 'visible' });
          assert.equal(await input.getAttribute('type'), 'text');
          assert.equal(await revealed.getAttribute('aria-pressed'), 'true');
          assert(
            await revealed.evaluate((element) => element === document.activeElement),
            'Reveal must retain toggle focus'
          );
          assert.equal(
            await input.inputValue(),
            values[field.name],
            'Password reveal must preserve spaces/value'
          );
          await page.keyboard.press('Space');
          await toggle.waitFor({ state: 'visible' });
          assert.equal(await toggle.getAttribute('aria-pressed'), 'false');
          assert(
            await toggle.evaluate((element) => element === document.activeElement),
            'Hiding the password must retain toggle focus'
          );
          assert.equal(await input.getAttribute('type'), 'password');
          assert.equal(await input.getAttribute('id'), id);
          assert.equal(await input.inputValue(), values[field.name]);
        }
        if (field.name === 'confirmation') {
          await assertFieldError(page, field, `${canary}-mismatch`);
          await input.fill(values.confirmation);
        }
        if (field.name === 'code') {
          assert.equal(await input.getAttribute('type'), 'text');
          assert.equal(await input.getAttribute('inputmode'), 'numeric');
          assert.equal(await input.getAttribute('autocomplete'), 'one-time-code');
          await assertFieldError(page, field, '12345');
          await input.fill('');
          await context.grantPermissions(['clipboard-read', 'clipboard-write'], {
            origin: new URL(baseURL).origin,
          });
          try {
            await page.evaluate((code) => navigator.clipboard.writeText(code), values.code);
            await input.focus();
            await page.keyboard.press('Control+V');
            await page.waitForFunction(
              (code) =>
                document.querySelector('input[autocomplete="one-time-code"]')?.value === code,
              values.code
            );
            assert.equal(
              await input.inputValue(),
              '012345',
              'Native whole-code paste must preserve the leading zero'
            );
            assert(
              await input.evaluate((element) => element === document.activeElement),
              'Sixth digit must not submit or move focus'
            );
            assert.equal(
              await page.evaluate(() => globalThis.__authObservations.submissions),
              0,
              'No sixth-digit autosubmit'
            );
          } finally {
            await page.evaluate(() => navigator.clipboard.writeText(''));
            await context.clearPermissions();
          }
        }
        await input.press('Tab');
        await input.and(page.locator('[aria-invalid="false"]')).waitFor({ state: 'visible' });
        assert(
          await input.evaluate((element) => !document.getElementById(`${element.id}-error`)),
          'Resolved errors must be removed'
        );
      }
      assert.equal(
        page.url(),
        new URL(route.path, baseURL).href,
        'Typing, validation and paste must not navigate'
      );
      if (!route.passkey) await assertInertInteraction(page, route, observed, beforeStorage);
      await assertCleanBaseline();
      await navigate(route.back, route.backPath || '/login');
      await navigate('Hatef Identity home', '/');
      assert.deepEqual(
        await storageSnapshot(page),
        beforeStorage,
        'Navigating away must not persist form values'
      );
    }
    await assertCleanBaseline();
    await page.close();

    // Unmodified, JS-disabled documents prove the action is disabled in SSR, without React prevention.
    const noScriptContext = await browser.newContext({
      javaScriptEnabled: false,
      bypassCSP: false,
      serviceWorkers: 'block',
    });
    try {
      noScriptContext.setDefaultTimeout(15_000);
      noScriptContext.setDefaultNavigationTimeout(30_000);
      const noScript = await noScriptContext.newPage();
      const noScriptObserved = observePage(noScript);
      for (const route of authRoutes) {
        const response = await noScript.goto(new URL(route.path, baseURL).href, {
          waitUntil: 'load',
        });
        assert(response);
        assert.equal(response.status(), 200);
        const html = await response.text();
        webDocumentNonce(new Headers(await response.allHeaders()), html, seenNonces);
        await waitForExternalCss(noScript);
        await noScript
          .getByRole('heading', { name: route.heading, level: 1, exact: true })
          .waitFor({ state: 'visible' });
        await assertUnavailable(noScript, route, true);
        const beforeStorage = await storageSnapshot(noScript);
        for (const field of route.fields)
          await noScript.getByLabel(field.label, { exact: true }).fill(values[field.name]);
        await assertInertInteraction(noScript, route, noScriptObserved, beforeStorage, true);
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
    console.log(
      'Production browser CSP, inactive auth forms, passive passkey entry, keyboard/contrast/reflow, no-JS safety and client navigation checks passed'
    );
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
