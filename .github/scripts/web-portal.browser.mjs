import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { anonymousReclaim, browserFailure, portalRoute, startPortalHarness } from './portal-harness.mjs';

let checkpoint = 'startup';
import { webDocumentNonce } from './smoke-image.mjs';

const routes = ['/dashboard', '/dashboard/profile', '/dashboard/security', '/dashboard/sessions', '/dashboard/privacy', '/recover-account'];
const hash = (value) => createHash('sha256').update(value).digest('hex');

function observe(context, harness) {
  const state = {
    failures: [],
    pending: [],
    proofs: new Set(),
    keys: new Set(),
    nonceChallenges: 0,
    downloads: 0,
    anonymous: 0,
  };
  context.on('page', (page) => {
    page.on('pageerror', () => state.failures.push('Uncaught portal runtime error'));
    page.on('download', () => state.downloads++);
    page.on('console', (message) => {
      if (/hydration|Content Security Policy/i.test(message.text())) {
        state.failures.push('Hydration or CSP console error');
      }
      if (harness.secrets.some((secret) => secret && message.text().includes(secret))) {
        state.failures.push('Fixture identity or credential appeared in console output');
      }
    });
    page.on('request', (request) => {
      if (request.url().startsWith('blob:')) return;
      const url = new URL(request.url());
      if (url.origin !== harness.origin) state.failures.push('Unexpected third-party request');
      if (
        harness.secrets.some((secret) => secret && url.href.includes(encodeURIComponent(secret)))
      ) {
        state.failures.push('Fixture secret appeared in a request URL');
      }
      if (!url.pathname.startsWith('/api/')) return;
      const proof = request.headers().dpop;
      if (!proof) return; // Deliberate cookie-only denial probes are included below.
      try {
        const [header, claims] = proof
          .split('.')
          .slice(0, 2)
          .map((part) => JSON.parse(Buffer.from(part, 'base64url').toString()));
        assert.equal(header.typ, 'dpop+jwt');
        assert.equal(header.alg, 'ES256');
        assert.equal(header.jwk.kty, 'EC');
        assert.equal(header.jwk.crv, 'P-256');
        assert(!('d' in header.jwk));
        assert.equal(claims.htm, request.method());
        assert.equal(claims.htu, harness.origin + url.pathname);
        assert.equal(typeof claims.iat, 'number');
        assert.equal(typeof claims.jti, 'string');
        assert(!('ath' in claims), 'Cookie DPoP must not invent an access-token hash');
        const jti = hash(claims.jti);
        assert(!state.proofs.has(jti), 'Every transmitted proof needs a fresh JTI');
        state.proofs.add(jti);
        state.keys.add(
          hash(
            JSON.stringify({
              crv: header.jwk.crv,
              kty: header.jwk.kty,
              x: header.jwk.x,
              y: header.jwk.y,
            })
          )
        );
      } catch {
        state.failures.push(
          `Invalid or reused outgoing browser proof for ${portalRoute(url.pathname)}`
        );
      }
    });
    page.on('response', (response) => {
      const url = new URL(response.url());
      if (!url.pathname.startsWith('/api/')) return;
      state.pending.push(
        (async () => {
          const headers = await response.allHeaders();
          assert.match(headers['cache-control'] || '', /\bprivate\b/);
          assert.match(headers['cache-control'] || '', /\bno-store\b/);
          assert.equal(headers['referrer-policy'], 'no-referrer');
          if (headers['dpop-nonce']) {
            assert.equal(response.status(), 401);
            assert.match(headers['www-authenticate'] || '', /use_dpop_nonce/);
            state.nonceChallenges++;
          }
          if (anonymousReclaim(url.pathname, response.request().method())) {
            const requestHeaders = await response.request().allHeaders();
            for (const header of ['cookie', 'authorization', 'dpop', 'x-portal-session', 'x-step-up-auth', 'referer'])
              assert(!requestHeaders[header], 'Anonymous recovery transmitted browser authority');
            assert.equal(requestHeaders.origin, harness.origin);
            assert(!headers['set-cookie'], 'Recovery issued a session cookie');
            state.anonymous++;
          } else if (response.ok() && url.pathname !== '/api/v1/auth/logout') {
            assert(response.request().headers().dpop, 'Successful portal API request without DPoP');
          }
        })().catch(() =>
          state.failures.push(
            `API privacy/auth response policy failed for ${portalRoute(url.pathname)}`
          )
        )
      );
    });
  });
  return state;
}

async function newContext(browser, harness) {
  const context = await browser.newContext({ bypassCSP: false, serviceWorkers: 'block' });
  context.setDefaultTimeout(15_000);
  context.setDefaultNavigationTimeout(30_000);
  await context.addInitScript(() => {
    globalThis.__portalCsp = [];
    globalThis.__portalObjectURLs = new Set();
    globalThis.__portalPageShows = [];
    globalThis.__portalBroadcasts = [];
    const post = BroadcastChannel.prototype.postMessage;
    BroadcastChannel.prototype.postMessage = function (value) {
      if (this.name === 'hatef-portal-session')
        globalThis.__portalBroadcasts.push(value === 'invalidate' ? 'invalidate' : 'unexpected');
      return Reflect.apply(post, this, [value]);
    };
    document.addEventListener('securitypolicyviolation', (event) => {
      globalThis.__portalCsp.push(event.effectiveDirective);
    });
    addEventListener('pageshow', (event) => globalThis.__portalPageShows.push(event.persisted));
    const create = URL.createObjectURL;
    const revoke = URL.revokeObjectURL;
    URL.createObjectURL = function (...args) {
      const value = Reflect.apply(create, this, args);
      globalThis.__portalObjectURLs.add(value);
      return value;
    };
    URL.revokeObjectURL = function (value) {
      globalThis.__portalObjectURLs.delete(value);
      return Reflect.apply(revoke, this, [value]);
    };
  });
  return { context, observed: observe(context, harness) };
}

async function addAuthenticator(page, credential) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { cdp, authenticatorId };
}

async function visit(page, origin, path) {
  await page.bringToFront();
  const response = await page.goto(origin + path, { waitUntil: 'load' });
  assert(response && response.status() === 200, 'Expected production portal document');
  webDocumentNonce(new Headers(await response.allHeaders()), await response.text());
  return response;
}

async function signIn(page, origin, path = '/login/webauthn') {
  await page.bringToFront();
  await visit(page, origin, path);
  await page.getByTestId('passkey-login').click();
  await page.waitForURL(origin + '/dashboard');
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  const cookie = (await page.context().cookies(origin)).find(
    (cookie) => cookie.name === '__Host-session'
  );
  assert(cookie && cookie.secure && cookie.httpOnly && cookie.sameSite === 'Strict');
  assert.equal(cookie.path, '/');
  assert.equal(cookie.domain, 'localhost');
  assert(!(await page.evaluate(() => document.cookie)).includes('__Host-session='));
}

// This independent boundary probe signs with the actual persisted CryptoKey.
// User flows above/below still use the production adapter and real authenticators.
async function api(page, path, { method = 'GET', body, sessionID, stepUpToken } = {}) {
  assert(stepUpToken === undefined || (typeof stepUpToken === 'string' && stepUpToken.length > 0 &&
    stepUpToken.length <= 8192 && !/[\r\n]/.test(stepUpToken)), 'Invalid bounded step-up probe');
  return page.evaluate(
    async ({ path, method, body, sessionID, stepUpToken }) => {
      const database = await new Promise((resolve, reject) => {
        const open = indexedDB.open('hatef-portal-dpop');
        open.onsuccess = () => resolve(open.result);
        open.onerror = () =>
          reject(new Error('Test probe could not open the existing browser key'));
      });
      const key = await new Promise((resolve, reject) => {
        const read = database.transaction('keys', 'readonly').objectStore('keys').get('active');
        read.onsuccess = () => resolve(read.result);
        read.onerror = () =>
          reject(new Error('Test probe could not read the existing browser key'));
      });
      database.close();
      const encode = (bytes) =>
        btoa(String.fromCharCode(...new Uint8Array(bytes)))
          .replaceAll('+', '-')
          .replaceAll('/', '_')
          .replace(/=+$/, '');
      const text = (value) => encode(new TextEncoder().encode(JSON.stringify(value)));
      let nonce;
      for (let attempt = 0; attempt < 2; attempt++) {
        const claims = {
          htm: method,
          htu: location.origin + path,
          iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(),
          ...(nonce ? { nonce } : {}),
        };
        const unsigned = `${text({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.publicJwk })}.${text(claims)}`;
        const signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          key.privateKey,
          new TextEncoder().encode(unsigned)
        );
        const response = await fetch(path, {
          method,
          credentials: 'same-origin',
          cache: 'no-store',
          redirect: 'error',
          headers: {
            DPoP: `${unsigned}.${encode(signature)}`,
            ...(sessionID ? { 'X-Portal-Session': sessionID } : {}),
            ...(stepUpToken ? { 'X-Step-Up-Auth': stepUpToken } : {}),
            ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          },
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        });
        const result = response.status === 204 ? null : await response.json().catch(() => null);
        if (
          attempt === 0 &&
          response.status === 401 &&
          result?.error === 'use_dpop_nonce' &&
          response.headers.get('DPoP-Nonce')
        ) {
          nonce = response.headers.get('DPoP-Nonce');
          continue;
        }
        return { status: response.status, body: result };
      }
      throw new Error('Test boundary probe exhausted its single nonce retry');
    },
    { path, method, body, sessionID, stepUpToken }
  );
}

async function keyStorage(page) {
  return page.evaluate(async () => {
    const databases = await indexedDB.databases();
    if (databases.length !== 1 || databases[0].name !== 'hatef-portal-dpop') {
      throw new Error('Unexpected persistent portal database');
    }
    const database = await new Promise((resolve, reject) => {
      const open = indexedDB.open('hatef-portal-dpop');
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(new Error('Cannot inspect browser key storage'));
    });
    const values = await new Promise((resolve, reject) => {
      const read = database.transaction('keys', 'readonly').objectStore('keys').getAll();
      read.onsuccess = () => resolve(read.result);
      read.onerror = () => reject(new Error('Cannot inspect browser key record'));
    });
    database.close();
    const value = values[0];
    if (values.length !== 1 || Object.keys(value).sort().join(',') !== 'privateKey,publicJwk') {
      throw new Error('Portal persists more than its single key and public metadata');
    }
    if (
      !(value.privateKey instanceof CryptoKey) ||
      value.privateKey.extractable ||
      value.privateKey.type !== 'private' ||
      value.privateKey.algorithm.name !== 'ECDSA' ||
      value.privateKey.algorithm.namedCurve !== 'P-256' ||
      value.privateKey.usages.join(',') !== 'sign'
    ) {
      throw new Error('Persisted private key is not nonexportable signing-only P-256');
    }
    for (const format of ['jwk', 'pkcs8']) {
      let denied = false;
      try {
        await crypto.subtle.exportKey(format, value.privateKey);
      } catch {
        denied = true;
      }
      if (!denied) throw new Error('Persisted private key was exportable');
    }
    if (Object.keys(value.publicJwk).sort().join(',') !== 'crv,kty,x,y') {
      throw new Error('Unexpected public key metadata');
    }
    const sample = new TextEncoder().encode('nonexportable-key-roundtrip');
    const algorithm = { name: 'ECDSA', hash: 'SHA-256' };
    const signature = await crypto.subtle.sign(algorithm, value.privateKey, sample);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      value.publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    if (!(await crypto.subtle.verify(algorithm, publicKey, signature, sample))) {
      throw new Error('Stored public metadata does not match its private CryptoKey');
    }
    return {
      publicKey: JSON.stringify(value.publicJwk),
      localEmpty: localStorage.length === 0,
      sessionEmpty: sessionStorage.length === 0,
    };
  });
}

async function clean(page, observed, keyless = false) {
  await Promise.all(observed.pending);
  assert.deepEqual(observed.failures, [], 'Portal runtime, privacy or proof regression');
  assert.deepEqual(
    await page.evaluate(() => globalThis.__portalCsp),
    [],
    'Strict portal CSP violation'
  );
  const inlineApplicationStyles = await page.locator('[style]').evaluateAll((elements) =>
    elements.filter((element) => {
      let current = element;
      while (current) {
        if (current.localName === 'next-route-announcer') return false;
        const root = current.getRootNode();
        current = current.parentElement || (root instanceof ShadowRoot ? root.host : null);
      }
      return true;
    }).length
  );
  assert.equal(
    inlineApplicationStyles,
    0,
    'Inline application style'
  );
  assert(!(await page.evaluate(() => globalThis.__portalBroadcasts)).includes('unexpected'),
    'Portal broadcast non-neutral data');
  const storage = keyless ? await page.evaluate(async () => {
    if ((await indexedDB.databases()).length !== 0) throw new Error('Recovery created a browser key');
    return { localEmpty: localStorage.length === 0, sessionEmpty: sessionStorage.length === 0 };
  }) : await keyStorage(page);
  assert(
    storage.localEmpty && storage.sessionEmpty,
    'Portal stored string credentials or account data'
  );
}

async function navigate(page, origin, label, path) {
  await page.bringToFront();
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  const marker = randomUUID();
  await page.evaluate((marker) => {
    document.__portalNavigationMarker = marker;
  }, marker);
  const link = page.getByRole('link', { name: label, exact: true });
  assert.equal(await link.getAttribute('href'), path);
  await Promise.all([page.waitForURL(origin + path), link.click()]);
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  assert.equal(
    await page.evaluate(() => document.__portalNavigationMarker),
    marker,
    'Portal navigation replaced the document'
  );
}

async function stepUp(page, trigger) {
  await trigger();
  const dialog = page.getByTestId('stepup-dialog');
  await dialog.waitFor({ state: 'visible' });
  assert(await dialog.evaluate((element) => element instanceof HTMLDialogElement && element.open));
  await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
  await dialog.getByRole('button', { name: 'Verify with a passkey', exact: true }).click();
}

async function hidePortal(page, context, evidence) {
  const cover = await context.newPage();
  await cover.bringToFront();
  const nativeHidden = await page.evaluate(() => document.visibilityState === 'hidden');
  evidence.nativeHiddenTabObserved ||= nativeHidden;
  if (!nativeHidden) {
    // Headless targets can stay visible. Model a complete transition, not a
    // visible-only event that cannot test the application's resume boundary.
    await page.evaluate(() => {
      globalThis.__portalVisibilityDescriptors = {
        visibility: Object.getOwnPropertyDescriptor(document, 'visibilityState'),
        hidden: Object.getOwnPropertyDescriptor(document, 'hidden'),
      };
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
      Object.defineProperty(document, 'hidden', { configurable: true, value: true });
      document.dispatchEvent(new Event('visibilitychange'));
    });
  }
  await page.getByTestId('portal-ready').waitFor({ state: 'hidden' });
  return async () => {
    await page.bringToFront();
    if (!nativeHidden) {
      await page.evaluate(() => {
        const prior = globalThis.__portalVisibilityDescriptors;
        for (const [name, descriptor] of [
          ['visibilityState', prior.visibility],
          ['hidden', prior.hidden],
        ]) {
          if (descriptor) Object.defineProperty(document, name, descriptor);
          else delete document[name];
        }
        delete globalThis.__portalVisibilityDescriptors;
        document.dispatchEvent(new Event('visibilitychange'));
      });
    }
    await cover.close();
  };
}

async function totpStepUp(page, context, harness, fixture, evidence, trigger) {
  await trigger();
  const dialog = page.getByTestId('stepup-dialog');
  await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
  await dialog.getByRole('button', { name: 'Use authenticator code', exact: true }).click();
  // Send a deliberately invalid factor to the real verifier, without mocking
  // its response or relying on a random six-digit value being incorrect.
  const pattern = '**/api/v1/auth/stepup/verify';
  const rejectFactor = async (route) => {
    const body = route.request().postDataJSON();
    await route.continue({ postData: JSON.stringify({ ...body, code: 'invalid-factor' }) });
  };
  await page.route(pattern, rejectFactor);
  const rejected = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === '/api/v1/auth/stepup/verify' &&
      response.status() === 401 &&
      !response.headers()['dpop-nonce']
  );
  await dialog.getByLabel('Authenticator code', { exact: true }).fill('000000');
  await dialog.getByRole('button', { name: 'Verify code', exact: true }).click();
  await rejected;
  await page.unroute(pattern, rejectFactor);
  await dialog.getByRole('alert').waitFor({ state: 'visible' });
  assert(await page.getByTestId('portal-ready').isVisible(), 'Rejected TOTP erased valid session state');
  await dialog.getByLabel('Authenticator code', { exact: true }).fill('123');

  const resume = await hidePortal(page, context, evidence);
  const rechecked = operationResponse(page, '/api/v1/users/me', 'GET');
  await resume();
  assert.equal((await rechecked).status(), 200);
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  await dialog.getByText(/Your pending action was restored after checking the same session/).waitFor();
  assert.equal(await dialog.getByLabel('Authenticator code', { exact: true }).count(), 0);
  await dialog.getByRole('button', { name: 'Continue to verification', exact: true }).click();
  const input = dialog.getByLabel('Authenticator code', { exact: true });
  await input.waitFor({ state: 'visible' });
  assert.equal(await input.inputValue(), '', 'A factor code survived background suspension');
  let current = harness.fixture('totp-code', { user_id: fixture.user_id });
  assert.match(current.code, /^\d{6}$/);
  await input.fill(current.code);
  const verified = operationResponse(page, '/api/v1/auth/stepup/verify', 'POST');
  await dialog.getByRole('button', { name: 'Verify code', exact: true }).click();
  current = undefined;
  assert.equal((await verified).status(), 200, 'Production TOTP verification failed');
  evidence.checks.push(
    'real encrypted TOTP: rejected factor retains session, background clears entered code, same-session resume requires fresh challenge and explicit successful verification'
  );
}

function operationResponse(page, path, method) {
  return page
    .waitForResponse(
      (response) =>
        new URL(response.url()).pathname === path &&
        response.request().method() === method &&
        response.status() !== 401
    )
    .catch(() => {
      throw new Error(`Timed out waiting for ${method} ${portalRoute(path)}`);
    });
}

async function concurrentTabs(browser, harness, evidence, contexts) {
  const fixture = harness.fixture('seed', { credentials: 2 });
  const { context, observed } = await newContext(browser, harness);
  contexts.push(context);
  const pages = [await context.newPage(), await context.newPage()];
  const authenticators = [];
  for (const [index, page] of pages.entries()) {
    authenticators.push(await addAuthenticator(page, fixture.credentials[index]));
    await visit(page, harness.origin, index === 0 ? '/login' : '/login/webauthn');
  }
  const signedIn = Promise.any(pages.map((page) => page.waitForURL(harness.origin + '/dashboard')));
  await Promise.all(pages.map((page) => page.getByTestId('passkey-login').click()));
  await signedIn;
  // A sibling login notification can cancel one UI continuation. Re-bootstrap
  // both tabs against the final shared cookie rather than silently re-login.
  for (const page of pages) {
    await visit(page, harness.origin, '/dashboard');
    await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  }
  const [first, second] = await Promise.all(pages.map(keyStorage));
  assert.equal(
    first.publicKey,
    second.publicKey,
    'Concurrent initialization created split browser keys'
  );
  assert.equal(observed.keys.size, 1, 'A tab signed a login proof with a losing IndexedDB key');
  for (const page of pages) await clean(page, observed);
  evidence.checks.push(
    'concurrent first-login tabs converge on one persisted, nonexportable signing key'
  );
  return { fixture, context, observed, pages, authenticators };
}

async function profileAndSessions(browser, harness, evidence, contexts, initial) {
  // Reuse the concurrent-login fixture to stay below the real shared anonymous
  // admission limit; never raise a production limit or fake a client subnet.
  const {
    fixture,
    context,
    observed,
    pages: [page, tab],
    authenticators,
  } = initial;
  const original = await api(page, '/api/v1/users/me');
  assert.equal(original.status, 200);
  assert.equal(original.body.lifecycle_revision, '9007199254740993');
  assert(original.body.id === fixture.user_id && original.body.email === fixture.email);
  const key = await keyStorage(page);
  assert.equal(
    (await keyStorage(tab)).publicKey,
    key.publicKey,
    'Tabs do not share the persisted key'
  );

  await navigate(page, harness.origin, 'Profile', '/dashboard/profile');
  const input = page.getByLabel('Display name', { exact: true });
  for (const displayName of ['First portal name', 'Second portal name']) {
    harness.secrets.push(displayName);
    await input.fill(displayName);
    const response = operationResponse(page, '/api/v1/users/me', 'PATCH');
    await page.getByRole('button', { name: 'Save profile', exact: true }).click();
    assert.equal((await response).status(), 200, 'Repeated profile save failed');
    await page.getByRole('status').filter({ hasText: /saved/i }).waitFor({ state: 'visible' });
  }
  const saved = (await api(page, '/api/v1/users/me')).body;
  assert.equal(saved.lifecycle_revision, '9007199254740995');
  const draft = 'Unsaved portal draft';
  harness.secrets.push(draft);
  await input.fill(draft);
  const competing = await api(tab, '/api/v1/users/me', {
    method: 'PATCH',
    sessionID: original.body.session.id,
    body: { display_name: 'Saved in another tab', expected_revision: saved.lifecycle_revision },
  });
  assert.equal(competing.status, 200);
  const conflict = operationResponse(page, '/api/v1/users/me', 'PATCH');
  await page.getByRole('button', { name: 'Save profile', exact: true }).click();
  assert.equal((await conflict).status(), 409);
  assert((await input.inputValue()) === draft, 'Profile conflict erased the unsaved draft');
  await page.getByRole('button', { name: 'Refresh saved profile', exact: true }).click();
  assert((await input.inputValue()) === draft, 'Conflict refresh erased the unsaved draft');

  const cookieOnly = await page.evaluate(async () => {
    const response = await fetch('/api/v1/users/me', { cache: 'no-store' });
    return response.status;
  });
  assert.equal(cookieOnly, 401, 'Cookie-only bootstrap bypassed browser proof binding');
  await noJavaScript(browser, context, harness, evidence);
  await page.bringToFront();
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  await appearance(page, evidence);

  const remote = await newContext(browser, harness);
  contexts.push(remote.context);
  const remotePage = await remote.context.newPage();
  const { credentials } = await authenticators[1].cdp.send('WebAuthn.getCredentials', {
    authenticatorId: authenticators[1].authenticatorId,
  });
  const remoteCredential = credentials.find(
    (credential) => credential.credentialId === fixture.credentials[1].credentialId
  );
  assert(remoteCredential, 'Missing virtual credential for independent remote session');
  await addAuthenticator(remotePage, remoteCredential);
  await signIn(remotePage, harness.origin);
  const remoteProfile = (await api(remotePage, '/api/v1/users/me')).body;
  await navigate(page, harness.origin, 'Sessions', '/dashboard/sessions');
  const remoteRow = page.locator(`[data-session-id="${remoteProfile.session.id}"]`);
  await remoteRow.waitFor({ state: 'visible' });
  await remoteRow.getByRole('button', { name: /revoke/i }).click();
  const revoke = operationResponse(
    page,
    `/api/v1/users/me/sessions/${remoteProfile.session.id}`,
    'DELETE'
  );
  await page
    .getByTestId('session-dialog')
    .getByRole('button', { name: 'Confirm revocation', exact: true })
    .click();
  assert.equal((await revoke).status(), 204);
  assert.equal(
    (await api(remotePage, '/api/v1/users/me')).status,
    401,
    'Revoked session retained API authority'
  );
  await remotePage.bringToFront();
  await remotePage.reload();
  await remotePage
    .getByRole('link', { name: 'Sign in with a passkey', exact: true })
    .waitFor({ state: 'visible' });
  await remotePage.getByTestId('portal-ready').waitFor({ state: 'hidden' });
  assert(
    !(await remotePage.locator('body').innerText()).includes(fixture.email),
    'Revoked session redisplayed profile data'
  );

  // Change the shared cookie by a real second account's login. Even if a tab
  // misses its BroadcastChannel invalidation, its captured intent cannot write.
  const other = harness.fixture('seed');
  const loginTab = await context.newPage();
  await addAuthenticator(loginTab, other.credentials[0]);
  await signIn(loginTab, harness.origin);
  const changed = (await api(loginTab, '/api/v1/users/me')).body;
  const stale = await api(page, '/api/v1/users/me', {
    method: 'PATCH',
    sessionID: original.body.session.id,
    body: {
      display_name: 'Must not cross accounts',
      expected_revision: changed.lifecycle_revision,
    },
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error, 'session_changed');
  const staleRead = await api(page, '/api/v1/auth/webauthn/keys', {
    sessionID: original.body.session.id,
  });
  assert.equal(staleRead.status, 409, 'A stale post-bootstrap read merged accounts');
  assert(
    (await api(loginTab, '/api/v1/users/me')).body.display_name === '',
    'Stale intent changed the replacement account'
  );
  await page.waitForFunction((email) => !document.body.textContent.includes(email), fixture.email);

  await navigate(loginTab, harness.origin, 'Sessions', '/dashboard/sessions');
  await loginTab
    .locator(`[data-session-id="${changed.session.id}"]`)
    .getByRole('button', { name: 'Sign out this session', exact: true })
    .click();
  const logout = operationResponse(
    loginTab,
    `/api/v1/users/me/sessions/${changed.session.id}`,
    'DELETE'
  );
  await loginTab
    .getByTestId('session-dialog')
    .getByRole('button', { name: 'Confirm sign out', exact: true })
    .click();
  assert.equal((await logout).status(), 204);
  await page.getByTestId('portal-ready').waitFor({ state: 'hidden' });
  assert(
    !(await context.cookies(harness.origin)).some((cookie) => cookie.name === '__Host-session')
  );
  await Promise.all(observed.pending);
  assert.deepEqual(observed.failures, []);
  assert(
    observed.nonceChallenges > 0 && observed.proofs.size > 10,
    'Real browser nonce/proof path was not exercised'
  );
  evidence.checks.push(
    'real passkey login, exact revisions, repeated/conflicting profile edits, multi-tab key reuse, no-JS private shell, remote revoke, stale reads/writes, cross-tab logout'
  );
}

async function noJavaScript(browser, authenticated, harness, evidence) {
  const context = await browser.newContext({
    javaScriptEnabled: false,
    bypassCSP: false,
    serviceWorkers: 'block',
  });
  try {
    await context.addCookies(await authenticated.cookies(harness.origin));
    const page = await context.newPage();
    const apiCalls = [];
    page.on('request', (request) => {
      if (new URL(request.url()).pathname.startsWith('/api/')) apiCalls.push(request.method());
    });
    for (const route of routes) {
      const response = await visit(page, harness.origin, route);
      const html = await response.text();
      const exposed = harness.secrets.findIndex((secret) => secret && html.includes(secret));
      assert.equal(
        exposed,
        -1,
        `Private profile was server-rendered (${route}; secret index ${exposed}; length ${harness.secrets[exposed]?.length || 0})`
      );
      assert.equal(
        await page.getByTestId('portal-ready').count(),
        0,
        'Cookie presence rendered an authorized portal'
      );
    }
    assert.deepEqual(apiCalls, [], 'No-JavaScript shell attempted authenticated API work');
    evidence.noJavaScript = routes.length;
  } finally {
    await context.close();
  }
}

async function appearance(page, evidence, scope = 'portal') {
  for (const dark of [false, true]) {
    await page.evaluate((dark) => document.documentElement.classList.toggle('dark', dark), dark);
    for (const viewport of [
      { width: 320, height: 568 },
      { width: 390, height: 844 },
      { width: 1280, height: 800 },
    ]) {
      await page.setViewportSize(viewport);
      const violations = await page.evaluate(() => {
        const failures = [];
        if (document.documentElement.scrollWidth > innerWidth + 1)
          failures.push('horizontal overflow');
        for (const control of document.querySelectorAll('main button, main input, nav a')) {
          if (!control.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;
          // A checkbox's associated, clickable label is its larger touch target.
          const target = control.matches('input[type="checkbox"]') && control.labels?.length
            ? control.labels[0] : control;
          const rect = target.getBoundingClientRect();
          if (rect.width < 44 || rect.height < 44) failures.push('control below 44px');
          if (rect.left < -1 || rect.right > innerWidth + 1)
            failures.push('control outside viewport');
        }
        return failures;
      });
      assert.deepEqual(
        violations,
        [],
        `Portal ${dark ? 'dark' : 'light'} ${viewport.width}px reflow`
      );
      evidence.viewports.push(`${scope}-${dark ? 'dark' : 'light'}-${viewport.width}x${viewport.height}`);
      if (process.env.PORTAL_BROWSER_ARTIFACT_DIR) {
        const directory = resolve(process.env.PORTAL_BROWSER_ARTIFACT_DIR);
        await mkdir(directory, { recursive: true });
        await page.screenshot({
          path: resolve(directory, `${scope}-${dark ? 'dark' : 'light'}-${viewport.width}.png`),
          fullPage: true,
          // Artifacts demonstrate layout, not a persistent account-data export.
          mask: [
            page.locator('input, [data-testid="saved-display-name"]'),
            page.getByText(/portal-[a-f0-9-]+@[a-f0-9]+\.example\.test/, { exact: true }),
          ],
        });
      }
    }
  }
  await page.evaluate(() => document.documentElement.classList.remove('dark'));
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function passkeyManagement(browser, harness, evidence, contexts) {
  const fixture = harness.fixture('seed', { totp: true });
  const { context, observed } = await newContext(browser, harness);
  contexts.push(context);
  const page = await context.newPage();
  const authenticator = await addAuthenticator(page, fixture.credentials[0]);
  await signIn(page, harness.origin);
  await navigate(page, harness.origin, 'Security', '/dashboard/security');
  const originalID = Buffer.from(fixture.credentials[0].credentialId, 'base64').toString(
    'base64url'
  );
  const passkeyName = 'Portable browser test key';
  harness.secrets.push(passkeyName);
  await page.getByLabel('New passkey name', { exact: true }).fill(passkeyName);
  const add = page.getByRole('button', { name: 'Add passkey', exact: true });
  await add.click();
  const dialog = page.getByTestId('stepup-dialog');
  await dialog.waitFor({ state: 'visible' });
  for (let i = 0; i < 8; i++) {
    assert(
      await dialog.evaluate((element) => element.contains(document.activeElement)),
      'Modal focus escaped'
    );
    await page.keyboard.press('Tab');
  }
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  assert(
    await add.evaluate((element) => element === document.activeElement),
    'Modal did not restore initiating focus'
  );

  // The fixture injects the existing credential directly into the virtual
  // authenticator. Remove it only after step-up reaches registration so the
  // device can create a distinct credential while the server keeps the original.
  await page.route(
    '**/api/v1/auth/webauthn/register/generate-options',
    async (route) => {
      await authenticator.cdp.send('WebAuthn.removeCredential', {
        authenticatorId: authenticator.authenticatorId,
        credentialId: fixture.credentials[0].credentialId,
      });
      await route.continue();
    },
    { times: 1 }
  );
  const created = operationResponse(page, '/api/v1/auth/webauthn/register/verify', 'POST');
  const createdBody = harness.captureJSON('/api/v1/auth/webauthn/register/verify', 'POST', 201);
  await stepUp(page, () => add.click());
  const createResponse = await created;
  assert.equal(createResponse.status(), 201);
  const key = await createdBody;
  assert(key.name === passkeyName, 'Registration did not preserve the pending name');
  const row = page.locator(`[data-key-id="${key.id}"]`);
  await row.waitFor({ state: 'visible' });
  await row.getByRole('button', { name: /^Rename / }).click();
  await row.getByLabel('Passkey name', { exact: true }).fill('Renamed browser key');
  const renamed = operationResponse(page, `/api/v1/auth/webauthn/keys/${key.id}`, 'PATCH');
  await totpStepUp(page, context, harness, fixture, evidence, () =>
    row.getByRole('button', { name: 'Save passkey name', exact: true }).click()
  );
  assert.equal((await renamed).status(), 200);
  const removed = operationResponse(page, `/api/v1/auth/webauthn/keys/${key.id}`, 'DELETE');
  await stepUp(page, () => row.getByRole('button', { name: /remove/i }).click());
  assert.equal((await removed).status(), 204);
  await row.waitFor({ state: 'detached' });

  const original = page.locator(`[data-key-id="${originalID}"]`);
  assert(
    await original.getByRole('button', { name: /^Remove / }).isDisabled(),
    'UI offered to remove the final passkey'
  );
  await page
    .getByText('Add another passkey before removing your last one.', { exact: true })
    .waitFor({ state: 'visible' });
  await clean(page, observed);
  evidence.checks.push(
    'native modal focus/escape/return, UV step-up, named registration across replicas, rename/delete, disabled final-passkey removal, strict CSP'
  );
}

async function generateCodes(page, harness) {
  const generated = harness.captureJSON('/api/v1/auth/recovery-codes/generate', 'POST', 200);
  await stepUp(page, () => page.getByRole('button', { name: /generate.*recovery codes/i }).click());
  const batch = await generated;
  assert(Array.isArray(batch.codes) && batch.codes.length === batch.count && batch.count === 10);
  harness.secrets.push(...batch.codes);
  const viewer = page.getByTestId('recovery-viewer');
  await viewer.waitFor({ state: 'visible' });
  const visible = await viewer.getByTestId('recovery-code').allTextContents();
  assert(
    visible.length === batch.codes.length &&
      visible.every((code, i) => code.trim() === batch.codes[i]),
    'One-time viewer does not match the received batch'
  );
  return batch.codes;
}

async function recoveryLifecycle(browser, harness, evidence, contexts) {
  const fixture = harness.fixture('seed');
  const { context, observed } = await newContext(browser, harness);
  contexts.push(context);
  const page = await context.newPage();
  await page.clock.install({ time: new Date() });
  await addAuthenticator(page, fixture.credentials[0]);
  await signIn(page, harness.origin);
  await navigate(page, harness.origin, 'Security', '/dashboard/security');
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: harness.origin });
  await page.evaluate(() => navigator.clipboard.writeText('portal-clipboard-sentinel'));
  const first = await generateCodes(page, harness);
  assert(
    (await page.evaluate(() => navigator.clipboard.readText())) === 'portal-clipboard-sentinel',
    'Codes were automatically copied'
  );
  assert.equal(observed.downloads, 0, 'Codes were automatically downloaded');
  const viewer = page.getByTestId('recovery-viewer');
  await viewer.getByRole('button', { name: /copy/i }).click();
  await page.waitForFunction(async (codes) => {
    const value = await navigator.clipboard.readText();
    return codes.every((code) => value.includes(code));
  }, first);
  const downloadPromise = page.waitForEvent('download');
  await viewer.getByRole('button', { name: /download/i }).click();
  const download = await downloadPromise;
  assert.match(
    download.suggestedFilename(),
    /^[a-z][a-z-]{0,63}\.txt$/i,
    'Download filename must be neutral'
  );
  assert(
    !(
      download.suggestedFilename().includes(fixture.user_id) ||
      download.suggestedFilename().includes(fixture.email)
    )
  );
  const stream = await download.createReadStream();
  assert(stream);
  let text = '';
  for await (const chunk of stream) {
    text += chunk.toString();
    assert(text.length <= 8192, 'Unbounded recovery download');
  }
  assert(
    first.every((code) => text.includes(code)),
    'Downloaded batch differs from the one-time viewer'
  );
  await page.waitForFunction(() => globalThis.__portalObjectURLs.size === 0);
  text = '';
  await viewer.getByRole('button', { name: 'Done', exact: true }).click();
  await viewer.waitFor({ state: 'hidden' });
  assert(
    (await page.evaluate(() => navigator.clipboard.readText())).includes(first[0]),
    'Done must not claim to erase the user clipboard'
  );
  await page.evaluate(() => navigator.clipboard.writeText(''));

  const second = await generateCodes(page, harness);
  assert.equal(
    harness.fixture('consume-code', { user_id: fixture.user_id, code: first[0] }).consumed,
    false,
    'Replacement kept an old code valid'
  );
  assert.equal(
    harness.fixture('consume-code', { user_id: fixture.user_id, code: second[0] }).consumed,
    true
  );
  assert.equal(
    harness.fixture('consume-code', { user_id: fixture.user_id, code: second[0] }).consumed,
    false,
    'Code replay succeeded'
  );
  assert.equal((await api(page, '/api/v1/auth/recovery-codes/status')).body.remaining, 9);
  await navigate(page, harness.origin, 'Profile', '/dashboard/profile');
  await navigate(page, harness.origin, 'Security', '/dashboard/security');
  assert.equal(
    await page.getByTestId('recovery-viewer').count(),
    0,
    'Client navigation restored plaintext codes'
  );

  await generateCodes(page, harness);
  await visit(page, harness.origin, '/login');
  await page.goBack({ waitUntil: 'load' });
  await page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  assert.equal(
    await page.getByTestId('recovery-viewer').count(),
    0,
    'History navigation restored plaintext codes'
  );
  evidence.nativeBfcacheRestoreObserved = await page.evaluate(() =>
    globalThis.__portalPageShows.includes(true)
  );

  await generateCodes(page, harness);
  await page.clock.fastForward(300_001);
  await page.getByTestId('recovery-viewer').waitFor({ state: 'hidden' });
  await page.clock.setSystemTime(new Date());

  await generateCodes(page, harness);
  const current = (await api(page, '/api/v1/users/me')).body;
  const resume = await hidePortal(page, context, evidence);
  harness.fixture('expire-session', { user_id: fixture.user_id, session_id: current.session.id });
  await resume();
  await page.getByTestId('recovery-viewer').waitFor({ state: 'hidden' });
  assert.equal(
    (await api(page, '/api/v1/users/me')).status,
    401,
    'Expired session retained API authority'
  );
  await Promise.all(observed.pending);
  assert.deepEqual(observed.failures, []);
  const storage = await keyStorage(page);
  assert(storage.localEmpty && storage.sessionEmpty);
  evidence.checks.push(
    'one-time recovery Copy/Download/no-auto-export, neutral filename, revoked object URL, replacement and physical one-use consumption, Done/navigation/history/five-minute/session-expiry cleanup'
  );
}

async function uncertainRecovery(browser, harness, evidence, contexts) {
  const fixture = harness.fixture('seed');
  const { context, observed } = await newContext(browser, harness);
  contexts.push(context);
  const page = await context.newPage();
  const authenticator = await addAuthenticator(page, fixture.credentials[0]);
  await signIn(page, harness.origin);
  await navigate(page, harness.origin, 'Security', '/dashboard/security');
  let committed = 0;
  let lostCodes;
  let interceptionFailed = false;
  const interceptions = [];
  const cdp = authenticator.cdp;
  const loseResponse = (event) => {
    const task = (async () => {
      try {
        // Stay on Chromium's pinned-certificate connection. Node route.fetch
        // would create a separate TLS client and could log credential headers.
        if (event.responseStatusCode === 200) {
          const result = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
          const text = result.base64Encoded
            ? Buffer.from(result.body, 'base64').toString('utf8')
            : result.body;
          lostCodes = JSON.parse(text).codes;
          harness.secrets.push(...lostCodes);
          committed++;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        } else {
          await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
        }
      } catch {
        interceptionFailed = true;
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }).catch(() => {});
      }
    })();
    interceptions.push(task);
  };
  cdp.on('Fetch.requestPaused', loseResponse);
  await cdp.send('Fetch.enable', {
    patterns: [{ urlPattern: `${harness.origin}/api/v1/auth/recovery-codes/generate`, requestStage: 'Response' }],
  });
  try {
    await stepUp(page, () => page.getByRole('button', { name: /generate.*recovery codes/i }).click());
    await page
      .getByTestId('stepup-dialog')
      .getByRole('alert')
      .filter({ hasText: /may.*invalid|may.*replaced|cannot confirm|uncertain/i })
      .waitFor({ state: 'visible' });
    await Promise.all(interceptions);
    assert.equal(interceptionFailed, false, 'Recovery response interception failed');
    await page.waitForTimeout(300);
  } finally {
    await cdp.send('Fetch.disable').catch(() => {});
    cdp.off('Fetch.requestPaused', loseResponse);
    await Promise.all(interceptions);
  }
  assert.equal(committed, 1, 'Uncertain generation was silently retried');
  assert.equal(await page.getByTestId('recovery-viewer').count(), 0);
  assert.equal((await api(page, '/api/v1/auth/recovery-codes/status')).body.remaining, 10);
  await page
    .getByTestId('stepup-dialog')
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  await page.getByTestId('stepup-dialog').waitFor({ state: 'hidden' });
  await generateCodes(page, harness);
  assert.equal(
    harness.fixture('consume-code', { user_id: fixture.user_id, code: lostCodes[0] }).consumed,
    false
  );
  lostCodes = undefined;
  await clean(page, observed);
  const logout = operationResponse(page, '/api/v1/auth/logout', 'POST');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  assert.equal((await logout).status(), 204);
  await page.getByTestId('recovery-viewer').waitFor({ state: 'hidden' });
  assert(
    !(await context.cookies(harness.origin)).some((cookie) => cookie.name === '__Host-session')
  );
  evidence.checks.push(
    'lost real generation response is uncertain, no automatic retry/cache restore, explicit replacement with fresh step-up, local sign-out clears the viewer and cookie'
  );
}

async function currentCredential(authenticator, credentialID) {
  const { credentials } = await authenticator.cdp.send('WebAuthn.getCredentials', {
    authenticatorId: authenticator.authenticatorId,
  });
  const credential = credentials.find((value) => value.credentialId === credentialID);
  assert(credential, 'Missing current fixture credential');
  return credential;
}

async function deletionPolicy(page, harness, fixture, authenticator, evidence) {
  const profile = (await api(page, '/api/v1/users/me')).body;
  assert.equal(profile.deletion_enabled, true, 'Production fixture did not enable deletion');
  for (const path of ['/api/v1/users/me', '/api/v1/users/me/']) {
    const denied = await api(page, path, { method: 'DELETE', sessionID: profile.session.id });
    assert.equal(denied.status, 403);
    assert.equal(denied.body.error, 'insufficient_user_authentication');
  }
  const challenge = await api(page, '/api/v1/auth/stepup/challenge', {
    method: 'POST', sessionID: profile.session.id, body: {},
  });
  assert(challenge.body.methods.includes('totp'), 'Fixture did not advertise real TOTP');
  let factor = harness.fixture('totp-code', { user_id: fixture.user_id });
  const grant = await api(page, '/api/v1/auth/stepup/verify', {
    method: 'POST', sessionID: profile.session.id, body: { method: 'totp', code: factor.code },
  });
  factor = undefined;
  assert.equal(grant.status, 200, 'Valid TOTP verification did not mint a real grant');
  harness.secrets.push(grant.body.token);
  const claims = JSON.parse(Buffer.from(grant.body.token.split('.')[1], 'base64url').toString());
  assert.deepEqual(claims.amr, ['otp']);
  const denied = await api(page, '/api/v1/users/me', {
    method: 'DELETE', sessionID: profile.session.id, stepUpToken: grant.body.token,
  });
  assert.equal(denied.status, 403, 'A real TOTP grant authorized account deletion');
  assert.equal(denied.body.error, 'insufficient_user_authentication');
  const consumed = await api(page, '/api/v1/auth/recovery-codes/generate', {
    method: 'POST', sessionID: profile.session.id, stepUpToken: grant.body.token, body: {},
  });
  assert.equal(consumed.status, 403, 'Wrong-method deletion grant remained reusable');
  grant.body.token = '';
  assert.equal((await api(page, '/api/v1/users/me')).status, 200);

  await navigate(page, harness.origin, 'Privacy', '/dashboard/privacy');
  await appearance(page, evidence, 'privacy');
  const acknowledgement = page.getByRole('checkbox', { name: /I understand the account-deletion consequences/ });
  const remove = page.getByRole('button', { name: 'Delete my account', exact: true });
  assert(await remove.isDisabled(), 'Deletion did not require acknowledgement');
  await acknowledgement.focus();
  await page.keyboard.press('Space');
  await remove.click();
  const dialog = page.getByRole('dialog', { name: 'Confirm account deletion', exact: true });
  await dialog.waitFor({ state: 'visible' });
  for (let index = 0; index < 8; index++) {
    assert(await dialog.evaluate((element) => element.contains(document.activeElement)),
      'Deletion modal focus escaped');
    await page.keyboard.press('Tab');
  }
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  assert(await remove.isDisabled(), 'Cancelling deletion retained acknowledgement');

  await acknowledgement.check();
  await authenticator.cdp.send('WebAuthn.setResponseOverrideBits', {
    authenticatorId: authenticator.authenticatorId, isBadUV: true,
  });
  try {
    const refused = operationResponse(page, '/api/v1/auth/stepup/verify', 'POST');
    const refusedBody = harness.captureJSON('/api/v1/auth/stepup/verify', 'POST', 403);
    await stepUp(page, () => remove.click());
    const response = await refused;
    assert.equal(response.status(), 403, 'Presence-only authenticator was not rejected');
    assert.equal((await refusedBody).error, 'user_verification_required');
    await dialog.getByRole('alert').waitFor({ state: 'visible' });
    assert.equal(await dialog.getByRole('button', { name: 'Use authenticator code', exact: true }).count(), 0);
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  } finally {
    await authenticator.cdp.send('WebAuthn.setResponseOverrideBits', {
      authenticatorId: authenticator.authenticatorId,
    });
  }
  const unchanged = harness.fixture('deletion-state', { user_id: fixture.user_id });
  assert.equal(unchanged.status, 'active');
  assert.equal(unchanged.requests, 0, 'Cancelled or non-UV authorization changed the account');
  evidence.checks.push(
    'deletion aliases reject missing grants; real valid TOTP grant is denied and consumed without session loss; acknowledgement, keyboard cancellation/focus containment, real UP-only assertion refusal, no TOTP deletion fallback'
  );
}

async function deleteWithOutcome(page, harness, authenticator, mode) {
  const key = (await keyStorage(page)).publicKey;
  const broadcasts = await page.evaluate(() => globalThis.__portalBroadcasts.length);
  let requests = 0;
  let nonces = 0;
  let logouts = 0;
  let commits = 0;
  let interceptionFailed = false;
  const interceptions = [];
  const request = (request) => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/users/me' && request.method() === 'DELETE') requests++;
    if (path === '/api/v1/auth/logout') logouts++;
  };
  const response = (response) => {
    if (new URL(response.url()).pathname === '/api/v1/users/me' &&
      response.request().method() === 'DELETE' && response.headers()['dpop-nonce']) nonces++;
  };
  page.on('request', request);
  page.on('response', response);
  const cdp = authenticator.cdp;
  const intercept = (event) => {
    interceptions.push((async () => {
      try {
        if (event.request.method !== 'DELETE' || event.responseStatusCode !== 204) {
          await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
          return;
        }
        commits++;
        if (mode === 'post-send-abort') {
          // The real API has committed. Backgrounding must abort the caller,
          // clear private views, and retain only an unconfirmed terminal result.
          await page.evaluate(() => {
            globalThis.__privacyVisibility = {
              visibilityState: Object.getOwnPropertyDescriptor(document, 'visibilityState'),
              hidden: Object.getOwnPropertyDescriptor(document, 'hidden'),
            };
            Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
            Object.defineProperty(document, 'hidden', { configurable: true, value: true });
            document.dispatchEvent(new Event('visibilitychange'));
          });
          // Cancellation can retire the interception before this release.
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
        } else {
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        }
      } catch {
        interceptionFailed = true;
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }).catch(() => {});
      }
    })());
  };
  if (mode !== 'confirmed') {
    cdp.on('Fetch.requestPaused', intercept);
    await cdp.send('Fetch.enable', {
      patterns: [{ urlPattern: `${harness.origin}/api/v1/users/me`, requestStage: 'Response' }],
    });
  }
  try {
    const confirmed = mode === 'confirmed' ? operationResponse(page, '/api/v1/users/me', 'DELETE') : null;
    await page.getByRole('checkbox', { name: /I understand the account-deletion consequences/ }).check();
    await stepUp(page, () => page.getByRole('button', { name: 'Delete my account', exact: true })
      .evaluate((button) => { button.click(); button.click(); }));
    if (confirmed) {
      assert.equal((await confirmed).status(), 204);
      commits++;
    }
    const outcome = page.getByTestId('deletion-outcome');
    await outcome.waitFor({ state: 'visible' });
    assert.equal(await outcome.getAttribute('data-outcome'), mode === 'confirmed' ? 'confirmed' : 'unconfirmed');
    await Promise.all(interceptions);
    assert.equal(interceptionFailed, false, 'Deletion response interception failed');
    if (mode === 'post-send-abort') {
      await page.evaluate(() => {
        for (const [name, descriptor] of Object.entries(globalThis.__privacyVisibility)) {
          if (descriptor) Object.defineProperty(document, name, descriptor);
          else delete document[name];
        }
        delete globalThis.__privacyVisibility;
        document.dispatchEvent(new Event('visibilitychange'));
      });
    }
    await page.waitForFunction(() => document.activeElement ===
      document.querySelector('[data-testid="deletion-outcome"] h1'));
    assert(await outcome.getByRole('status').isVisible(), 'Deletion outcome was not announced');
    assert.equal(await page.getByTestId('portal-ready').count(), 0);
    assert.equal(await page.getByTestId('stepup-dialog').count(), 0);
    assert.equal(await page.evaluate(() => globalThis.__portalBroadcasts.length) - broadcasts, 1,
      'Deletion broadcast was not exactly once');
    assert.equal(logouts, 0, 'Deletion issued a redundant logout');
    assert.equal(commits, 1, 'Duplicate clicks or uncertainty repeated deletion');
    assert.equal(requests - nonces, 1, 'Deletion was replayed without an explicit nonce challenge');
    assert((await keyStorage(page)).publicKey === key, 'Deletion removed the shared browser key');
    if (mode === 'confirmed') {
      assert(!(await page.context().cookies(harness.origin)).some((cookie) => cookie.name === '__Host-session'),
        'Confirmed deletion retained its session cookie');
    }
  } finally {
    if (mode !== 'confirmed') {
      await cdp.send('Fetch.disable').catch(() => {});
      cdp.off('Fetch.requestPaused', intercept);
      await Promise.all(interceptions);
    }
    page.off('request', request);
    page.off('response', response);
  }
}

async function openReclaimLink(page, harness, path) {
  // An email opens a fresh document. Hash-only navigation on an already open
  // recovery page deliberately clears authority and is not a new page load.
  await page.goto('about:blank');
  return visit(page, harness.origin, path);
}

async function reclaimFromMail(browser, harness, fixture, notice, credential, evidence, contexts, totpOnly = false, loseSuccess = false) {
  const { context, observed } = await newContext(browser, harness);
  contexts.push(context);
  const page = await context.newPage();
  const authenticator = credential ? await addAuthenticator(page, credential) : null;
  let optionsCalls = 0;
  let completions = 0;
  page.on('request', (request) => {
    const path = new URL(request.url()).pathname;
    if (path === '/api/v1/auth/deletion/reclaim/options') optionsCalls++;
    if (path === '/api/v1/auth/deletion/reclaim/') completions++;
  });
  for (const fragment of ['', '#token=invalid', `#token=${notice.token}&token=${notice.token}`]) {
    await openReclaimLink(page, harness, `/recover-account${fragment}`);
    await page.waitForURL(harness.origin + '/recover-account');
    const start = page.getByRole('button', { name: 'Start account recovery', exact: true });
    await page.getByRole('alert').filter({ hasText: /no longer holds a usable recovery link/ }).waitFor();
    assert(await start.isDisabled(), 'Missing or duplicate token enabled recovery');
  }
  await openReclaimLink(page, harness, notice.link.slice(harness.origin.length));
  await page.waitForURL(harness.origin + '/recover-account');
  await page.getByRole('button', { name: 'Start account recovery', exact: true }).waitFor();
  await page.reload({ waitUntil: 'load' });
  await page.getByRole('alert').filter({ hasText: /no longer holds a usable recovery link/ }).waitFor();
  assert(await page.getByRole('button', { name: 'Start account recovery', exact: true }).isDisabled(),
    'Reload restored an emailed bearer token');
  await openReclaimLink(page, harness, notice.link.slice(harness.origin.length));
  await page.waitForURL(harness.origin + '/recover-account');
  assert.equal(optionsCalls, 0, 'Opening an email link automatically requested options');
  assert.equal(completions, 0, 'Opening an email link automatically redeemed it');
  await clean(page, observed, true);
  assert.equal((await context.cookies(harness.origin)).length, 0);
  const start = async () => {
    await page.waitForFunction(() => Array.from(document.querySelectorAll('button')).some((button) =>
      button.textContent.trim() === 'Start account recovery' && !button.disabled));
    const prepared = operationResponse(page, '/api/v1/auth/deletion/reclaim/options', 'POST');
    const preparedBody = harness.captureJSON('/api/v1/auth/deletion/reclaim/options', 'POST', 200);
    await page.getByRole('button', { name: 'Start account recovery', exact: true })
      .evaluate((button) => { button.click(); button.click(); });
    const result = await prepared;
    assert.equal(result.status(), 200);
    const selected = await preparedBody;
    assert.equal(selected.factor, totpOnly ? 'totp' : 'webauthn');
    if (!totpOnly) assert.equal(selected.webauthn.publicKey.userVerification, 'required');
  };
  await start();
  assert.equal(optionsCalls, 1, 'Duplicate start clicks allocated two ceremonies');
  if (totpOnly) {
    assert.equal(await page.getByRole('button', { name: 'Recover with a passkey', exact: true }).count(), 0);
    const input = page.getByLabel('Authenticator code', { exact: true });
    await input.waitFor();
    assert.equal(await input.getAttribute('type'), 'text');
    assert.equal(await input.getAttribute('inputmode'), 'numeric');
    await input.fill('004219');
    assert.equal(await input.inputValue(), '004219', 'Whole-code entry lost a leading zero');
    const resume = await hidePortal(page, context, evidence);
    await resume();
    await page.getByRole('button', { name: 'Start account recovery', exact: true }).waitFor();
    assert.equal(optionsCalls, 1, 'Background resume automatically retried recovery');
    assert.equal(await input.count(), 0, 'Backgrounding kept the TOTP form');
    await start();
    assert.equal(await input.inputValue(), '', 'Entered TOTP survived backgrounding');
    await input.fill('123');
    await page.getByRole('button', { name: 'Recover account', exact: true }).click();
    assert.equal(await input.getAttribute('aria-invalid'), 'true');
    assert.equal(completions, 0, 'Invalid TOTP length was submitted');
    const pattern = '**/api/v1/auth/deletion/reclaim/';
    const invalid = async (route) => route.continue({
      postData: JSON.stringify({ ...route.request().postDataJSON(), code: 'invalid-factor' }),
    });
    await page.route(pattern, invalid);
    const rejected = page.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/v1/auth/deletion/reclaim/' && response.status() === 401);
    const rejectedBody = harness.captureJSON('/api/v1/auth/deletion/reclaim/', 'POST', 401);
    await input.fill('000000');
    await page.getByRole('button', { name: 'Recover account', exact: true }).click();
    assert.equal((await rejected).status(), 401);
    assert.equal((await rejectedBody).error, 'invalid_token');
    await page.unroute(pattern, invalid);
    await page.getByRole('alert').filter({
      hasText: /The recovery link or verification could not be accepted/,
    }).waitFor({ state: 'visible' });
    await start();
    await appearance(page, evidence, 'reclaim');
    let factor = harness.fixture('reclaim-totp-code', { user_id: fixture.user_id });
    await input.fill(factor.code);
    factor = undefined;
  } else {
    assert.equal(await page.getByLabel('Authenticator code', { exact: true }).count(), 0,
      'Recovery ignored the server-selected factor');
  }
  let lost = 0;
  let interceptionFailed = false;
  const interceptions = [];
  const cdp = authenticator?.cdp;
  const loseResponse = (event) => {
    interceptions.push((async () => {
      try {
        if (event.responseStatusCode === 204) {
          lost++;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        } else await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
      } catch {
        interceptionFailed = true;
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }).catch(() => {});
      }
    })());
  };
  if (loseSuccess) {
    cdp.on('Fetch.requestPaused', loseResponse);
    await cdp.send('Fetch.enable', {
      patterns: [{ urlPattern: `${harness.origin}/api/v1/auth/deletion/reclaim/`, requestStage: 'Response' }],
    });
  }
  const outcome = page.getByTestId('reclaim-outcome');
  try {
    const completed = loseSuccess ? null : operationResponse(page, '/api/v1/auth/deletion/reclaim/', 'POST');
    await page.getByRole('button', { name: totpOnly ? 'Recover account' : 'Recover with a passkey', exact: true }).click();
    if (completed) assert.equal((await completed).status(), 204);
    await outcome.waitFor({ state: 'visible' });
    await Promise.all(interceptions);
    assert.equal(interceptionFailed, false, 'Recovery response interception failed');
    assert.equal(lost, loseSuccess ? 1 : 0);
  } finally {
    if (loseSuccess) {
      await cdp.send('Fetch.disable').catch(() => {});
      cdp.off('Fetch.requestPaused', loseResponse);
      await Promise.all(interceptions);
    }
  }
  assert.equal(await outcome.getAttribute('data-outcome'), loseSuccess ? 'unconfirmed' : 'confirmed');
  await page.waitForFunction(() => document.activeElement === document.querySelector('[data-testid="reclaim-outcome"] h2'));
  assert(await outcome.getByRole('status').isVisible(), 'Recovery result was not announced');
  const login = outcome.getByRole('link', { name: 'Sign in to your account', exact: true });
  if (loseSuccess) assert.equal(await login.count(), 0, 'Unconfirmed recovery promised a successful sign-in');
  else assert.equal(await login.getAttribute('href'), '/login');
  assert.equal(page.url(), harness.origin + '/recover-account', 'Recovery signed in automatically');
  assert.equal((await context.cookies(harness.origin)).length, 0, 'Recovery issued session state');
  assert.equal(await page.getByLabel('Authenticator code', { exact: true }).count(), 0);
  await clean(page, observed, true);
  assert.equal(completions, totpOnly ? 2 : 1, 'Recovery silently replayed a factor');
  assert(observed.anonymous >= (loseSuccess ? 1 : 2), 'Anonymous transport was not observed');
  assert(await page.evaluate((secrets) => !secrets.some((secret) =>
    document.documentElement.outerHTML.includes(secret) || JSON.stringify(history.state).includes(secret)),
  [notice.token, notice.link]), 'Recovery token entered DOM or history state');
  return { context, page, observed, authenticator };
}

async function deletionLifecycle(browser, harness, evidence, contexts) {
  const fixture = harness.fixture('seed', { credentials: 2, totp: true });
  let current = await newContext(browser, harness);
  contexts.push(current.context);
  current.page = await current.context.newPage();
  current.authenticator = await addAuthenticator(current.page, fixture.credentials[0]);
  await signIn(current.page, harness.origin);
  const tab = await current.context.newPage();
  await visit(tab, harness.origin, '/dashboard/privacy');
  await tab.getByTestId('portal-ready').waitFor({ state: 'visible' });
  const remote = await newContext(browser, harness);
  contexts.push(remote.context);
  const remotePage = await remote.context.newPage();
  await addAuthenticator(remotePage, fixture.credentials[1]);
  await signIn(remotePage, harness.origin);
  const remoteCookies = await remote.context.cookies(harness.origin);
  harness.secrets.push(...remoteCookies.map((cookie) => cookie.value));
  await current.page.bringToFront();
  await current.page.getByTestId('portal-ready').waitFor({ state: 'visible' });
  await deletionPolicy(current.page, harness, fixture, current.authenticator, evidence);
  const original = harness.fixture('deletion-state', { user_id: fixture.user_id });
  const oldAuthority = [{ page: remotePage, context: remote.context, cookies: remoteCookies }];
  await harness.stopNotifier();
  harness.mail.rejectNext(fixture.email);
  for (const [index, mode] of ['confirmed', 'lost-response', 'post-send-abort'].entries()) {
    const { page, context, authenticator, observed } = current;
    if (index > 0) {
      await signIn(page, harness.origin);
      await navigate(page, harness.origin, 'Privacy', '/dashboard/privacy');
    }
    const oldCookies = await context.cookies(harness.origin);
    harness.secrets.push(...oldCookies.map((cookie) => cookie.value));
    const siblingBroadcasts = index === 0 ? await tab.evaluate(() => globalThis.__portalBroadcasts.length) : 0;
    await deleteWithOutcome(page, harness, authenticator, mode);
    assert(!(await page.locator('body').innerText()).includes(fixture.email), 'Deletion left private account data visible');
    const pending = harness.fixture('deletion-state', { user_id: fixture.user_id });
    assert.equal(pending.status, 'pending_deletion');
    assert.equal(pending.requests, index + 1);
    assert.equal(pending.notifications, index + 1, 'Duplicate deletion enqueued duplicate notices');
    assert.equal(Date.parse(pending.expires_at) - Date.parse(pending.deleted_at), 720 * 3600 * 1000);
    assert(BigInt(pending.auth_version) > BigInt(original.auth_version));
    if (index === 0) {
      assert.equal(pending.accepted, 0, 'Stopped worker somehow accepted mail');
      assert.equal(pending.payloads, 1, 'Committed deletion lost its durable encrypted mail');
      harness.startNotifier();
      await tab.getByTestId('portal-ready').waitFor({ state: 'hidden' });
      assert.equal(await tab.evaluate(() => globalThis.__portalBroadcasts.length), siblingBroadcasts,
        'Sibling tab echoed a deletion invalidation');
    }
    const notice = await harness.mail.waitFor(fixture.email, index + 1);
    assert.equal(Date.parse(notice.expires_at), Date.parse(pending.expires_at), 'Mail changed the persisted recovery deadline');
    const stable = await harness.waitForNoticeCleanup(fixture.user_id, index + 1);
    assert.equal(stable.attempts, index + 2, 'Worker did not persist each actual relay attempt');
    assert.equal(stable.deleted_at, pending.deleted_at, 'Delivery retry reset deletion time');
    assert.equal(stable.expires_at, pending.expires_at, 'Delivery retry reset recovery expiry');
    const attempts = harness.mail.messages.filter((message) => message.recipient === fixture.email && message.message_id === notice.message_id);
    assert.equal(attempts.length, index === 0 ? 2 : 1);
    assert(attempts.every((attempt) => attempt.token === notice.token && attempt.expires_at === notice.expires_at));

    await context.addCookies(oldCookies);
    assert.equal((await api(page, '/api/v1/users/me')).status, 401, 'Old bound session survived deletion');
    await context.clearCookies();
    await remote.context.addCookies(remoteCookies);
    assert.equal((await api(remotePage, '/api/v1/users/me')).status, 401, 'Independent session survived deletion');
    assert.equal(await page.getByTestId('deletion-outcome').getAttribute('data-outcome'),
      mode === 'confirmed' ? 'confirmed' : 'unconfirmed', 'A later 401 invented a confirmed deletion');
    await clean(page, observed);
    const credential = await currentCredential(authenticator, fixture.credentials[0].credentialId);
    const totpOnly = index === 2;
    if (totpOnly) assert.equal(harness.fixture('reclaim-totp-only', { user_id: fixture.user_id }).totp_only, true);
    const recovered = await reclaimFromMail(browser, harness, fixture, notice, totpOnly ? null : credential,
      evidence, contexts, totpOnly, index === 1);
    const restored = harness.fixture('deletion-state', { user_id: fixture.user_id });
    assert.equal(restored.status, 'active');
    assert.equal(restored.deleted_at, null);
    assert(BigInt(restored.auth_version) > BigInt(pending.auth_version), 'Recovery revived old authority');
    oldAuthority.push({ page, context, cookies: oldCookies });
    for (const old of oldAuthority) {
      await old.context.addCookies(old.cookies);
      assert.equal((await api(old.page, '/api/v1/users/me')).status, 401,
        'Pre-deletion browser authority revived after recovery');
      await old.context.clearCookies();
    }
    current = recovered;
  }
  assert(harness.mail.evidence.authenticated >= 4 && harness.mail.evidence.temporary === 1 && harness.mail.evidence.accepted === 3,
    'Real authenticated SMTP retry/drain path was not exercised');
  // A used link follows the same opaque API failure, never a success inferred
  // from the account's active status. Loading it still performs no redemption.
  const last = harness.mail.messages.filter((message) => message.accepted).at(-1);
  await openReclaimLink(current.page, harness, last.link.slice(harness.origin.length));
  await current.page.waitForURL(harness.origin + '/recover-account');
  const invalid = current.page.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/v1/auth/deletion/reclaim/options' && response.status() === 401);
  const invalidBody = harness.captureJSON('/api/v1/auth/deletion/reclaim/options', 'POST', 401);
  await current.page.getByRole('button', { name: 'Start account recovery', exact: true }).click();
  assert.equal((await invalid).status(), 401);
  assert.equal((await invalidBody).error, 'invalid_token');
  await current.page.getByRole('alert').filter({
    hasText: /The recovery link or verification could not be accepted/,
  }).waitFor({ state: 'visible' });
  assert.equal(await current.page.getByTestId('reclaim-outcome').count(), 0);
  await current.page.clock.install({ time: new Date() });
  await openReclaimLink(current.page, harness, last.link.slice(harness.origin.length));
  await current.page.waitForURL(harness.origin + '/recover-account');
  await current.page.clock.fastForward(300_001);
  await current.page.getByRole('alert').filter({ hasText: /no longer holds a usable recovery link/ }).waitFor();
  assert(await current.page.getByRole('button', { name: 'Start account recovery', exact: true }).isDisabled(),
    'Recovery token survived its five-minute memory bound');
  await clean(current.page, current.observed, true);
  evidence.checks.push(
    'real UV deletion 204, worker-stopped durable enqueue and restart, verified/authenticated SMTP temporary retry with identical token/message identity/deadline; cookie clear, exactly-once neutral peer invalidation, old and independent sessions revoked before and after recovery',
    'real committed deletion with lost success and post-send background abort stays unconfirmed, clears private state, preserves browser key, never logs out or automatically replays; later 401 is not proof of success',
    'captured-mail keyless anonymous UV and TOTP recovery across replicas, fragment scrub and reload/five-minute cleanup, malformed/duplicate/used links, no auto-redemption, no cookies/DPoP/session issuance, lost real recovery success stays unconfirmed without factor replay, TOTP leading-zero entry and app-switch clearing with explicit fresh options, real invalid-factor rejection, focused outcome announcements and mobile light/dark nonce-CSP checks'
  );
}

export async function validatePortal(harness) {
  const browser = await chromium.launch({
    channel: 'chromium',
    // Trust only this ephemeral localhost certificate, not all TLS failures.
    args: [`--ignore-certificate-errors-spki-list=${harness.tlsSPKI}`],
  });
  const contexts = [];
  const evidence = {
    checks: [],
    viewports: [],
    noJavaScript: 0,
    nativeBfcacheRestoreObserved: false,
    nativeHiddenTabObserved: false,
  };
  try {
    checkpoint = 'concurrent-tabs';
    const initial = await concurrentTabs(browser, harness, evidence, contexts);
    checkpoint = 'profile-sessions';
    await profileAndSessions(browser, harness, evidence, contexts, initial);
    checkpoint = 'passkeys-totp';
    await passkeyManagement(browser, harness, evidence, contexts);
    checkpoint = 'recovery-lifecycle';
    await recoveryLifecycle(browser, harness, evidence, contexts);
    checkpoint = 'uncertain-recovery';
    await uncertainRecovery(browser, harness, evidence, contexts);
    checkpoint = 'deletion-reclaim';
    // The legacy scenarios legitimately consume the production per-subnet login
    // budget. Isolate this account lifecycle instead of disabling rate limits.
    const privacyHarness = await startPortalHarness();
    const privacyContexts = [];
    let privacyBrowser;
    try {
      privacyBrowser = await chromium.launch({
        channel: 'chromium',
        args: [`--ignore-certificate-errors-spki-list=${privacyHarness.tlsSPKI}`],
      });
      await deletionLifecycle(privacyBrowser, privacyHarness, evidence, privacyContexts);
      for (const [key, counts] of privacyHarness.routeEvidence) {
        const prior = harness.routeEvidence.get(key) || [0, 0];
        harness.routeEvidence.set(key, [prior[0] + counts[0], prior[1] + counts[1]]);
      }
      for (const key of Object.keys(harness.originEvidence)) {
        harness.originEvidence[key] += privacyHarness.originEvidence[key];
      }
    } catch (error) {
      privacyHarness.diagnostics();
      throw error;
    } finally {
      for (const context of privacyContexts) await context.close();
      await privacyBrowser?.close();
      await privacyHarness.close();
    }
    checkpoint = 'final-evidence';
    for (const [start, finish] of [
      ['/api/v1/auth/webauthn/login/generate-options', '/api/v1/auth/webauthn/login/verify'],
      ['/api/v1/auth/webauthn/register/generate-options', '/api/v1/auth/webauthn/register/verify'],
      ['/api/v1/auth/stepup/challenge', '/api/v1/auth/stepup/verify'],
      ['/api/v1/auth/deletion/reclaim/options', '/api/v1/auth/deletion/reclaim/'],
    ]) {
      assert(
        (harness.routeEvidence.get(`POST ${start}`)?.[0] || 0) > 0,
        'Ceremony did not start on replica A'
      );
      assert(
        (harness.routeEvidence.get(`POST ${finish}`)?.[1] || 0) > 0,
        'Ceremony did not finish on replica B'
      );
    }
    evidence.checks.push(
      'login, registration, UV step-up, and anonymous reclaim started on API A and finished on API B using real Redis'
    );
    assert(harness.originEvidence.unsafe > 0, 'No unsafe browser requests reached the HTTPS ingress');
    assert.equal(harness.originEvidence.mismatched, 0, 'A browser mutation suppressed or changed its Origin');
    assert.equal(harness.originEvidence.referrers, 0, 'A browser mutation disclosed a Referer');
    assert(harness.originEvidence.anonymous > 0, 'No anonymous recovery reached the ingress');
    evidence.checks.push('HTTPS ingress observed exact Origin and no Referer on unsafe DPoP and anonymous reclaim requests');
    evidence.manualGates = [
      'Assistive-technology review and platform authenticator UX',
      'Real deployed HTTPS ingress, log redaction, and downstream v1/v2 consumer rollout',
      'Independent mailbox access, SMTP sender/provider policy, bounce handling, governance-approved retention copy, and physical authenticator/assistive-technology review before deletion enablement',
      ...(!evidence.nativeBfcacheRestoreObserved
        ? ['Native bfcache restore not observed; history/pagehide cleanup was tested']
        : []),
      ...(!evidence.nativeHiddenTabObserved
        ? [
            'Native hidden-tab transition not observed; resume events were injected against the real API',
          ]
        : []),
    ];
    if (process.env.PORTAL_BROWSER_ARTIFACT_DIR) {
      const directory = resolve(process.env.PORTAL_BROWSER_ARTIFACT_DIR);
      await mkdir(directory, { recursive: true });
      await writeFile(
        resolve(directory, 'portal-evidence.json'),
        JSON.stringify(evidence, null, 2) + '\n'
      );
    }
    console.log(JSON.stringify(evidence, null, 2));
    console.log('Focused real-API production portal browser checks passed');
  } finally {
    for (const context of contexts) await context.close();
    await browser.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let harness;
  try {
    harness = await startPortalHarness();
    await validatePortal(harness);
  } catch (error) {
    harness?.diagnostics();
    console.error(browserFailure(error, checkpoint));
    process.exitCode = 1;
  } finally {
    await harness?.close();
  }
}
