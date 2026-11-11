import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { chromium } from 'playwright';
import { createDemoRenderer } from './page-gallery-demo.mjs';

const font = await readFile(new URL('../../apps/web/app/fonts/Vazirmatn[wght].woff2', import.meta.url));
const secret = 'private-value-do-not-export';
const email = 'source.actor@example.invalid';
const actor = 'a17342b8-5138-4b76-a55f-ef28dd5582e1';
const recovery = 'ABCD-9876-XYZZ';
const registry = [secret, email, actor, recovery, 'localhost', 'required'];
let sourceBrowser, renderer, rendererBrowser;
const launch = chromium.launch.bind(chromium);
let screenshots = 0, snapshots = 0, failScreenshot = false;
try {
  sourceBrowser = await launch({ headless: true });
  const context = await sourceBrowser.newContext({ viewport: { width: 600, height: 500 } });
  await context.addCookies([{ name: 'private-auth', value: secret, domain: 'source.example.test', path: '/' }]);
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/font.woff2') await route.fulfill({ contentType: 'font/woff2', body: font });
    else if (url.pathname === '/style.css') await route.fulfill({ contentType: 'text/css', body: '@font-face{font-family:persianFont;src:url("/font.woff2") format("woff2");font-weight:100 900;font-display:swap}@font-face{font-family:persianFontFallback;src:local("Unavailable Demo Fallback")}html[lang="fa-IR"] body{font-family:persianFont}body{margin:0;background:white;color:navy;font:18px sans-serif}.dark body{background:navy;color:white}main{height:1400px;padding:12px}.scroller{width:350px;height:120px;overflow:auto}table{width:1000px}td,th{min-width:180px;padding:10px;border:1px solid navy}dialog{width:400px;max-height:280px;overflow:auto}dialog::backdrop{background:rgba(0,0,100,.2)}.spacer{height:800px}' });
    else await route.fulfill({ contentType: 'text/html', body: `<!doctype html><html class="source-class"><head><meta charset="utf-8"><link rel="stylesheet" href="/style.css"><script nonce="private-nonce">window.sourceMarker=1</script><script type="application/json">{"secret":"${secret}"}</script></head><body class="body-class"><main><h1>Account review</h1><p>Public narrative remains readable.</p><section><h2 id="overview-profile">Unregistered Display Name</h2><dl><dt>Primary email</dt><dd>${email}</dd><dt>Account status</dt><dd>active</dd></dl><button aria-label="View Unregistered Display Name" onclick="alert('${secret}')">View account</button></section><label>Email<input name="email" value="stale@example.invalid"></label><input name="empty" value="${secret}"><input type="password" name="password"><textarea>${secret}</textarea><select><option value="en">English</option><option value="fa-IR">Persian</option></select><label><input type="checkbox" name="review">I reviewed the request</label><p data-testid="recovery-status">You have <strong>8</strong> recovery codes remaining.</p><div data-testid="passkey-row"><h3>Unregistered Passkey</h3><p>Created <time datetime="2025-03-01T00:00:00Z">March 1, 2025</time>. Never used.</p><p>Synced passkey. User verified.</p><button aria-label="Rename Unregistered Passkey">Rename</button></div><pre>{"actor":"${actor}","private":"${secret}"}</pre><code data-testid="recovery-code">${recovery}</code><details open><summary>Technical details</summary><dl><dt>Reason</dt><dd>Unregistered private narrative</dd></dl></details><div class="scroller"><table><thead><tr><th>Account</th><th>Email</th><th>Action</th></tr></thead><tbody><tr data-session-id="opaque-unregistered-session"><th><a href="/admin/users/${actor}?token=${secret}" aria-label="View ${actor}"><bdi>${actor}</bdi></a></th><td>${email}</td><td><button>View details</button></td></tr></tbody></table></div><dialog aria-label="Native review"><h2>Native review</h2><label><input type="checkbox" name="modal-check">I reviewed this dialog</label><p>Keep this public dialog description.</p><div class="spacer"></div><label>Authenticator<input name="otp"></label><button>Confirm request</button></dialog></main></body></html>` });
  });
  const source = await context.newPage();
  await source.goto('https://source.example.test/');
  await source.evaluate(({ email, secret }) => {
    document.querySelector('input[name="email"]').value = email;
    document.querySelector('input[name="empty"]').value = '';
    document.querySelector('input[name="password"]').value = secret;
    document.querySelector('textarea').value = 'Unsaved private reason';
    document.querySelector('select').value = 'fa-IR';
    document.querySelector('[name="review"]').checked = true;
    document.querySelector('details dd').title = 'Unregistered private narrative';
    const note = document.createElement('p');
    note.textContent = 'localhost required';
    document.querySelector('main').append(note);
    const link = document.createElement('a');
    link.href = '/admin/users/unregistered-private-actor?token=unregistered-bearer';
    link.textContent = 'View another account';
    document.querySelector('main').append(link);
    const sheet = new CSSStyleSheet();
    sheet.replaceSync('h1{font-weight:700}');
    document.adoptedStyleSheets = [sheet];
    document.hiddenEvents = 0;
    document.addEventListener('visibilitychange', () => { if (document.hidden) document.hiddenEvents++; });
  }, { email, secret });
  const evaluate = source.evaluate.bind(source);
  source.evaluate = async (fn, args) => {
    const result = await evaluate(fn, args);
    if (result?.html) {
      snapshots++;
      for (const value of registry.slice(0, 4)) assert(!result.html.includes(value), 'Secret bytes in returned snapshot');
      assert(!result.html.includes('opaque-unregistered-session'));
      assert(!result.html.includes('Unregistered Passkey'));
      assert(!result.html.includes('Unregistered Display Name'));
      assert(!result.html.includes('Unregistered private narrative'));
      assert(!result.html.includes('Unsaved private reason'));
      assert(!result.html.includes('unregistered-private-actor'));
      assert(!result.html.includes('unregistered-bearer'));
      assert(!result.html.includes('<script'));
      assert(!result.html.includes('nonce='));
      assert(!result.html.includes('onclick='));
      assert(result.html.includes('Public narrative remains readable.'));
      assert(result.html.includes('localhost required'));
      assert(result.html.includes('Synced passkey. User verified.'));
      assert(result.html.includes('Technical details'));
      assert(result.html.includes('View details'));
      assert(result.html.includes('data:font/woff2;base64,'));
      assert(result.html.includes('demo.user@example.test'));
      assert(result.html.includes('DEMO-0001-0001'));
      assert(result.html.includes('"actor":'));
      assert(result.html.includes('"private":'));
    }
    return result;
  };
  chromium.launch = async options => {
    const browser = await launch(options);
    rendererBrowser = browser;
    const newContext = browser.newContext.bind(browser);
    browser.newContext = async options => {
      assert.equal(options.bypassCSP, false);
      assert.equal(options.offline, true);
      const context = await newContext(options);
      const newPage = context.newPage.bind(context);
      context.newPage = async () => {
        const page = await newPage();
        let requests = 0;
        page.on('request', () => requests++);
        const screenshot = page.screenshot.bind(page);
        page.screenshot = async options => {
          if (failScreenshot) throw new Error(secret);
          assert(!('mask' in options) && !('maskColor' in options) && !('style' in options));
          assert.equal((await context.cookies()).length, 0);
          const state = await page.evaluate(() => ({
            text: document.body.innerText,
            htmlClass: document.documentElement.className,
            bodyClass: document.body.className,
            email: document.querySelector('[name="email"]').value,
            empty: document.querySelector('[name="empty"]').value,
            password: document.querySelector('[name="password"]').value,
            textarea: document.querySelector('textarea').value,
            select: document.querySelector('select').value,
            checked: document.querySelector('[name="review"]').checked,
            modal: document.querySelector('dialog').matches(':modal'),
            dialogScroll: document.querySelector('dialog').scrollTop,
            tableScroll: document.querySelector('.scroller').scrollLeft,
            windowScroll: window.scrollY,
            font: getComputedStyle(document.body).fontFamily,
            loaded: [...document.fonts].some(font => font.family === 'persianFont' && font.status === 'loaded'),
            language: document.documentElement.lang,
            sourceMarker: window.sourceMarker,
            timeDirection: document.querySelector('time').dir,
          }));
          assert.equal(state.email, 'demo.user@example.test');
          assert.equal(state.empty, '');
          assert.equal(state.password, 'DEMO-PASSWORD');
          assert.equal(state.textarea, 'Demo review request');
          assert.equal(state.select, 'fa-IR');
          assert.equal(state.checked, true);
          assert.equal(state.sourceMarker, undefined);
          assert.equal(state.timeDirection, 'ltr');
          assert(state.htmlClass.includes('source-class'));
          assert.equal(state.bodyClass, 'body-class');
          assert.equal(state.tableScroll, state.language === 'fa-IR' ? -250 : 250);
          if (state.modal) assert.equal(state.dialogScroll, 350);
          else assert.equal(state.windowScroll, 180);
          if (state.language === 'fa-IR') {
            assert.equal(state.font, 'persianFont');
            assert.equal(state.loaded, true);
          }
          assert.equal(requests, 0);
          const png = await screenshot(options);
          assert(png.length > 1000);
          for (const value of registry.slice(0, 4)) assert(!png.includes(Buffer.from(value)));
          screenshots++;
          return png;
        };
        return page;
      };
      return context;
    };
    return browser;
  };
  renderer = await createDemoRenderer();
  chromium.launch = launch;
  const sourceState = () => evaluate(() => ({ html: document.documentElement.outerHTML, email: document.querySelector('[name="email"]').value,
    empty: document.querySelector('[name="empty"]').value, password: document.querySelector('[name="password"]').value,
    textarea: document.querySelector('textarea').value, checked: document.querySelector('[name="review"]').checked,
    top: window.scrollY, table: document.querySelector('.scroller').scrollLeft, dialog: document.querySelector('dialog').scrollTop,
    marker: window.sourceMarker, hiddenEvents: document.hiddenEvents }));
  for (const locale of ['en', 'fa-IR']) for (const theme of ['light', 'dark']) for (const modal of [false, true]) {
    await evaluate(async ({ locale, modal }) => {
      document.documentElement.lang = locale;
      document.documentElement.dir = locale === 'fa-IR' ? 'rtl' : 'ltr';
      void document.body.offsetWidth;
      await document.fonts.ready;
      await document.fonts.load('16px persianFontFallback').catch(() => {});
      document.querySelector('.scroller').style.direction = locale === 'fa-IR' ? 'rtl' : 'ltr';
      const dialog = document.querySelector('dialog');
      if (dialog.open) dialog.close();
      if (modal) { dialog.showModal(); dialog.scrollTop = 350; }
      else window.scrollTo(0, 180);
      document.querySelector('.scroller').scrollLeft = locale === 'fa-IR' ? -250 : 250;
    }, { locale, modal });
    const before = await sourceState();
    const png = await renderer.capture(source, { selectors: ['main dd', 'main bdi', '#overview-profile', '[data-testid="passkey-row"] h3',
      '[data-testid="passkey-row"] p', '[data-testid="recovery-status"]', 'main time', 'main details', 'tbody td', 'tbody th'],
      privateValues: registry, locale, fullPage: !modal, viewport: { width: 600, height: 500 }, theme });
    assert(modal ? png.readUInt32BE(16) === 600 : png.readUInt32BE(16) >= 600);
    assert(modal ? png.readUInt32BE(20) === 500 : png.readUInt32BE(20) > 500);
    assert(isDeepStrictEqual(await sourceState(), before), 'Source document or authority changed');
    assert.equal(rendererBrowser.contexts().length, 0);
  }
  assert.equal(snapshots, 8);
  assert.equal(screenshots, 8);
  await assert.rejects(renderer.capture(source, { selectors: ['['], privateValues: registry, locale: 'en', fullPage: true,
    viewport: { width: 600, height: 500 }, theme: 'light' }), /^Error: Demo capture unavailable; private diagnostics suppressed\.$/);
  failScreenshot = true;
  await assert.rejects(renderer.capture(source, { selectors: ['main dd', 'main bdi', '#overview-profile', '[data-testid="passkey-row"] h3',
    '[data-testid="passkey-row"] p', '[data-testid="recovery-status"]', 'main time', 'main details', 'tbody td', 'tbody th'],
    privateValues: registry, locale: 'fa-IR', fullPage: false, viewport: { width: 600, height: 500 }, theme: 'dark' }),
    /^Error: Demo capture unavailable; private diagnostics suppressed\.$/);
  assert.equal(rendererBrowser.contexts().length, 0);
  console.log('Demo renderer: 8 isolated bilingual/theme/modal captures, sanitized snapshots, local Persian font, native dialogs, scroll mirroring, zero network/cookies, unchanged source passed.');
} finally {
  chromium.launch = launch;
  try {
    if (renderer) { await renderer.close(); await renderer.close(); }
    if (rendererBrowser) assert.equal(rendererBrowser.isConnected(), false);
  }
  finally { if (sourceBrowser) await sourceBrowser.close(); }
}
