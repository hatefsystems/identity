import assert from 'node:assert/strict';
import { test } from 'node:test';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import {
  assertStaticAssetHeaders,
  maintenanceEntrypoints,
  maintenanceSucceeded,
  smokeImage,
  staticAssets,
  webDocumentNonce,
  assertRuntimeInventory,
} from './smoke-image.mjs';
import { portalCleanup, removeOwnedDockerResource } from './portal-harness.mjs';

const nonce = Buffer.alloc(32, 255).toString('base64');
const otherNonce = Buffer.alloc(32, 1).toString('base64');

function documentHeaders(value = nonce) {
  return new Headers({
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'private, no-cache, no-store, max-age=0, must-revalidate',
    'content-security-policy': [
      "default-src 'self'",
      `script-src 'self' 'nonce-${value}' 'strict-dynamic'`,
      "script-src-attr 'none'",
      `style-src 'self' 'nonce-${value}'`,
      "style-src-attr 'none'",
      "connect-src 'self'",
      "img-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "frame-src 'none'",
      'upgrade-insecure-requests',
    ].join('; '),
  });
}

function documentHtml(value = nonce) {
  return (
    '<!doctype html><html><head><link rel="stylesheet" href="/_next/static/app.css">' +
    `<style nonce="${value}">body { color: black; }</style></head><body>` +
    `<script nonce="${value}" src="/_next/static/app.js" async></script>` +
    `<script nonce="${value}">self.__next_f = [];</script></body></html>`
  );
}

test('maintenance smoke requires structured ERROR logging and exit one', () => {
  const good = { status: 1, stdout: '', stderr: '{"level":"ERROR","msg":"missing configuration"}' };
  assert(maintenanceSucceeded(good));
  assert(!maintenanceSucceeded({ ...good, status: 0 }));
  assert(!maintenanceSucceeded({ ...good, status: 125 }));
  assert(!maintenanceSucceeded({ ...good, status: null }));
  assert(!maintenanceSucceeded({ ...good, stderr: 'not JSON, "level":"ERROR"' }));
  assert(!maintenanceSucceeded({ ...good, stderr: '{"level":"INFO"}' }));
});

test('all packaged entrypoints are covered by the production-configuration smoke', () => {
  assert.deepEqual(maintenanceEntrypoints, [
    'identity-api', 'audit-signer', 'purge-worker', 'migrate', 'security-ledger-purge',
    'admin-audit-publisher', 'lifecycle-publisher', 'deletion-notifier', 'admin-legal', 'registration-cleanup',
  ]);
});

test('migration smoke checks its missing-database error instead of a JSON log or usage error', () => {
  const missingDatabase = {
    status: 1,
    stdout: '',
    stderr: 'migrate: migrate: DATABASE_URL is empty\n',
  };
  assert(maintenanceSucceeded(missingDatabase, 'migrate'));
  assert(!maintenanceSucceeded({ ...missingDatabase, status: 0 }, 'migrate'));
  assert(
    !maintenanceSucceeded(
      { ...missingDatabase, stderr: 'usage: migrate <up|down|reset|status>' },
      'migrate'
    )
  );
  assert(!maintenanceSucceeded({ ...missingDatabase, stderr: '{"level":"ERROR"}' }, 'migrate'));
});

test('ledger purge smoke requires its exact dedicated configuration failure, not an arbitrary ERROR', () => {
  const reason = 'config: SECURITY_LEDGER_PURGE_DATABASE_URL is required; API credentials are not a fallback';
  const good = { status: 1, stdout: JSON.stringify({ level: 'ERROR', msg: 'security ledger purge failed', reason }), stderr: '' };
  assert(maintenanceSucceeded(good, 'security-ledger-purge'));
  for (const record of [{ level: 'ERROR' }, { level: 'ERROR', msg: 'another binary failed', reason },
    { level: 'ERROR', msg: 'security ledger purge failed', reason: 'connection refused' },
    { level: 'INFO', msg: 'security ledger purge failed', reason }]) {
    assert(!maintenanceSucceeded({ ...good, stdout: JSON.stringify(record) }, 'security-ledger-purge'));
  }
  for (const status of [0, 125, null]) assert(!maintenanceSucceeded({ ...good, status }, 'security-ledger-purge'));
});

test('collects real local static assets, preserves queries, and deduplicates preloads', () => {
  const html =
    '<link href="/_next/static/app.css?v=1&amp;x=2"><script src="/_next/static/app.js"></script>' +
    '<link href="/_next/static/app.js"><script src="https://example.test/app.js"></script>' +
    '<img src="/_next/static/logo.png"><a href="/not-an-asset.js">';
  assert.deepEqual(staticAssets(html), ['/_next/static/app.css?v=1&x=2', '/_next/static/app.js']);
});

test('refuses a page without both generated CSS and JavaScript', () => {
  assert.throws(() => staticAssets('<h1>Hatef Identity Platform</h1>'), /CSS/);
  assert.throws(() => staticAssets('<link href="/_next/static/app.css">'), /JS/);
  assert.throws(
    () => staticAssets('<script src="https://example.test/_next/static/app.js"></script>'),
    /CSS/
  );
});

test('asset parser handles quoted delimiters, uppercase names, unquoted values and entities', () => {
  assert.deepEqual(
    staticAssets(
      '<LINK data-note="a > b" HREF=/_next/static/app.css>' +
        "<SCRIPT SRC='/_next/static/app.js?x=1&#38;y=2'></SCRIPT>"
    ),
    ['/_next/static/app.css', '/_next/static/app.js?x=1&y=2']
  );
});

test('asset parser does not mistake comments, data attributes or raw text for resources', () => {
  const decoys =
    '<!-- <link href="/_next/static/comment.css"><script src="/_next/static/comment.js"></script> -->' +
    '<div data-href="/_next/static/attribute.css" data-src="/_next/static/attribute.js"></div>' +
    '<script type="application/json">{"html":"<link href=/_next/static/string.css>"}</script>' +
    '<textarea><script src="/_next/static/text.js"></script></textarea>';
  assert.throws(() => staticAssets(decoys), /CSS/);
  assert.deepEqual(staticAssets(decoys + documentHtml()), [
    '/_next/static/app.css',
    '/_next/static/app.js',
  ]);
});

test('accepts a strict production document and canonical 32-byte nonce', () => {
  assert.equal(webDocumentNonce(documentHeaders(), documentHtml()), nonce);
  const headers = documentHeaders();
  headers.set(
    'content-security-policy',
    headers.get('content-security-policy').split('; ').reverse().join(' ; ') + ';'
  );
  assert.equal(webDocumentNonce(headers, documentHtml()), nonce);
});

test('HTML parser accepts equivalent attribute syntax and ignores inert script bodies', () => {
  const html =
    `<SCRIPT TYPE=module NONCE=${nonce} data-note="a > b"></SCRIPT>` +
    `<script type='text/javascript' nonce='${nonce}'></script>` +
    `<style nonce="${nonce.replaceAll('/', '&#47;')}">a::before { content: '<script>'; }</style>` +
    '<!-- <script nonce="wrong"></script><div style="color:red"></div> -->' +
    '<script type="application/json">{"html":"<script nonce=wrong>"}</script>' +
    '<script type="application/ld+json">{}</script>' +
    '<script type="text/plain">not executable</script>';
  assert.equal(webDocumentNonce(documentHeaders(), html), nonce);
});

test('requires one enforcing policy rather than duplicate or report-only headers', () => {
  const missing = documentHeaders();
  missing.set('content-security-policy-report-only', missing.get('content-security-policy'));
  missing.delete('content-security-policy');
  assert.throws(() => webDocumentNonce(missing, documentHtml()), /Missing enforcing/);
  const duplicate = documentHeaders();
  duplicate.append('content-security-policy', duplicate.get('content-security-policy'));
  assert.throws(() => webDocumentNonce(duplicate, documentHtml()), /exactly one/);
  const reportOnly = documentHeaders();
  reportOnly.set('content-security-policy-report-only', "default-src 'self'");
  assert.throws(() => webDocumentNonce(reportOnly, documentHtml()), /report-only/);
});

for (const [label, from, to] of [
  ['script unsafe-inline', "'strict-dynamic'", "'strict-dynamic' 'unsafe-inline'"],
  ['script unsafe-eval', "'strict-dynamic'", "'strict-dynamic' 'unsafe-eval'"],
  ['missing script nonce', `'nonce-${nonce}'`, ''],
  ['wildcard', "connect-src 'self'", 'connect-src *'],
  ['extra origin', "img-src 'self'", "img-src 'self' https://example.test"],
  ['development sockets', "connect-src 'self'", "connect-src 'self' ws: wss:"],
  ['inline styles', "style-src-attr 'none'", "style-src-attr 'unsafe-inline'"],
  ['style unsafe-inline', `style-src 'self' 'nonce-${nonce}'`, "style-src 'self' 'unsafe-inline'"],
  ['inline handlers', "script-src-attr 'none'", "script-src-attr 'unsafe-inline'"],
  [
    'mismatched style nonce',
    `style-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${otherNonce}'`,
  ],
  ['multiple script nonces', "'strict-dynamic'", `'strict-dynamic' 'nonce-${otherNonce}'`],
  ['duplicate source', "default-src 'self'", "default-src 'self' 'self'"],
  ['missing upgrade', '; upgrade-insecure-requests', ''],
  ['missing frame restriction', "; frame-src 'none'", ''],
  [
    'duplicate directive',
    'upgrade-insecure-requests',
    "upgrade-insecure-requests; script-src 'none'",
  ],
  [
    'overriding element directive',
    'upgrade-insecure-requests',
    "upgrade-insecure-requests; script-src-elem 'self'",
  ],
]) {
  test(`rejects production policy regression: ${label}`, () => {
    const headers = documentHeaders();
    headers.set(
      'content-security-policy',
      headers.get('content-security-policy').replace(from, to)
    );
    assert.throws(() => webDocumentNonce(headers, documentHtml()), /CSP|Production|nonce/);
  });
}

for (const value of [
  Buffer.alloc(16).toString('base64'),
  Buffer.alloc(31).toString('base64'),
  Buffer.alloc(33).toString('base64'),
  nonce.replaceAll('/', '_'),
  `${'A'.repeat(42)}B=`,
  'not-a-nonce',
]) {
  test(`rejects invalid or non-canonical nonce: ${value}`, () => {
    assert.throws(() => webDocumentNonce(documentHeaders(value), documentHtml(value)), /[Nn]once/);
  });
}

for (const [label, markup] of [
  ['unnonced inline script', '<script>globalThis.executed = true;</script>'],
  ['unnonced external script', '<script src="/_next/static/app.js"></script>'],
  ['data-nonce instead of nonce', `<script data-nonce="${nonce}"></script>`],
  ['wrong nonce', `<script nonce="${otherNonce}"></script>`],
  ['duplicate nonce', `<script nonce="wrong" nonce="${nonce}"></script>`],
  ['style element without nonce', '<style>body { color: red; }</style>'],
  ['style element with wrong nonce', `<style nonce="${otherNonce}"></style>`],
  ['style attribute even on nonced tag', `<div nonce="${nonce}" STYLE="color:red"></div>`],
  ['inline event handler', '<button onClick="alert(1)">click</button>'],
  ['unterminated script', `<script nonce="${nonce}">`],
]) {
  test(`rejects unsafe HTML: ${label}`, () => {
    assert.throws(
      () => webDocumentNonce(documentHeaders(), documentHtml() + markup),
      /nonce|Inline|Unclosed/
    );
  });
}

test('inert data blocks cannot stand in for executable framework scripts', () => {
  assert.throws(
    () => webDocumentNonce(documentHeaders(), '<script type="application/json">{}</script>'),
    /No executable scripts/
  );
});

test('requires fresh nonces for every response in a document sequence', () => {
  const seen = new Set();
  webDocumentNonce(documentHeaders(), documentHtml(), seen);
  assert.throws(() => webDocumentNonce(documentHeaders(), documentHtml(), seen), /reused/);
  webDocumentNonce(documentHeaders(otherNonce), documentHtml(otherNonce), seen);
  assert.equal(seen.size, 2);
});

for (const cache of [
  '',
  'private',
  'no-store',
  'public, no-store',
  'private, no-store, public',
  'private, no-store, max-age=60',
  'private, no-store, s-maxage=60',
]) {
  test(`rejects cacheable or incomplete document cache policy: ${cache || '(missing)'}`, () => {
    const headers = documentHeaders();
    headers.set('cache-control', cache);
    assert.throws(() => webDocumentNonce(headers, documentHtml()), /HTML must/);
  });
}

test('rejects nonce disclosure and non-HTML document responses', () => {
  const headers = documentHeaders();
  headers.set('x-nonce', nonce);
  assert.throws(() => webDocumentNonce(headers, documentHtml()), /response x-nonce/);
  headers.delete('x-nonce');
  headers.set('content-type', 'text/x-component');
  assert.throws(() => webDocumentNonce(headers, documentHtml()), /MIME/);
});

test('static assets retain immutable caching without document security headers', () => {
  const headers = new Headers({ 'cache-control': 'public, max-age=31536000, immutable' });
  assertStaticAssetHeaders(headers, '/_next/static/app.js');
  assertStaticAssetHeaders(new Headers({ 'cache-control': 'public, max-age=0' }), '/favicon.ico');
  for (const name of [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-nonce',
  ]) {
    const invalid = new Headers(headers);
    invalid.set(name, name === 'x-nonce' ? nonce : `script-src 'nonce-${nonce}'`);
    assert.throws(() => assertStaticAssetHeaders(invalid, '/_next/static/app.js'), /per-request/);
    assert.throws(() => assertStaticAssetHeaders(invalid, '/favicon.ico'), /per-request/);
  }
  for (const cache of [
    '',
    'public, max-age=0, immutable',
    'public, max-age=31536000',
    'public, max-age=31536000, immutable, no-store',
    'private, max-age=31536000, immutable',
  ]) {
    assert.throws(
      () =>
        assertStaticAssetHeaders(new Headers({ 'cache-control': cache }), '/_next/static/app.css'),
      /must/
    );
  }
});

test('rejects unsupported kinds and unsafe references without starting Docker', async () => {
  await assert.rejects(smokeImage('database', 'postgres'), /kind/);
  await assert.rejects(smokeImage('web', '--help'), /reference/);
  await assert.rejects(smokeImage('api', 'not a reference'), /reference/);
  await assert.rejects(smokeImage('web', 'identity-web:test', true), /callback/);
});

test('actual runtime inventory is exact and excludes fixture, private key and environment files', () => {
  const inventory = ['etc/ssl/certs/ca-certificates.crt', ...maintenanceEntrypoints.map((name) => `usr/local/bin/${name}`)];
  assertRuntimeInventory(inventory);
  for (const file of ['usr/local/bin/portal-fixture', 'usr/local/bin/admin-roles', '.env', 'etc/.env.production', 'etc/signing.key', 'usr/local/bin/unknown']) assert.throws(() => assertRuntimeInventory([...inventory, file]));
  assert.throws(() => assertRuntimeInventory(inventory.filter((name) => !name.endsWith('/registration-cleanup'))));
});

test('smoke ownership cleanup attempts every resource, verifies absence and never removes a foreign ID', async (t) => {
  for (const problem of ['none', 'remove-failed', 'still-present', 'foreign', 'inspection-failed', 'list-failed']) await t.test(problem, async (t) => {
    const runID = 'a'.repeat(32), ids = ['1'.repeat(64), '2'.repeat(64)], present = new Set(ids), removed = [];
    t.mock.method(childProcess, 'spawnSync', (command, args) => {
      assert.equal(command, 'docker');
      if (args[0] === 'container') return { status: problem === 'list-failed' ? 1 : 0, stdout: [...present].join('\n') };
      if (args[0] === 'inspect') return { status: problem === 'inspection-failed' && args[1] === ids[1] ? 1 : 0,
        stdout: JSON.stringify([{ Id: args[1], Config: { Labels: { 'ldp.run': problem === 'foreign' && args[1] === ids[1] ? 'foreign' : runID } } }]) };
      assert.equal(args[0], 'rm');
      const id = args.at(-1);
      removed.push(id);
      if (problem !== 'still-present' || id !== ids[1]) present.delete(id);
      return { status: problem === 'remove-failed' && id === ids[1] ? 1 : 0, stdout: '' };
    });
    syncBuiltinESMExports();
    t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    const close = portalCleanup(ids.map((id) => () => removeOwnedDockerResource({ kind: 'container', id, runID })));
    if (problem === 'none') { assert.deepEqual(await close(), { completed: true }); assert.equal(present.size, 0); }
    else await assert.rejects(close(), /cleanup did not complete/);
    if (['foreign', 'inspection-failed'].includes(problem)) assert.deepEqual(removed, [ids[0]]);
    if (['remove-failed', 'still-present'].includes(problem)) assert.deepEqual(removed, [ids[1], ids[0]]);
    if (problem === 'list-failed') assert.deepEqual(removed, []);
  });
});

test('image smoke publishes success only after every actual owned ID is retired', async (t) => {
  for (const problem of ['none', 'cleanup', 'collision', 'inventory']) await t.test(problem, async (t) => {
    const present = new Map(), created = [], removed = [], messages = [];
    t.mock.method(console, 'log', (message) => messages.push(message));
    t.mock.method(childProcess, 'spawnSync', (command, args) => {
      if (command === 'tar') return { status: 0, stdout: maintenanceEntrypoints.map((name) => `usr/local/bin/${name}`).join('\n') + (problem === 'inventory' ? '\n.env' : '') };
      assert.equal(command, 'docker');
      if (args[0] === 'image') return { status: 0, stdout: JSON.stringify([{ Id: `sha256:${'f'.repeat(64)}`, Os: 'linux', Architecture: 'amd64', Config: { User: 'nonroot:nonroot' } }]) };
      if (args[0] === 'create') {
        if (problem === 'collision' && created.length === 2) return { status: 125, stdout: '' };
        const id = String(created.length + 1).padStart(64, '0');
        const runID = args.find((item) => item.startsWith('ldp.run=')).slice('ldp.run='.length);
        const binary = args.includes('--entrypoint') ? args[args.indexOf('--entrypoint') + 1].split('/').at(-1) : 'inventory';
        present.set(id, { runID, binary }); created.push(id);
        return { status: 0, stdout: id };
      }
      if (args[0] === 'export') return { status: 0, stdout: '' };
      if (args[0] === 'start') {
        const { binary } = present.get(args.at(-1));
        if (binary === 'migrate') return { status: 1, stdout: '', stderr: 'migrate: migrate: DATABASE_URL is empty\n' };
        return { status: 1, stdout: JSON.stringify({ level: 'ERROR', msg: binary === 'security-ledger-purge' ? 'security ledger purge failed' : 'config: APP_ENV is required', reason: 'config: SECURITY_LEDGER_PURGE_DATABASE_URL is required; API credentials are not a fallback' }), stderr: '' };
      }
      if (args[0] === 'container') return { status: 0, stdout: [...present.keys()].join('\n') };
      if (args[0] === 'inspect') return { status: 0, stdout: JSON.stringify([{ Id: args[1], Config: { Labels: { 'ldp.run': present.get(args[1]).runID } } }]) };
      assert.equal(args[0], 'rm');
      const id = args.at(-1); removed.push(id); present.delete(id);
      return { status: problem === 'cleanup' && id === created.at(-1) ? 1 : 0, stdout: '' };
    });
    syncBuiltinESMExports();
    t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
    if (problem === 'none') {
      await smokeImage('api', 'identity-api:owned');
      assert.equal(messages.length, 1);
      const report = JSON.parse(messages[0]);
      assert.equal(report.cleanup.completed, true);
      assert.equal(report.status, 'passed');
      assert.equal(present.size, 0);
    } else {
      await assert.rejects(smokeImage('api', 'identity-api:owned'));
      assert.deepEqual(messages, []);
    }
    assert.deepEqual(removed, [...created].reverse(), 'Every owned resource must be attempted, never a colliding foreign name');
  });
});
