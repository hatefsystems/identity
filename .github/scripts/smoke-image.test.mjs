import assert from 'node:assert/strict';
import { test } from 'node:test';
import { maintenanceSucceeded, smokeImage, staticAssets } from './smoke-image.mjs';

test('maintenance smoke requires structured ERROR logging and exit one', () => {
  const good = { status: 1, stdout: '', stderr: '{"level":"ERROR","msg":"missing configuration"}' };
  assert(maintenanceSucceeded(good));
  assert(!maintenanceSucceeded({ ...good, status: 0 }));
  assert(!maintenanceSucceeded({ ...good, status: 125 }));
  assert(!maintenanceSucceeded({ ...good, status: null }));
  assert(!maintenanceSucceeded({ ...good, stderr: 'not JSON, "level":"ERROR"' }));
  assert(!maintenanceSucceeded({ ...good, stderr: '{"level":"INFO"}' }));
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

test('rejects unsupported kinds and unsafe references without starting Docker', async () => {
  await assert.rejects(smokeImage('database', 'postgres'), /kind/);
  await assert.rejects(smokeImage('web', '--help'), /reference/);
  await assert.rejects(smokeImage('api', 'not a reference'), /reference/);
});
