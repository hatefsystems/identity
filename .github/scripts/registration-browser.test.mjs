import assert from 'node:assert/strict';
import test from 'node:test';
import { registrationBlockers } from './registration-browser.mjs';

test('registration prerequisite gate cannot certify absent features or mutable images', async () => {
  const result = await registrationBlockers({ image: 'identity-api:latest', exists: async () => false });
  assert.equal(result.status, 'blocked');
  assert.equal(result.blockers.length, 7);
  assert(result.blockers.includes('immutable-quality-tested-api-image'));
});

test('an immutable image and future source files cannot stand in for browser evidence', async () => {
  const result = await registrationBlockers({ image: 'sha256:' + 'a'.repeat(64), exists: async () => true });
  assert.equal(result.status, 'blocked');
  assert.deepEqual(result.blockers, ['production-image-isolated-provider-and-browser-acceptance']);
});
