import assert from 'node:assert/strict';
import test from 'node:test';
import { performanceInvocation, percentile95, sanitizePlan } from './geography-performance.mjs';

test('performance requires operator-provided absolute complete snapshot paths without inherited credentials', () => {
  assert.deepEqual(performanceInvocation(['--cities=/local/cities.json', '--types=/local/types.json', '--manifest=/local/manifest.json']),
    { cities: '/local/cities.json', types: '/local/types.json', manifest: '/local/manifest.json' });
  for (const args of [[], ['--cities=relative', '--types=/types', '--manifest=/manifest'],
    ['--cities=/cities', '--cities=/again', '--manifest=/manifest'],
    ['--cities=/cities', '--database=private', '--manifest=/manifest']]) assert.throws(() => performanceInvocation(args));
});

test('performance retains bounded EXPLAIN structure and timings, never source predicates or result labels', () => {
  const plan = { 'Node Type': 'Limit', 'Actual Total Time': 0.5, 'Actual Rows': 20,
    Output: ['PRIVATE_LABEL'], Plans: [{ 'Node Type': 'Index Scan', 'Index Name': 'idx_geography_localities',
      'Actual Total Time': 0.4, 'Index Cond': 'PRIVATE_LABEL', Filter: 'PRIVATE_LABEL', 'Shared Hit Blocks': 6 }] };
  const clean = sanitizePlan(plan);
  assert.equal(JSON.stringify(clean).includes('PRIVATE_LABEL'), false);
  assert.equal(clean.plans[0].index, 'idx_geography_localities');
  for (const invalid of [{ 'Node Type': 'PRIVATE_LABEL' }, { 'Node Type': 'Index Scan', 'Index Name': 'private' },
    { 'Node Type': 'Limit', 'Actual Total Time': -1 }]) assert.throws(() => sanitizePlan(invalid));
});

test('performance p95 requires exactly 100 actual nonnegative finite measurements', () => {
  assert.equal(percentile95(Array.from({ length: 100 }, (_, index) => index)), 94);
  for (const values of [[], [1], Array(99).fill(1), Array(101).fill(1), [...Array(99).fill(1), NaN],
    [...Array(99).fill(1), -1]]) assert.throws(() => percentile95(values));
});
