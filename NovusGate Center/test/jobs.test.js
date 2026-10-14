const test = require('node:test');
const assert = require('node:assert');
const { createJobLock } = require('../lib/jobs');

test('one job per server: a second start is refused until the first releases', () => {
  const jobs = createJobLock();
  const release = jobs.tryStart('a', 'install');
  assert.strictEqual(typeof release, 'function');
  assert.strictEqual(jobs.tryStart('a', 'uninstall'), null);
  assert.strictEqual(jobs.running('a'), 'install');
  release();
  assert.strictEqual(jobs.running('a'), null);
  assert.strictEqual(typeof jobs.tryStart('a', 'uninstall'), 'function');
});

test('different servers run in parallel', () => {
  const jobs = createJobLock();
  assert.ok(jobs.tryStart('a', 'install'));
  assert.ok(jobs.tryStart('b', 'install'));
});

test('release is idempotent and cannot free a newer job', () => {
  const jobs = createJobLock();
  const first = jobs.tryStart('a', 'install');
  first();
  const second = jobs.tryStart('a', 'update');
  first(); // a late second call of the old release
  assert.strictEqual(jobs.running('a'), 'update');
  second();
  assert.strictEqual(jobs.running('a'), null);
});
