const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const { ARCHIVE_EXCLUDES, newArchivePath } = require('../lib/archive');

test('install archive never ships a local server/data directory', () => {
  assert.ok(ARCHIVE_EXCLUDES.includes('--exclude=server/data'));
  assert.ok(ARCHIVE_EXCLUDES.includes('--exclude=.env'));
});

// Two installs at once used to write the same NovusGate.tar.gz: one could
// upload, or delete, the other's half-written archive.
test('every install gets its own archive file in the temp directory', () => {
  const a = newArchivePath();
  const b = newArchivePath();
  assert.notStrictEqual(a, b);
  assert.strictEqual(path.dirname(a), os.tmpdir());
  assert.match(path.basename(a), /^novusgate-[0-9a-f]+\.tar\.gz$/);
});
