const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Center shows the release from its package.json (the same number as the
// panel and the control plane: web/tests/version.test.mjs), never a literal.
const root = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('/api/health reports the package.json version', () => {
  const server = read('server.js');
  assert.match(server, /require\('\.\/package\.json'\)\.version/);
  assert.doesNotMatch(server, /version: '\d+\.\d+\.\d+'/);
});

test('the page shows the version it gets from /api/health', () => {
  const page = read('public/index.html');
  assert.doesNotMatch(page, /NovusGate Center v\d/);
  assert.match(page, /id="appVersion"/);
  assert.match(page, /fetch\('\/api\/health'\)/);
});
