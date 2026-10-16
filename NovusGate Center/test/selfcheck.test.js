const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { centerStale } = require('../lib/selfcheck');

// The Center runs the copy of its files baked into its image; after a
// `git pull` the project folder may be newer, and Install/Update would still
// use the old scripts. centerStale finds that so the Center can say so.
function tree(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-self-'));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

test('centerStale is empty when the image matches the folder', () => {
  const files = { 'server.js': 'a\n', 'scripts/update.sh': 'u\n', 'lib/x.js': 'x\n', 'public/index.html': 'h\n' };
  const app = tree(files);
  const live = tree({ ...files, 'scripts/update.sh': 'u\r\n' }); // a Windows checkout
  assert.deepStrictEqual(centerStale(app, live), []);
});

test('centerStale lists changed, added and removed files', () => {
  const app = tree({ 'server.js': 'a\n', 'scripts/update.sh': 'old\n', 'lib/gone.js': 'g\n' });
  const live = tree({ 'server.js': 'a\n', 'scripts/update.sh': 'new\n', 'lib/new.js': 'n\n', 'test/t.js': 'ignored\n' });
  assert.deepStrictEqual(centerStale(app, live), ['lib/gone.js', 'lib/new.js', 'scripts/update.sh']);
});

test('centerStale is empty when the project folder is not mounted', () => {
  const app = tree({ 'server.js': 'a\n' });
  assert.deepStrictEqual(centerStale(app, path.join(app, 'no-such-dir')), []);
});

test('the Center warns in the job log and on its page', () => {
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/center\/status'/);
  const install = server.slice(server.indexOf("app.post('/api/servers/:id/install'"));
  assert.match(install.slice(0, install.indexOf('\n});')), /centerStale\(/, 'Install/Update/Reinstall log the warning');
  const page = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  assert.match(page, /fetch\('\/api\/center\/status'\)/);
});

// The Center's data/ holds the saved servers (SSH passwords and keys) and
// job logs; the running Center creates data/jobs as root 0700, so a rebuild
// failed with "permission denied" — and before that the saved servers were
// copied into the image. The build context leaves them out.
test('the Center image does not take data/ or node_modules', () => {
  const ignore = fs.readFileSync(path.join(__dirname, '..', '.dockerignore'), 'utf8').split(/\r?\n/);
  for (const entry of ['data', 'node_modules']) assert.ok(ignore.includes(entry), `.dockerignore lists ${entry}`);
});
