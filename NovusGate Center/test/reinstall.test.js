const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig } = require('./helpers');

function makeTree() {
  // A space in the path guards against unquoted variables.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ng install '));
  const dir = path.join(root, 'NovusGate');
  const write = (rel, content) => {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  };
  write('server/data/postgres/PG_VERSION', '16\n');
  write('server/data/postgres/base/1/1259', 'binary');
  write('server/go.mod', 'module x\n');
  write('server/deployments/docker/.env', 'DB_PASSWORD=x\n');
  write('web/index.html', '<html>');
  write('admin-vpn.conf', '[Interface]\n');
  write('data/keep.txt', 'k');
  write('stale.txt', 's');
  return dir;
}

function runClean(dir) {
  return spawnSync('bash', ['-c', `${scripts.CLEAN_INSTALL_DIR_FN}\nclean_install_dir "$1"`, 'bash', dir], { encoding: 'utf8' });
}

test('clean_install_dir keeps the database, top-level data and admin-vpn.conf', () => {
  const dir = makeTree();
  const result = runClean(dir);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(dir), 'install dir itself must survive');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'server/data/postgres/PG_VERSION'), 'utf8'), '16\n');
  assert.strictEqual(fs.readFileSync(path.join(dir, 'server/data/postgres/base/1/1259'), 'utf8'), 'binary');
  assert.ok(fs.existsSync(path.join(dir, 'admin-vpn.conf')));
  assert.ok(fs.existsSync(path.join(dir, 'data/keep.txt')));
  assert.ok(!fs.existsSync(path.join(dir, 'server/go.mod')));
  assert.ok(!fs.existsSync(path.join(dir, 'server/deployments')));
  assert.ok(!fs.existsSync(path.join(dir, 'web')));
  assert.ok(!fs.existsSync(path.join(dir, 'stale.txt')));
});

test('clean_install_dir on a missing directory is a no-op', () => {
  const missing = path.join(os.tmpdir(), `ng-missing-${process.pid}`);
  const result = runClean(missing);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.ok(!fs.existsSync(missing));
});

test('reinstall script uses clean_install_dir instead of the unsafe find', () => {
  const script = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  assert.match(script, /clean_install_dir "\$INSTALL_DIR"/);
  assert.doesNotMatch(script, /-maxdepth 1 ! -name 'data' ! -name '\.'/);
});

test('reinstall script backs up and restores web/.env', () => {
  const script = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  assert.match(script, /cp "\$INSTALL_DIR\/web\/\.env" \/tmp\/NovusGate\.web\.env\.bak/);
  assert.match(script, /mv \/tmp\/NovusGate\.web\.env\.bak web\/\.env/);
});
