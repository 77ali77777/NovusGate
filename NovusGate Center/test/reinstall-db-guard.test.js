const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig } = require('./helpers');

const ENV_BACKUP = '/tmp/NovusGate.env.bak';

function runGuard(installDir) {
  const body = `INSTALL_DIR="$1"\n${scripts.REINSTALL_DB_GUARD}\necho passed`;
  return spawnSync('bash', ['-c', body, 'bash', installDir], { encoding: 'utf8' });
}

function makeDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ng-dbguard-'));
}

function addDatabase(dir) {
  fs.mkdirSync(path.join(dir, 'server/data/postgres'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'server/data/postgres/PG_VERSION'), '16\n');
}

test('reinstall guard lets a server without a database through', () => {
  const result = runGuard(makeDir());
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /passed/);
});

test('reinstall guard lets a database with its .env through', () => {
  const dir = makeDir();
  addDatabase(dir);
  fs.mkdirSync(path.join(dir, 'server/deployments/docker'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'server/deployments/docker/.env'), 'DB_PASSWORD=x\n');
  const result = runGuard(dir);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /passed/);
});

test('reinstall guard stops when a database exists without any .env', (t) => {
  if (fs.existsSync(ENV_BACKUP)) {
    t.skip(`${ENV_BACKUP} exists on this host, the no-.env case cannot be reproduced`);
    return;
  }
  const dir = makeDir();
  addDatabase(dir);
  const result = runGuard(dir);
  assert.strictEqual(result.status, scripts.EXIT_DB_WITHOUT_ENV);
  assert.strictEqual(scripts.EXIT_DB_WITHOUT_ENV, 4);
  assert.match(result.stdout, /no \.env to go with it/);
  assert.doesNotMatch(result.stdout, /passed/);
});

test('reinstall runs the database guard before anything is stopped or deleted', () => {
  const script = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  const guard = script.indexOf('no .env to go with it');
  assert.ok(guard > -1, 'guard missing from reinstall script');
  assert.ok(
    script.indexOf('compose -f server/deployments/docker/docker-compose.yml down') > -1 &&
      guard < script.indexOf('compose -f server/deployments/docker/docker-compose.yml down'),
    'guard must run before the stack is stopped'
  );
  assert.ok(guard < script.indexOf('clean_install_dir "$INSTALL_DIR"'), 'guard must run before files are removed');
  assert.ok(guard < script.indexOf('cp -p "$INSTALL_DIR/server/deployments/docker/.env"'), 'guard must run before the .env backup');
});
