const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig } = require('./helpers');

function runGuard(installDir) {
  const body = `INSTALL_DIR="$1"\n${scripts.ALREADY_INSTALLED_GUARD}\necho passed`;
  return spawnSync('bash', ['-c', body, 'bash', installDir], { encoding: 'utf8' });
}

test('guard lets a fresh server through', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  const result = runGuard(dir);
  assert.strictEqual(result.status, 0, result.stderr);
  assert.match(result.stdout, /passed/);
});

test('leftovers of a failed install without .env do not block a retry', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  fs.mkdirSync(path.join(dir, 'server/deployments/docker'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'admin-vpn.conf'), '[Interface]\n');
  const result = runGuard(dir);
  assert.strictEqual(result.status, 0, result.stderr);
});

test('guard stops when NovusGate is already installed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-guard-'));
  fs.mkdirSync(path.join(dir, 'server/deployments/docker'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'server/deployments/docker/.env'), 'DB_PASSWORD=x\n');
  const result = runGuard(dir);
  assert.strictEqual(result.status, scripts.EXIT_ALREADY_INSTALLED);
  assert.strictEqual(scripts.EXIT_ALREADY_INSTALLED, 3);
  assert.match(result.stdout, /already installed/);
  assert.doesNotMatch(result.stdout, /passed/);
});

test('guard runs before any package installation or secret generation', () => {
  const script = scripts.GENERATE_INSTALL_SCRIPT(sampleConfig);
  const guard = script.indexOf('is already installed in');
  assert.ok(guard > -1, 'guard missing from install script');
  // apt_get() is defined at the top; the first call is "apt_get update".
  assert.ok(script.indexOf('apt_get update') > -1, 'apt_get update missing');
  assert.ok(guard < script.indexOf('apt_get update'), 'guard must run before apt-get');
  assert.ok(guard < script.indexOf('generate_secret()'), 'guard must run before secrets are generated');
  assert.ok(guard < script.indexOf('wg genkey'), 'guard must run before wg0 keys are generated');
});
