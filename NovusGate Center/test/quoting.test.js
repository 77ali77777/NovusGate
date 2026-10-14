const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const scripts = require('../lib/scripts');
const { validateInstallConfig } = require('../lib/validate');
const { generateAll } = require('./helpers');

// shellQuote must survive any value, including quotes, $ and backticks.
test('shellQuote round-trips through bash', () => {
  for (const v of ['plain', "it's", 'a"b', '$HOME', '`id`', 'x\y', '']) {
    const r = spawnSync('bash', ['-c', `X=${scripts.shellQuote(v)}; printf %s "$X"`], { encoding: 'utf8' });
    assert.strictEqual(r.stdout, v, `value ${JSON.stringify(v)}`);
  }
});

// Scripts generated from awkward values stay valid bash.
test('scripts stay valid bash with awkward config values', () => {
  const awkward = {
    adminUsername: "o'admin", adminPassword: 'p$a"s`s', networkName: 'n', networkCidr: '10.99.0.0/24',
    vpnIp: '10.99.0.1', dbName: 'db', dbUser: 'u', dbPassword: "d'$x",
  };
  for (const [name, script] of Object.entries(generateAll(awkward))) {
    const r = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
    assert.strictEqual(r.status, 0, `${name}: ${r.stderr}`);
  }
});

// Values end up in docker compose's .env, which interpolates $ and treats
// quotes specially, so the Center accepts only characters safe there.
test('validateInstallConfig accepts safe values and rejects the rest', () => {
  assert.strictEqual(validateInstallConfig({ adminUsername: 'admin', adminPassword: 'S3cure-pass_1!', dbName: 'NovusGate', dbUser: 'NovusGate', dbPassword: '', vpnIp: '10.99.0.1' }), '');
  for (const [field, value] of [['adminPassword', 'a$b'], ['adminPassword', "a'b"], ['dbPassword', 'a"b'], ['adminUsername', 'a b'], ['dbName', 'x`y`'], ['vpnIp', '10.99.0.300'], ['dbPassword', 'p@ss'], ['dbPassword', 'a:b'], ['dbUser', 'u%x']]) {
    assert.notStrictEqual(validateInstallConfig({ [field]: value }), '', `${field}=${value} must be rejected`);
  }
});
