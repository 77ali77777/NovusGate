const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { sampleConfig, generateAll } = require('./helpers');

function bashSyntax(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-script-'));
  const file = path.join(dir, 'script.sh');
  fs.writeFileSync(file, script);
  return spawnSync('bash', ['-n', file], { encoding: 'utf8' });
}

for (const [name, script] of Object.entries(generateAll(sampleConfig))) {
  test(`${name} script is valid bash`, () => {
    const result = bashSyntax(script);
    assert.strictEqual(result.status, 0, result.stderr);
  });
}

// P4c: node private keys are sealed with MASTER_KEY; every path that writes
// or keeps the server .env must make sure it has one (64 hex characters).
test('install writes a MASTER_KEY into the server .env', () => {
  const script = generateAll(sampleConfig).install;
  assert.match(script, /MASTER_KEY=\$\(openssl rand -hex 32\)/);
  assert.match(script, /^MASTER_KEY=\$MASTER_KEY$/m);
});

for (const name of ['reinstall', 'update']) {
  test(`${name} adds a MASTER_KEY to an .env that lacks one`, () => {
    const script = generateAll(sampleConfig)[name];
    assert.match(script, /grep -q "\^MASTER_KEY=" [^\n]*\.env/);
    assert.match(script, /echo "MASTER_KEY=\$\(openssl rand -hex 32\)" >> [^\n]*\.env/);
  });
}
