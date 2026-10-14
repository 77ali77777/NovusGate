const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { sampleConfig, generateAll } = require('./helpers');

function bashSyntax(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-script-'));
  try {
    const file = path.join(dir, 'script.sh');
    fs.writeFileSync(file, script);
    return spawnSync('bash', ['-n', file], { encoding: 'utf8' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
  assert.ok(script.includes(`MASTER_KEY=${scripts.MASTER_KEY_GEN}`));
  assert.match(script, /^MASTER_KEY=\$MASTER_KEY$/m);
});

for (const name of ['reinstall', 'update']) {
  test(`${name} adds a MASTER_KEY to an .env that lacks one`, () => {
    const script = generateAll(sampleConfig)[name];
    assert.ok(script.includes('grep -q "^MASTER_KEY=."'), 'checks for a non-empty key');
    assert.ok(script.includes(scripts.MASTER_KEY_GEN), 'uses the shared generator');
  });
}

// The ensure-MASTER_KEY block, run for real: a missing or empty key gets a
// 64-hex key (also without openssl), an existing key is never touched.
test('ensureMasterKey adds, fills and keeps keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-mk-'));
  try {
    const fakeBin = path.join(dir, 'bin');
    fs.mkdirSync(fakeBin);
    fs.writeFileSync(path.join(fakeBin, 'openssl'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const env = path.join(dir, '.env');
    const run = (content, extraPath) => {
      fs.writeFileSync(env, content);
      const r = spawnSync('bash', ['-c', scripts.ensureMasterKey(env)], {
        encoding: 'utf8',
        env: { ...process.env, PATH: extraPath ? `${extraPath}:${process.env.PATH}` : process.env.PATH },
      });
      assert.strictEqual(r.status, 0, r.stderr);
      return fs.readFileSync(env, 'utf8').split('\n').filter((l) => l.startsWith('MASTER_KEY='));
    };
    for (const [content, extra] of [['A=1\n', null], ['A=1\nMASTER_KEY=\n', null], ['A=1\n', fakeBin]]) {
      const lines = run(content, extra);
      assert.strictEqual(lines.length, 1, lines.join('|'));
      assert.match(lines[0], /^MASTER_KEY=[0-9a-f]{64}$/);
    }
    const kept = `MASTER_KEY=${'ab'.repeat(32)}`;
    assert.deepStrictEqual(run(`${kept}\n`, null), [kept]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// P4b: the web reads no .env any more; scripts must not copy the API key
// into web/.env (that file was also tracked by git on the Center side).
test('no script writes the API key into web/.env', () => {
  for (const [name, script] of Object.entries(generateAll(sampleConfig))) {
    assert.doesNotMatch(script, /VITE_API_KEY=/, `${name} writes VITE_API_KEY`);
  }
});

// Container lookups match "novusgate" in any case, like the status greps.
test('container cleanup matches names case-insensitively', () => {
  for (const [name, script] of Object.entries(generateAll(sampleConfig))) {
    assert.doesNotMatch(script, /docker ps -q --filter name=/, `${name} uses a case-sensitive docker filter`);
  }
});

// setup-firewall.sh guards the admin ports in mangle PREROUTING for IPv4
// and IPv6; uninstall flushes IPv4 mangle and must remove the IPv6 guard too.
test('uninstall removes the IPv6 admin port guard', () => {
  const script = generateAll(sampleConfig).uninstall;
  assert.ok(script.includes('ip6tables -t mangle -D PREROUTING -p tcp -m multiport --dports 3007,5432,8080,8443 -j NOVUSGATE-ADMIN'));
  assert.ok(script.includes('ip6tables -t mangle -F NOVUSGATE-ADMIN'));
  assert.ok(script.includes('ip6tables -t mangle -X NOVUSGATE-ADMIN'));
});
