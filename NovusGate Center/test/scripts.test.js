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
