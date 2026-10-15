const test = require('node:test');
const assert = require('node:assert');
const { spawnSync, execFileSync } = require('node:child_process');
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

// P7: Docker Compose v2 ("docker compose") is what get.docker.com installs;
// the v1 binary is only a fallback. apt waits for a held dpkg lock
// (unattended-upgrades on a fresh server) instead of failing.
for (const [name, script] of Object.entries(generateAll(sampleConfig))) {
  test(`${name} script uses the compose and apt_get helpers`, () => {
    assert.ok(script.includes('compose() {'), 'defines compose()');
    assert.ok(script.includes('apt_get() {'), 'defines apt_get()');
    assert.doesNotMatch(script, /(^|[\s;&|(])docker-compose -f/m, 'no direct docker-compose call');
    assert.doesNotMatch(script, /(^|[\s;&|(])apt-get (update|install)/m, 'no direct apt-get call');
  });
}

test('compose() prefers docker compose v2 and falls back to docker-compose', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-compose-'));
  try {
    const run = (dockerHasV2) => {
      fs.writeFileSync(path.join(dir, 'docker'),
        `#!/bin/bash\nif [ "$1 $2" = "compose version" ]; then exit ${dockerHasV2 ? 0 : 1}; fi\necho "v2 $*"\n`, { mode: 0o755 });
      fs.writeFileSync(path.join(dir, 'docker-compose'), '#!/bin/bash\necho "v1 $*"\n', { mode: 0o755 });
      return spawnSync('bash', ['-c', `${scripts.SHELL_HELPERS}\ncompose -f x.yml up -d`],
        { encoding: 'utf8', env: { PATH: `${dir}:/usr/bin:/bin` } }).stdout.trim();
    };
    assert.strictEqual(run(true), 'v2 compose -f x.yml up -d');
    assert.strictEqual(run(false), 'v1 -f x.yml up -d');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// P7: uninstall removes NovusGate and nothing else on the host.
test('uninstall does not touch other applications', () => {
  const s = scripts.UNINSTALL_SCRIPT;
  assert.doesNotMatch(s, /docker system prune/, 'a global prune deletes other apps\' images and volumes');
  // A whole-table flush has no chain name; NOVUSGATE-ADMIN is ours to remove.
  assert.doesNotMatch(s, /iptables -t (nat|mangle|raw) -[FX]\s*$/m, 'flushing nat/mangle/raw breaks Docker networking');
  assert.doesNotMatch(s, /^iptables -[FX]\s*$/m, 'only the INPUT chain NovusGate owns is flushed');
  assert.match(s, /--rmi local/, 'only the images NovusGate built are removed');
});

test('uninstall removes every NovusGate host artifact', () => {
  const s = scripts.UNINSTALL_SCRIPT;
  for (const piece of [
    'nft delete table inet novusgate',
    'systemctl disable novusgate-firewall.service',
    'novusgate-fw-rollback.timer',
    'rm -rf /etc/novusgate /var/lib/novusgate',
    'rm -f /etc/fail2ban/jail.d/novusgate.local',
    'iptables -t mangle -X NOVUSGATE-ADMIN',
    'ip6tables -t mangle -X NOVUSGATE-ADMIN',
  ]) {
    assert.ok(s.includes(piece), `missing: ${piece}`);
  }
});

// The interfaces to remove: wg0, the networks in the database and configs
// with the PostUp line the control plane writes; never another WireGuard.
test('uninstall picks the NovusGate WireGuard interfaces only', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-wg-'));
  try {
    const ng = "PostUp = iptables -t nat -A POSTROUTING -o $(ip route get 8.8.8.8 | awk '{print $5; exit}') -j MASQUERADE\n";
    fs.writeFileSync(path.join(dir, 'wg0.conf'), '[Interface]\n');
    fs.writeFileSync(path.join(dir, 'wg3.conf'), `[Interface]\n${ng}`);
    fs.writeFileSync(path.join(dir, 'wg9.conf'), '[Interface]\nPostUp = echo mine\n'); // not ours
    fs.writeFileSync(path.join(dir, 'office.conf'), `[Interface]\n${ng}`); // not a wgN name
    const fn = scripts.UNINSTALL_SCRIPT.match(/novusgate_ifaces\(\) \{[\s\S]*?\n\}/);
    assert.ok(fn, 'novusgate_ifaces() missing');
    const out = spawnSync('bash', ['-c', `${fn[0]}\nnovusgate_ifaces '${dir}' 'wg2 wg5 eth0'`], { encoding: 'utf8' });
    assert.deepStrictEqual(out.stdout.trim().split('\n'), ['wg0', 'wg2', 'wg3', 'wg5']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// P7: a failed update rolls back to the previous version.
test('update backs up before changing files and rolls back on failure', () => {
  const s = scripts.UPDATE_SCRIPT;
  const backup = s.indexOf('tar -czf "$BACKUP_DIR/code.tar.gz"');
  const trap = s.indexOf('trap rollback ERR');
  const copy = s.indexOf('Updating files');
  const rebuild = s.indexOf('Rebuilding changed containers');
  const health = s.lastIndexOf('wait_healthy ||');
  assert.ok(backup > -1 && trap > -1 && copy > -1 && health > -1, 'backup, trap and health check present');
  assert.ok(s.indexOf('No changes detected') < backup, 'no backup when nothing changed');
  assert.ok(backup < trap && trap < copy, 'backup and trap before the files change');
  assert.ok(rebuild < health, 'health is checked after the rebuild');
  assert.ok(s.includes('pg_dump'), 'database dump kept for a manual restore');
  assert.ok(s.includes('tar -xzf "$BACKUP_DIR/code.tar.gz" -C "$INSTALL_DIR"'), 'rollback restores the code');
  assert.match(s, /set -E/, 'ERR trap reaches functions');
});

test('wait_healthy succeeds once /health answers and fails after its tries', () => {
  const fn = scripts.UPDATE_SCRIPT.match(/wait_healthy\(\) \{[\s\S]*?\n\}/);
  assert.ok(fn, 'wait_healthy() missing');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-health-'));
  try {
    // curl stub: fails until the counter file reaches $OK_AFTER calls
    fs.writeFileSync(path.join(dir, 'curl'),
      `#!/bin/bash\nn=$(( $(cat ${dir}/n 2>/dev/null || echo 0) + 1 )); echo $n > ${dir}/n\n[ "$n" -ge "$OK_AFTER" ]\n`, { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'sleep'), '#!/bin/bash\nexit 0\n', { mode: 0o755 });
    const run = (okAfter) => {
      fs.rmSync(path.join(dir, 'n'), { force: true });
      return spawnSync('bash', ['-c', `${fn[0]}\nHEALTH_TRIES=5 wait_healthy`],
        { env: { PATH: `${dir}:/usr/bin:/bin`, OK_AFTER: String(okAfter) } }).status;
    };
    assert.strictEqual(run(3), 0, 'healthy on the third try');
    assert.strictEqual(run(99), 1, 'gives up after HEALTH_TRIES');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rollback restores the backed-up code, keeps server/data and exits 1', () => {
  const s = scripts.UPDATE_SCRIPT;
  const pick = (name) => s.match(new RegExp(`${name}\\(\\) \\{[\\s\\S]*?\\n\\}`))[0];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-rollback-'));
  try {
    const inst = path.join(root, 'opt');
    const bak = path.join(root, 'bak');
    const bin = path.join(root, 'bin');
    fs.mkdirSync(path.join(inst, 'server', 'data'), { recursive: true });
    fs.mkdirSync(bak);
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(inst, 'server', 'main.go'), 'old');
    fs.writeFileSync(path.join(inst, 'server', '.env'), 'SECRET=1');
    fs.writeFileSync(path.join(inst, 'server', 'data', 'pg'), 'database');
    spawnSync('tar', ['-czf', path.join(bak, 'code.tar.gz'), '-C', inst, '--exclude=./server/data', '.']);
    // the failed update: new code, a new file, the database still there
    fs.writeFileSync(path.join(inst, 'server', 'main.go'), 'new');
    fs.writeFileSync(path.join(inst, 'server', 'added.go'), 'new');
    fs.writeFileSync(path.join(bin, 'curl'), '#!/bin/bash\nexit 0\n', { mode: 0o755 });
    const body = [pick('compose'), pick('clean_install_dir'), pick('wait_healthy'), pick('rollback')].join('\n');
    const out = spawnSync('bash', ['-c', `compose() { echo "compose $*" >> "${root}/calls"; }\n${body.replace(/^compose\(\) \{[\s\S]*?\n\}\n/, '')}\nINSTALL_DIR='${inst}'\nBACKUP_DIR='${bak}'\nrollback`],
      { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin` } });
    assert.strictEqual(out.status, 1, out.stderr);
    assert.strictEqual(fs.readFileSync(path.join(inst, 'server', 'main.go'), 'utf8'), 'old');
    assert.ok(!fs.existsSync(path.join(inst, 'server', 'added.go')), 'files of the failed version are gone');
    assert.strictEqual(fs.readFileSync(path.join(inst, 'server', '.env'), 'utf8'), 'SECRET=1');
    assert.strictEqual(fs.readFileSync(path.join(inst, 'server', 'data', 'pg'), 'utf8'), 'database');
    assert.match(fs.readFileSync(path.join(root, 'calls'), 'utf8'), /up -d --build --force-recreate/);
    assert.match(out.stdout, /previous version is running again/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// setup-firewall.sh adds a marker line and copytruncate to fail2ban's
// logrotate block; uninstall must take exactly those two lines out.
test('uninstall reverts the fail2ban logrotate change', () => {
  const line = scripts.UNINSTALL_SCRIPT.split('\n').find((l) => l.includes('/etc/logrotate.d/fail2ban') && l.includes('sed -i'));
  assert.ok(line, 'uninstall must edit /etc/logrotate.d/fail2ban');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-rot-'));
  try {
    const original = '/var/log/fail2ban.log {\n    weekly\n    create 640 root adm\n}\n';
    const patched = original.replace('{\n', '{\n    # NovusGate: keep the inode (the control plane bind-mounts this file)\n    copytruncate\n');
    const f = path.join(dir, 'fail2ban');
    fs.writeFileSync(f, patched);
    execFileSync('bash', ['-c', line.trim().replaceAll('/etc/logrotate.d/fail2ban', f)]);
    assert.equal(fs.readFileSync(f, 'utf8'), original);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The bash lives in scripts/*.sh; a placeholder without a value, or a value
// no placeholder uses, fails loudly instead of reaching a server.
test('render refuses missing and unused placeholders', () => {
  assert.strictEqual(scripts.render('x.sh', 'a=@@A@@ b=@@B@@', { A: 1, B: "'q'" }), "a=1 b='q'");
  assert.throws(() => scripts.render('x.sh', 'a=@@A@@', {}), /x\.sh: no value for @@A@@/);
  assert.throws(() => scripts.render('x.sh', 'a=1', { A: 1 }), /x\.sh: @@A@@ is not used/);
});

test('every script file is used and fully rendered', () => {
  const files = fs.readdirSync(path.join(__dirname, '..', 'scripts')).sort();
  assert.deepStrictEqual(files, [
    'already-installed-guard.sh', 'clean-install-dir.sh', 'ensure-master-key.sh', 'helpers.sh', 'install.sh',
    'migrate.sh', 'preflight.sh', 'reinstall-db-guard.sh', 'reinstall.sh', 'uninstall.sh', 'update.sh',
  ]);
  for (const s of Object.values(generateAll(sampleConfig))) {
    assert.doesNotMatch(s, /@@[A-Z_]+@@/);
  }
});
