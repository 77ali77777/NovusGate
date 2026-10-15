const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const scripts = require('../lib/scripts');
const { joinCommand } = require('../lib/join');
const { validContainerName } = require('../lib/validate');
const { sampleConfig } = require('./helpers');

// Audit 2026-10-15: findings of the Center review against the current hub.

// Join VPN on the hub itself would overwrite the hub's own wg0.conf (the
// admin VPN): the command refuses before it runs the node script.
test('joinCommand refuses to run on a NovusGate hub', () => {
  const cmd = joinCommand('/tmp/novusgate-join-ab12.sh');
  const guard = cmd.indexOf('[ -d /opt/NovusGate ]');
  assert.ok(guard >= 0 && guard < cmd.indexOf("bash '/tmp/novusgate-join-ab12.sh'"), cmd);
  assert.match(cmd, /rm -f '\/tmp\/novusgate-join-ab12\.sh'; exit 3/, 'the token file is removed on refusal too');
  assert.strictEqual(spawnSync('bash', ['-n', '-c', cmd]).status, 0, 'valid shell');
});

// Container names reach a shell over SSH: only docker's own name syntax.
test('validContainerName accepts docker names only', () => {
  for (const ok of ['novusgate-control-plane', 'novusgate_web.1', 'a1']) {
    assert.ok(validContainerName(ok), ok);
  }
  for (const bad of ['', undefined, 'x; rm -rf /', '$(id)', '`id`', '-f', 'a b', 'a|b', 'x'.repeat(200)]) {
    assert.ok(!validContainerName(bad), String(bad));
  }
});

test('the docker routes check the container name', () => {
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  for (const route of ["app.get('/api/servers/:id/docker/logs/stream'", "app.post('/api/servers/:id/docker/:action'"]) {
    const body = server.slice(server.indexOf(route), server.indexOf('\n});', server.indexOf(route)));
    assert.match(body, /validContainerName\(container\)/, route);
  }
});

// The Server page (P10a) leaves a managed sysctl file and maybe an armed
// rollback timer; uninstall removes both.
test('uninstall removes the P10a kernel settings', () => {
  const s = scripts.UNINSTALL_SCRIPT;
  assert.match(s, /systemctl stop novusgate-sysctl-rollback\.timer/);
  assert.match(s, /rm -f \/etc\/sysctl\.d\/90-novusgate\.conf/);
  assert.ok(s.indexOf('novusgate-sysctl-rollback.timer') < s.indexOf('rm -rf /etc/novusgate /var/lib/novusgate'),
    'the timer stops before its script is deleted');
});

test('install prints the https panel address and keeps VPN_IP for the credentials view', () => {
  const s = scripts.GENERATE_INSTALL_SCRIPT(sampleConfig);
  assert.match(s, /Admin Dashboard: https:\/\/\$VPN_IP:3007/);
  const env = s.slice(s.indexOf('docker/.env"'), s.indexOf('\nEOF', s.indexOf('docker/.env"')));
  assert.match(env, /^VPN_IP=\$VPN_IP$/m);
});

// A minimal Debian 12 has no curl: "curl | sh" without pipefail installed
// nothing and went on.
test('install has curl before it fetches Docker and fails when the fetch fails', () => {
  const s = scripts.GENERATE_INSTALL_SCRIPT(sampleConfig);
  assert.doesNotMatch(s, /curl -fsSL https:\/\/get\.docker\.com \| sh/);
  const ensure = s.indexOf('command -v curl');
  assert.ok(ensure >= 0 && ensure < s.indexOf('get.docker.com'), 'curl is installed first');
  assert.match(s, /curl -fsSL https:\/\/get\.docker\.com -o "\$DOCKER_SH"/);
});

// Debian 12 logs to the journal only: no /var/log/auth.log, so a logpath
// jail kept fail2ban from starting.
test('install and reinstall read sshd from the journal when there is no auth.log', () => {
  for (const s of [scripts.GENERATE_INSTALL_SCRIPT(sampleConfig), scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig)]) {
    assert.doesNotMatch(s, /^logpath = \/var\/log\/auth\.log$/m, 'no fixed logpath');
    assert.match(s, /SSHD_SOURCE="backend = systemd"/);
    assert.match(s, /python3-systemd/);
    const fn = s.match(/sshd_source\(\) \{[\s\S]*?\n\}/);
    assert.ok(fn, 'sshd_source() missing');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-f2b-'));
    try {
      fs.writeFileSync(path.join(dir, 'apt-get'), '#!/bin/bash\nexit 0\n', { mode: 0o755 });
      const run = (authLog) => spawnSync('bash', ['-c', `apt_get() { :; }\n${fn[0]}\nAUTH_LOG=${authLog} sshd_source; echo "$SSHD_SOURCE"`],
        { env: { PATH: `${dir}:/usr/bin:/bin` } }).stdout.toString().trim();
      fs.writeFileSync(path.join(dir, 'auth.log'), '');
      assert.strictEqual(run(path.join(dir, 'auth.log')), `logpath = ${path.join(dir, 'auth.log')}`);
      assert.strictEqual(run(path.join(dir, 'none.log')), 'backend = systemd');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

// /health answers 200 also when degraded, and the web container was never
// looked at: the update says so instead of a plain "complete".
test('update reports a degraded hub and a stopped web container', () => {
  const s = scripts.UPDATE_SCRIPT;
  const fn = s.match(/report_health\(\) \{[\s\S]*?\n\}/);
  assert.ok(fn, 'report_health() missing');
  assert.ok(s.indexOf('report_health') < s.indexOf('UPDATE COMPLETE'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-rh-'));
  try {
    fs.writeFileSync(path.join(dir, 'curl'), '#!/bin/bash\necho "$HEALTH_BODY"\n', { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'docker'), '#!/bin/bash\necho "$WEB_RUNNING"\n', { mode: 0o755 });
    const run = (body, web) => spawnSync('bash', ['-c', `${fn[0]}\nreport_health`],
      { env: { PATH: `${dir}:/usr/bin:/bin`, HEALTH_BODY: body, WEB_RUNNING: web } }).stdout.toString();
    const ok = run('{"status":"ok"}', 'true');
    assert.doesNotMatch(ok, /WARN/);
    assert.match(run('{"status":"degraded"}', 'true'), /WARN.*degraded/);
    assert.match(run('{"status":"ok"}', 'false'), /WARN.*novusgate-web/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Without rsync the update copied over the old tree, so deleted files
// stayed and could end up in the build.
test('update installs rsync instead of copying over the old tree', () => {
  const s = scripts.UPDATE_SCRIPT;
  assert.match(s, /command -v rsync[^\n]*\|\| apt_get install -y rsync/);
  assert.doesNotMatch(s, /cp -r "\$TEMP_DIR"\/\* "\$INSTALL_DIR\/"/);
});

// The .env holds the DB password, API key and master key: reinstall keeps it
// root-only like install does, also its copy in /tmp.
test('reinstall keeps .env readable by root only', () => {
  const s = scripts.GENERATE_REINSTALL_SCRIPT(sampleConfig);
  assert.match(s, /chmod 600 server\/deployments\/docker\/\.env/);
  assert.ok(s.indexOf('chmod 600 server/deployments/docker/.env') > s.indexOf('cat <<EOF > server/deployments/docker/.env'),
    'after the file is written or restored');
  assert.doesNotMatch(s, /^\s*cp "\$INSTALL_DIR\/server\/deployments\/docker\/\.env" \/tmp/m, 'the /tmp copy keeps its mode (cp -p)');
});
