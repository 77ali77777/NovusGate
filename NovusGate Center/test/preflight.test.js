const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scripts = require('../lib/scripts');
const { doneMessage } = require('../lib/run');

const GOOD_OS = 'ID=ubuntu\nVERSION_ID="22.04"\n';
const GB = 1024 * 1024; // in kB

// runPreflight runs PREFLIGHT_FN on a stubbed host and returns { code, out }.
function runPreflight({ osRelease = GOOD_OS, memKb = 4 * GB, freeKb = 20 * GB, arch = 'x86_64', busy = [], systemd = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-pre-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const stub = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'os-release'), osRelease);
    fs.writeFileSync(path.join(dir, 'meminfo'), `MemTotal:       ${memKb} kB\nMemFree:  1 kB\n`);
    stub('uname', `echo ${arch}`);
    stub('df', `echo "Filesystem 1024-blocks Used Available Capacity Mounted"\necho "/dev/sda1 100 1 ${freeKb} 1% /"`);
    // ss prints a listener when the filter names a busy port.
    stub('ss', `for p in ${busy.join(' ')}; do case "$*" in *":$p"*) echo "LISTEN 0 4096 0.0.0.0:$p 0.0.0.0:*";; esac; done`);
    if (systemd) stub('systemctl', 'exit 0');
    for (const tool of ['awk', 'grep', 'cat', 'sed']) {
      const real = spawnSync('bash', ['-c', `command -v ${tool}`]).stdout.toString().trim();
      fs.symlinkSync(real, path.join(bin, tool));
    }
    const script = `${scripts.PREFLIGHT_FN}\npreflight`;
    const r = spawnSync('/bin/bash', ['-c', script], {
      env: { PATH: bin, OS_RELEASE: path.join(dir, 'os-release'), MEMINFO: path.join(dir, 'meminfo'), PREFLIGHT_DIR: dir },
    });
    return { code: r.status, out: r.stdout.toString() + r.stderr.toString() };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('preflight passes on a supported host', () => {
  const r = runPreflight();
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /checks passed/);
  assert.strictEqual(runPreflight({ osRelease: 'ID=debian\nVERSION_ID="12"\n', arch: 'aarch64' }).code, 0);
});

test('preflight stops on an unsupported or old OS', () => {
  let r = runPreflight({ osRelease: 'ID=centos\nVERSION_ID="8"\n' });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /Unsupported OS 'centos'/);
  r = runPreflight({ osRelease: 'ID=ubuntu\nVERSION_ID="18.04"\n' });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /Ubuntu 18\.04 is too old/);
  r = runPreflight({ osRelease: 'ID=debian\nVERSION_ID="10"\n' });
  assert.match(r.out, /Debian 10 is too old/);
});

test('preflight checks memory, disk and architecture', () => {
  let r = runPreflight({ memKb: 500 * 1024 });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /RAM/);
  r = runPreflight({ memKb: 1500 * 1024 }); // enough, but the web build is slow
  assert.strictEqual(r.code, 0, r.out);
  assert.match(r.out, /\[WARN\].*RAM/);
  r = runPreflight({ freeKb: 1 * GB });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /disk/i);
  r = runPreflight({ arch: 'armv7l' });
  assert.match(r.out, /armv7l/);
  assert.notStrictEqual(r.code, 0);
});

test('preflight names every busy port and counts every problem', () => {
  const r = runPreflight({ busy: [8080, 51820], memKb: 500 * 1024 });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /TCP port 8080 is already in use/);
  assert.match(r.out, /UDP port 51820 is already in use/);
  assert.doesNotMatch(r.out, /port 3007/);
  assert.match(r.out, /3 problem\(s\)/);
});

test('preflight needs systemd', () => {
  const r = runPreflight({ systemd: false });
  assert.notStrictEqual(r.code, 0);
  assert.match(r.out, /systemd/);
});

test('the install script runs preflight before touching the host', () => {
  const s = scripts.GENERATE_INSTALL_SCRIPT({});
  const pre = s.indexOf(`preflight || {`);
  assert.ok(pre > 0, 'install must call preflight');
  assert.ok(pre < s.indexOf('apt_get update'), 'preflight must run before apt');
  assert.match(s, new RegExp(`exit ${scripts.EXIT_PREFLIGHT}`));
});

test('doneMessage explains a failed preflight', () => {
  assert.match(doneMessage(scripts.EXIT_PREFLIGHT, { install: true }), /requirements/);
});
