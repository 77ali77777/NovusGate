const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const { sshConfig, asRoot, ptyWindow } = require('../lib/ssh');

// The terminal built its own config and dropped the key passphrase, so an
// encrypted key worked for installs but not for the terminal.
test('sshConfig keeps the key passphrase and prefers the key over a password', () => {
  const cfg = sshConfig({ host: 'h', username: 'u', privateKey: 'KEY', passphrase: 'pw', password: 'x' });
  assert.deepStrictEqual(cfg, { host: 'h', port: 22, username: 'u', readyTimeout: 30000, privateKey: 'KEY', passphrase: 'pw' });
});

test('sshConfig uses the password without a key and keeps a custom port', () => {
  const cfg = sshConfig({ host: 'h', port: 2222, username: 'u', password: 'x' });
  assert.deepStrictEqual(cfg, { host: 'h', port: 2222, username: 'u', readyTimeout: 30000, password: 'x' });
});

test('asRoot leaves root commands alone and wraps others in sudo -n', () => {
  assert.strictEqual(asRoot({ username: 'root' }, 'id -u'), 'id -u');
  assert.strictEqual(asRoot({ username: 'ubuntu' }, 'id -u'), "sudo -n bash -c 'id -u'");
});

// The wrapped command must run the script unchanged, quotes and $ included.
test('asRoot keeps the script intact through the shell', () => {
  const script = `echo "a 'b' $HOME" && printf '%s' "x"`;
  const wrapped = asRoot({ username: 'ubuntu' }, script).replace(/^sudo -n /, '');
  const direct = spawnSync('bash', ['-c', script], { encoding: 'utf8' }).stdout;
  const viaWrap = spawnSync('bash', ['-c', wrapped], { encoding: 'utf8' }).stdout;
  assert.strictEqual(viaWrap, direct);
});

test('ptyWindow accepts sane terminal sizes only', () => {
  assert.deepStrictEqual(ptyWindow({ rows: 40, cols: 120 }), { rows: 40, cols: 120, height: 0, width: 0 });
  assert.strictEqual(ptyWindow({ rows: 0, cols: 120 }), null);
  assert.strictEqual(ptyWindow({ rows: 'x', cols: 80 }), null);
  assert.strictEqual(ptyWindow({ rows: 100000, cols: 80 }), null);
  assert.strictEqual(ptyWindow(null), null);
});

// fakeClient records the config and the commands an ssh2 Client would get.
const { EventEmitter } = require('node:events');
function fakeClientClass(log) {
  return class extends EventEmitter {
    connect(cfg) { log.config = cfg; setImmediate(() => this.emit('ready')); }
    exec(command, cb) { log.commands.push(command); if (cb) cb(null, {}); }
  };
}

test('connect runs every command as root through the connection', async () => {
  const { connect } = require('../lib/ssh');
  const log = { commands: [] };
  const conn = await connect({ host: 'h', username: 'ubuntu', password: 'x' }, fakeClientClass(log));
  conn.exec('docker ps', () => {});
  assert.deepStrictEqual(log.commands, ["sudo -n bash -c 'docker ps'"]);
  assert.strictEqual(log.config.password, 'x');
});

test('connect leaves root commands unchanged', async () => {
  const { connect } = require('../lib/ssh');
  const log = { commands: [] };
  const conn = await connect({ host: 'h', username: 'root', password: 'x' }, fakeClientClass(log));
  conn.exec('docker ps', () => {});
  assert.deepStrictEqual(log.commands, ['docker ps']);
});
