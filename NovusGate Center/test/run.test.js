const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { runScript, doneMessage } = require('../lib/run');
const { EXIT_ALREADY_INSTALLED, EXIT_DB_WITHOUT_ENV } = require('../lib/scripts');

function fakeRes() {
  return {
    headersSent: true,
    chunks: [],
    ended: false,
    write(chunk) { this.chunks.push(chunk); return true; },
    end() { this.ended = true; },
  };
}
const events = (res) => res.chunks.map((c) => JSON.parse(c.replace(/^data: /, '')));

// fakeConn is an ssh2-like connection whose exec fails or runs a stream.
function fakeConn(execErr) {
  const conn = { ended: false, stream: null };
  conn.end = () => { conn.ended = true; };
  conn.exec = (script, cb) => {
    if (execErr) return cb(execErr);
    const stream = new EventEmitter();
    stream.stderr = new EventEmitter();
    conn.stream = stream;
    cb(null, stream);
  };
  return conn;
}

test('an exec error ends the connection and the request with the reason', () => {
  const conn = fakeConn(new Error('channel open failure'));
  const res = fakeRes();
  let closed = false;
  runScript(conn, 'echo hi', res, () => { closed = true; });
  assert.ok(conn.ended, 'the SSH connection must be closed');
  assert.ok(res.ended);
  assert.ok(!closed, 'onClose is only for scripts that ran');
  const last = events(res).at(-1);
  assert.deepStrictEqual(last, { done: true, success: false, message: 'Execution failed: channel open failure' });
});

test('script output is streamed and onClose gets the exit code', () => {
  const conn = fakeConn(null);
  const res = fakeRes();
  let got;
  runScript(conn, 'echo hi', res, (code, output) => { got = { code, output }; });
  conn.stream.emit('data', Buffer.from('out\n'));
  conn.stream.stderr.emit('data', Buffer.from('err\n'));
  conn.stream.emit('close', 0);
  assert.ok(conn.ended);
  assert.deepStrictEqual(got, { code: 0, output: 'out\nerr\n' });
  assert.deepStrictEqual(events(res), [{ text: 'out\n' }, { text: 'err\n', stderr: true }]);
});

test('doneMessage explains why a run failed', () => {
  assert.strictEqual(doneMessage(0, { install: true }), '');
  assert.match(doneMessage(EXIT_ALREADY_INSTALLED, { install: true }), /already installed.*Update or Reinstall/);
  assert.match(doneMessage(EXIT_DB_WITHOUT_ENV, { install: false }), /database .* without its \.env/);
  assert.match(doneMessage(1, { install: false }), /exit code 1/);
});
