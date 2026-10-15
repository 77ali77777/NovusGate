const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createJobLogs, teeSSE } = require('../lib/joblog');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ng-jobs-'));
const at = (s) => new Date(`2026-10-15T${s}Z`);

test('a job log is a 0600 file per server, named by time and action', () => {
  const dir = tmp();
  const logs = createJobLogs(dir, () => at('09:30:05'));
  const log = logs.start('srv1', 'install', { name: 'prod', host: '203.0.113.5' });
  log.append('[INFO] hello\nADMIN PASS:  secret\n');
  log.finish(true, 0);
  const file = path.join(dir, 'srv1', '20261015-093005-install.log');
  const text = fs.readFileSync(file, 'utf8');
  assert.match(text, /^# NovusGate Center job: install on prod \(203\.0\.113\.5\), started 2026-10-15T09:30:05/);
  assert.match(text, /ADMIN PASS: {2}secret/, 'output is kept as it is (user decision)');
  assert.match(text, /# finished: success \(exit 0\)/);
  if (process.platform !== 'win32') {
    assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
    assert.strictEqual(fs.statSync(path.join(dir, 'srv1')).mode & 0o777, 0o700);
  }
});

test('two jobs in the same second get different names', () => {
  const logs = createJobLogs(tmp(), () => at('09:30:05'));
  const a = logs.start('srv1', 'update', {});
  const b = logs.start('srv1', 'update', {});
  assert.notStrictEqual(a.name, b.name);
});

test('list is newest first with action and status; open refuses other paths', () => {
  const dir = tmp();
  let clock = at('08:00:00');
  const logs = createJobLogs(dir, () => clock);
  logs.start('srv1', 'install', {}).finish(false, 5);
  clock = at('09:00:00');
  logs.start('srv1', 'join-vpn', {}); // still running: no footer
  const list = logs.list('srv1');
  assert.deepStrictEqual(list.map((j) => [j.action, j.status]), [['join-vpn', 'running'], ['install', 'failed']]);
  assert.ok(list[0].size > 0 && list[0].startedAt === '2026-10-15T09:00:00.000Z');
  assert.ok(logs.open('srv1', list[1].name));
  assert.strictEqual(logs.open('srv1', '../servers.json'), null);
  assert.strictEqual(logs.open('../x', list[1].name), null);
  assert.strictEqual(logs.open('srv1', '20261015-000000-install.log'), null);
  assert.deepStrictEqual(logs.list('nobody'), []);
});

test('teeSSE copies every streamed event into the log and finishes it', () => {
  const dir = tmp();
  const logs = createJobLogs(dir, () => at('10:00:00'));
  const log = logs.start('srv1', 'update', {});
  const written = [];
  const res = { write: (s) => written.push(s), end: () => written.push('END') };
  teeSSE(res, log);
  res.write(`data: ${JSON.stringify({ text: 'step 1\n' })}\n\n`);
  res.write(`data: ${JSON.stringify({ text: 'oops\n', stderr: true })}\n\n`);
  res.write(`data: ${JSON.stringify({ done: true, success: false, message: 'exit 3' })}\n\n`);
  res.end();
  assert.strictEqual(written.length, 4, 'the client still gets everything');
  const text = fs.readFileSync(log.path, 'utf8');
  assert.match(text, /step 1\noops\n/);
  assert.match(text, /exit 3/);
  assert.match(text, /# finished: failed/);
});

// Writing the log is best-effort: a disk that is full or not writable must
// not stop the job (or keep its server locked).
test('a log that cannot be written never throws', () => {
  const dir = tmp();
  const blocker = path.join(dir, 'file');
  fs.writeFileSync(blocker, 'not a directory');
  const logs = createJobLogs(blocker, () => at('09:30:05')); // mkdir fails
  const log = logs.start('srv1', 'install', {});
  assert.doesNotThrow(() => {
    log.append('text');
    log.finish(true, 0);
  });
  const ok = createJobLogs(dir, () => at('09:30:05')).start('srv2', 'update', {});
  fs.rmSync(path.join(dir, 'srv2'), { recursive: true }); // vanishes mid-job
  assert.doesNotThrow(() => {
    ok.append('more');
    ok.finish(false, 1);
  });
});

// A deleted server's logs go with it (they may hold its passwords).
test('remove deletes a server\'s logs', () => {
  const dir = tmp();
  const logs = createJobLogs(dir, () => at('09:30:05'));
  logs.start('srv1', 'install', {}).finish(true, 0);
  logs.remove('srv1');
  assert.strictEqual(fs.existsSync(path.join(dir, 'srv1')), false);
  assert.deepStrictEqual(logs.list('srv1'), []);
  assert.doesNotThrow(() => logs.remove('../etc'));
});
