const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../lib/store');

function tmpFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-store-'));
  return path.join(dir, 'servers.json');
}

test('a new store starts with no servers and creates the file', () => {
  const file = tmpFile();
  const store = createStore(file);
  assert.deepStrictEqual(store.load(), { servers: [] });
  assert.ok(fs.existsSync(file));
});

// The install route used to load at the start and save at the end of a
// minutes-long run, dropping servers added meanwhile (lost update).
test('updateServer re-reads the file, so a long job does not drop other changes', () => {
  const store = createStore(tmpFile());
  store.update((d) => d.servers.push({ id: 'a', name: 'A', history: [] }));
  // another request adds a server while a job on "a" runs
  store.update((d) => d.servers.push({ id: 'b', name: 'B', history: [] }));
  const updated = store.updateServer('a', (s) => { s.status = 'installed'; });
  assert.strictEqual(updated.status, 'installed');
  assert.deepStrictEqual(store.load().servers.map((s) => s.id), ['a', 'b']);
});

test('updateServer returns null for an unknown or deleted server and writes nothing', () => {
  const file = tmpFile();
  const store = createStore(file);
  const before = fs.readFileSync(file, 'utf8');
  assert.strictEqual(store.updateServer('missing', () => assert.fail('must not run')), null);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), before);
});

test('writes are atomic: no temp files are left and the JSON is complete', () => {
  const file = tmpFile();
  const store = createStore(file);
  for (let i = 0; i < 20; i++) store.update((d) => d.servers.push({ id: String(i) }));
  assert.strictEqual(JSON.parse(fs.readFileSync(file, 'utf8')).servers.length, 20);
  assert.deepStrictEqual(fs.readdirSync(path.dirname(file)), ['servers.json']);
});

test('a corrupt file is not overwritten with an empty list', () => {
  const file = tmpFile();
  fs.writeFileSync(file, '{"servers": [ {"id": "x"');
  const store = createStore(file);
  assert.throws(() => store.load(), /servers.json/);
  assert.throws(() => store.update(() => {}), /servers.json/);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), '{"servers": [ {"id": "x"');
});
