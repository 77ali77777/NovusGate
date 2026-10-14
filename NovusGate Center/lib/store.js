const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// createStore keeps servers.json. Every change re-reads the file and writes
// it atomically (temp file + rename), so a long job that changes one server
// at its end does not drop servers added or edited meanwhile, and a crash
// never leaves half a file. A file that is not valid JSON is never
// overwritten: load and update throw instead.
function createStore(file) {
  if (!fs.existsSync(file)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    write({ servers: [] });
  }

  function load() {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      throw new Error(`servers.json cannot be read (${err.message}); fix or restore it`);
    }
    if (!data || !Array.isArray(data.servers)) data = { servers: [] };
    return data;
  }

  function write(data) {
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  // update runs fn on the current data and saves it; fn's result is returned.
  // It is synchronous, so no other request can interleave in Node.
  function update(fn) {
    const data = load();
    const result = fn(data);
    write(data);
    return result;
  }

  // updateServer changes one server; null when it does not exist (anymore).
  function updateServer(id, fn) {
    const data = load();
    const server = data.servers.find((s) => s.id === id);
    if (!server) return null;
    fn(server);
    write(data);
    return server;
  }

  return { load, update, updateServer };
}

module.exports = { createStore };
