const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

test('install archive never ships a local server/data directory', () => {
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const block = server.match(/const excludes = \[([\s\S]*?)\]\.join/);
  assert.ok(block, 'excludes array not found in server.js');
  assert.match(block[1], /'--exclude=server\/data'/);
});
