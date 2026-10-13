const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { generateAll, sampleConfig } = require('./helpers');

const all = generateAll(sampleConfig);

test('migrate calls the binary built by Dockerfile.control-plane', () => {
  for (const [name, script] of Object.entries(all)) {
    assert.doesNotMatch(script, /NovusGate-server/, `${name} uses the wrong binary name`);
  }
  assert.match(all.migrate, /\.\/novusgate-server migrate/);
  assert.match(all.update, /\.\/novusgate-server migrate/);
});

test('container lookups match the lowercase compose names', () => {
  for (const [name, script] of Object.entries(all)) {
    assert.doesNotMatch(script, /--filter name=NovusGate/, `${name} filters by the wrong name`);
    assert.doesNotMatch(script, /grep NovusGate/, `${name} greps the wrong name`);
  }
  const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.doesNotMatch(server, /grep NovusGate/);
});

test('update keeps admin-vpn.conf', () => {
  assert.match(all.update, /--exclude='admin-vpn\.conf'/);
});
