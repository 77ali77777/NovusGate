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

// Server-side routing (P1): the installer's admin config routes the address
// pool (10.0.0.0/8) when the admin VPN is inside it, so a new network never
// needs a new admin config; a subnet outside the pool is routed by itself.
test('install routes the address pool in the admin config', () => {
  const line = all.install.split('\n').find((l) => l.includes('ADMIN_ROUTES=') && l.startsWith('case'));
  assert.ok(line, 'ADMIN_ROUTES is chosen by a case on VPN_SUBNET');
  assert.match(all.install, /^AllowedIPs = \$ADMIN_ROUTES$/m);
  const { execFileSync } = require('node:child_process');
  const pick = (subnet) => execFileSync('sh', ['-c', `VPN_SUBNET=${subnet}; ${line}; printf %s "$ADMIN_ROUTES"`]).toString();
  assert.strictEqual(pick('10.99.0.0/24'), '10.0.0.0/8');
  assert.strictEqual(pick('172.20.0.0/24'), '172.20.0.0/24');
});
