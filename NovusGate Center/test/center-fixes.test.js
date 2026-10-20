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
  const pick = (subnet, server = '203.0.113.5') =>
    execFileSync('sh', ['-c', `VPN_SUBNET=${subnet}; SERVER_IP=${server}; ${line}; printf %s "$ADMIN_ROUTES"`]).toString();
  assert.strictEqual(pick('10.99.0.0/24'), '10.0.0.0/8');
  assert.strictEqual(pick('172.20.0.0/24'), '172.20.0.0/24');
  // A hub reached at a 10.x address: its handshakes would go into the tunnel.
  assert.strictEqual(pick('10.99.0.0/24', '10.0.5.4'), '10.99.0.0/24');
});

// Server-side routing P2 at install: an optional domain names the hub in
// the admin config and in every device config (WG_SERVER_ENDPOINT), so a
// new server IP changes only a DNS record.
test('install takes an optional domain for the endpoint', () => {
  const { validateInstallConfig } = require('../lib/validate');
  assert.strictEqual(validateInstallConfig({ vpnDomain: 'vpn.example.com' }), '');
  assert.strictEqual(validateInstallConfig({ vpnDomain: '' }), '');
  for (const bad of ['http://vpn.example.com', 'vpn.example.com:51820', '1.2.3', 'a..b', "x'; reboot"]) {
    assert.notStrictEqual(validateInstallConfig({ vpnDomain: bad }), '', bad);
  }
  const withDomain = generateAll({ ...sampleConfig, vpnDomain: 'vpn.example.com' }).install;
  assert.match(withDomain, /^VPN_DOMAIN='vpn\.example\.com'$/m);
  assert.match(withDomain, /^Endpoint = \$ENDPOINT_HOST:51820$/m);
  assert.match(withDomain, /^WG_SERVER_ENDPOINT=\$ENDPOINT_HOST$/m);
  const line = withDomain.split('\n').find((l) => l.startsWith('ENDPOINT_HOST='));
  const { execFileSync } = require('node:child_process');
  const pick = (domain) => execFileSync('sh', ['-c', `VPN_DOMAIN=${domain}; SERVER_IP=203.0.113.5; ${line}; printf %s "$ENDPOINT_HOST"`]).toString();
  assert.strictEqual(pick('vpn.example.com'), 'vpn.example.com');
  assert.strictEqual(pick("''"), '203.0.113.5');
  assert.match(generateAll(sampleConfig).install, /^VPN_DOMAIN=''$/m);
});
