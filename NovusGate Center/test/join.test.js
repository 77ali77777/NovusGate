const test = require('node:test');
const assert = require('node:assert');
const { validateJoinScript, joinCommand } = require('../lib/join');
const { uploadText } = require('../lib/ssh');

const SCRIPT = '#!/bin/bash\n# NovusGate node installer. The enrollment token in it works once, for 15\necho hi\n';

// B10: join-vpn runs the install script the panel generates
// (Nodes → Connect → Linux → Generate install script).
test('validateJoinScript accepts the panel install script', () => {
  assert.strictEqual(validateJoinScript(SCRIPT), '');
  assert.strictEqual(validateJoinScript(SCRIPT.replace(/\n/g, '\r\n')), '', 'pasted with Windows line endings');
});

test('validateJoinScript refuses anything else', () => {
  assert.match(validateJoinScript(''), /paste/i);
  assert.match(validateJoinScript(undefined), /paste/i);
  assert.match(validateJoinScript('#!/bin/bash\nrm -rf /\n'), /NovusGate node install script/);
  assert.match(validateJoinScript(SCRIPT + 'x'.repeat(300 * 1024)), /too large/);
});

test('joinCommand runs the uploaded file and removes it, keeping the exit code', () => {
  const cmd = joinCommand('/tmp/novusgate-join-ab12.sh');
  // After the hub guard (center-audit.test.js).
  assert.ok(cmd.endsWith("; bash '/tmp/novusgate-join-ab12.sh'; rc=$?; rm -f '/tmp/novusgate-join-ab12.sh'; exit $rc"), cmd);
});

test('uploadText writes the text with the given mode over SFTP', async () => {
  const written = {};
  const conn = {
    sftp(cb) {
      cb(null, {
        writeFile(p, data, opts, done) { Object.assign(written, { p, data, opts }); done(null); },
        end() { written.ended = true; },
      });
    },
  };
  await uploadText(conn, '/tmp/x.sh', 'abc', 0o700);
  assert.deepStrictEqual(written, { p: '/tmp/x.sh', data: 'abc', opts: { mode: 0o700 }, ended: true });
});
