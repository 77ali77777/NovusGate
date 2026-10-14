const { shellQuote } = require('./scripts');

// Join VPN runs the node install script the panel generates (Nodes →
// Connect → Linux → Generate install script) on a saved server. The script
// carries a one-time, 15-minute enrollment token.
const SCRIPT_HEADER = '#!/bin/bash\n# NovusGate node installer.';
const MAX_SCRIPT_BYTES = 256 * 1024;

// validateJoinScript returns '' for a usable script, else the reason.
function validateJoinScript(script) {
  if (typeof script !== 'string' || script.trim() === '') {
    return 'Paste the install script from the panel (Nodes → Connect → Linux → Generate install script).';
  }
  if (Buffer.byteLength(script) > MAX_SCRIPT_BYTES) {
    return 'The script is too large to be a NovusGate install script.';
  }
  if (!normalizeScript(script).startsWith(SCRIPT_HEADER)) {
    return 'This is not a NovusGate node install script. Generate it in the panel and paste it unchanged.';
  }
  return '';
}

// normalizeScript drops Windows line endings a paste may add.
function normalizeScript(script) {
  return script.replace(/\r\n/g, '\n');
}

// joinCommand runs the uploaded script and removes it whatever the result,
// so the token does not stay on disk; the script's exit code is kept.
function joinCommand(remotePath) {
  const p = shellQuote(remotePath);
  return `bash ${p}; rc=$?; rm -f ${p}; exit $rc`;
}

module.exports = { validateJoinScript, normalizeScript, joinCommand };
