const { endWithError } = require('./sse');
const { EXIT_ALREADY_INSTALLED, EXIT_DB_WITHOUT_ENV, EXIT_PREFLIGHT } = require('./scripts');

const send = (res, event) => res.write(`data: ${JSON.stringify(event)}\n\n`);

// runScript runs a script over an ssh2-style connection and streams its
// stdout and stderr to res as SSE events. The connection is closed in every
// case. onClose(code, output) runs when the script finished; an exec error
// ends the request instead, with its reason, and calls onError(err).
function runScript(conn, script, res, onClose, onError = () => {}) {
  conn.exec(script, (err, stream) => {
    if (err) {
      conn.end();
      endWithError(res, new Error(`Execution failed: ${err.message}`));
      onError(err);
      return;
    }
    let output = '';
    stream.on('data', (chunk) => {
      const text = chunk.toString();
      output += text;
      send(res, { text });
    });
    stream.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      output += text;
      send(res, { text, stderr: true });
    });
    stream.on('close', (code) => {
      conn.end();
      onClose(code, output);
    });
  });
}

// doneMessage tells the operator why a run failed; '' when it succeeded.
function doneMessage(code, { install }) {
  if (code === 0) return '';
  if (install && code === EXIT_ALREADY_INSTALLED) {
    return 'NovusGate is already installed on this server. Use Update or Reinstall instead.';
  }
  if (install && code === EXIT_PREFLIGHT) {
    return 'This server does not meet the requirements (see the [ERROR] lines in the log). Nothing was changed.';
  }
  if (code === EXIT_DB_WITHOUT_ENV) {
    return 'An existing database was found without its .env. Restore the .env (see the log) or remove server/data, then retry.';
  }
  return `The script stopped with exit code ${code}. See the log above.`;
}

module.exports = { runScript, doneMessage };
