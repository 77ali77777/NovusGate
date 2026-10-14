const { shellQuote } = require('./scripts');

// sshConfig is the ssh2 connect config for a saved server; installs, status
// checks and the terminal all use it, so they authenticate the same way.
function sshConfig(server) {
  const config = {
    host: server.host,
    port: server.port || 22,
    username: server.username,
    readyTimeout: 30000,
  };
  if (server.privateKey) {
    config.privateKey = server.privateKey;
    if (server.passphrase) config.passphrase = server.passphrase;
  } else if (server.password) {
    config.password = server.password;
  }
  return config;
}

// asRoot runs a command as root: unchanged for root, otherwise through
// passwordless sudo (-n fails at once instead of waiting for a password).
function asRoot(server, command) {
  if (server.username === 'root') return command;
  return `sudo -n bash -c ${shellQuote(command)}`;
}

// ptyWindow validates a terminal size from the browser; null when unusable.
function ptyWindow(size) {
  if (!size) return null;
  const rows = Number(size.rows);
  const cols = Number(size.cols);
  const ok = (n) => Number.isInteger(n) && n > 0 && n <= 1000;
  if (!ok(rows) || !ok(cols)) return null;
  return { rows, cols, height: 0, width: 0 };
}

// connect opens an SSH connection whose exec runs every command as root
// (asRoot), so routes, modules and scripts need no sudo handling of their own.
function connect(server, ClientClass = require('ssh2').Client) {
  return new Promise((resolve, reject) => {
    const conn = new ClientClass();
    conn.on('ready', () => {
      const exec = conn.exec.bind(conn);
      conn.exec = (command, ...rest) => exec(asRoot(server, command), ...rest);
      resolve(conn);
    });
    conn.on('error', reject);
    conn.connect(sshConfig(server));
  });
}

// uploadText writes text to a remote file with the given mode over SFTP.
function uploadText(conn, remotePath, text, mode) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.writeFile(remotePath, text, { mode }, (writeErr) => {
        sftp.end();
        if (writeErr) reject(writeErr);
        else resolve();
      });
    });
  });
}

module.exports = { sshConfig, asRoot, ptyWindow, connect, uploadText };
