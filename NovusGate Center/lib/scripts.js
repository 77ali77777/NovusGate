// ============ INSTALL SCRIPTS ============
//
// The bash lives in scripts/*.sh. A script names a value with @@NAME@@;
// render() fills every placeholder and refuses a missing or unused one, so
// a typo fails at startup instead of reaching a server.

const fs = require('fs');
const path = require('path');

const SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');

// load reads scripts/<name>. CRLF is normalized: bash on the server breaks
// on it, and a Windows checkout without .gitattributes would have it.
function load(name) {
  return fs.readFileSync(path.join(SCRIPTS_DIR, name), 'utf8').replace(/\r\n/g, '\n');
}

// render fills the @@NAME@@ placeholders of text from vars.
function render(name, text, vars) {
  const used = new Set();
  const out = text.replace(/@@([A-Z_]+)@@/g, (_, key) => {
    if (!Object.prototype.hasOwnProperty.call(vars, key)) {
      throw new Error(`scripts/${name}: no value for @@${key}@@`);
    }
    used.add(key);
    return String(vars[key]);
  });
  for (const key of Object.keys(vars)) {
    if (!used.has(key)) throw new Error(`scripts/${name}: @@${key}@@ is not used`);
  }
  return out;
}

// template loads a script once and returns a function that renders it.
function template(name) {
  const text = load(name);
  return (vars = {}) => render(name, text, vars);
}

// shellQuote makes value one literal shell word: single-quoted, with each
// embedded single quote written as '\x27'. Every value from the Center's form
// goes through it.
function shellQuote(value) {
  return "'" + String(value).split("'").join("'\\''") + "'";
}

// Shell expression for a new MASTER_KEY (64 hex characters, seals node
// private keys); falls back to /dev/urandom when openssl is missing.
const MASTER_KEY_GEN = "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -t x1 | tr -d ' \\n')";

// Shell block that gives envFile a MASTER_KEY when it has none or an empty
// one. An existing key is never replaced: keys sealed with it would be lost.
const ensureMasterKeyTemplate = template('ensure-master-key.sh');
const ensureMasterKey = (envFile) => ensureMasterKeyTemplate({ ENV_FILE: envFile, MASTER_KEY_GEN });

// Bash function that empties the install dir while keeping persistent state:
// the Postgres data directory (server/data, bind-mounted by docker-compose),
// a legacy top-level data/ directory and the admin VPN client config.
const CLEAN_INSTALL_DIR_FN = load('clean-install-dir.sh');

// Bash helpers every script starts with: compose() runs Docker Compose v2
// ("docker compose", what get.docker.com installs) and falls back to the v1
// binary; apt_get() waits up to 10 minutes for a held dpkg lock (e.g.
// unattended-upgrades on a fresh server) instead of failing at once.
const SHELL_HELPERS = load('helpers.sh');

// Exit code of the install script when NovusGate is already installed.
const EXIT_ALREADY_INSTALLED = 3;

// A fresh install regenerates the database password and the wg0 server key,
// which would lock the control plane out of the existing database and break
// every VPN client. Existing installs must use Update or Reinstall instead.
const ALREADY_INSTALLED_GUARD = template('already-installed-guard.sh')({ EXIT_ALREADY_INSTALLED });

// Exit code of the reinstall script when a database exists without its .env.
const EXIT_DB_WITHOUT_ENV = 4;

// Reinstall keeps server/data, so it must also keep the credentials that
// database was created with. Without .env (or its /tmp backup) new secrets
// would lock the control plane out of the existing database.
const REINSTALL_DB_GUARD = template('reinstall-db-guard.sh')({ EXIT_DB_WITHOUT_ENV });

// Exit code of the install script when the host fails the preflight checks.
const EXIT_PREFLIGHT = 5;

// preflight stops a fresh install early, with every reason at once, on a
// host it cannot work on: the installer is apt-based, needs systemd, room
// for the images and the ports the stack listens on. OS_RELEASE, MEMINFO
// and PREFLIGHT_DIR are overridable for tests.
const PREFLIGHT_FN = load('preflight.sh');

const installTemplate = template('install.sh');
const GENERATE_INSTALL_SCRIPT = (config) =>
  installTemplate({
    SHELL_HELPERS,
    ALREADY_INSTALLED_GUARD,
    PREFLIGHT_FN,
    EXIT_PREFLIGHT,
    MASTER_KEY_GEN,
    ADMIN_USERNAME: shellQuote(config.adminUsername || 'admin'),
    ADMIN_PASSWORD: shellQuote(config.adminPassword || ''), // empty: generated on the server
    VPN_IP: shellQuote(config.vpnIp || '10.99.0.1'),
    VPN_SUBNET: shellQuote(config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.0/24') : '10.99.0.0/24'),
    VPN_CLIENT_IP: shellQuote(config.vpnIp ? config.vpnIp.replace(/\.\d+$/, '.2') : '10.99.0.2'),
    VPN_DOMAIN: shellQuote(config.vpnDomain || ''), // empty: the server IP
    DB_NAME: shellQuote(config.dbName || 'NovusGate'),
    DB_USER: shellQuote(config.dbUser || 'NovusGate'),
    DB_PASSWORD: shellQuote(config.dbPassword || ''), // empty: generated on the server
  });

// Reinstall keeps an existing .env; the form values are used only when there
// is none.
const reinstallTemplate = template('reinstall.sh');
const GENERATE_REINSTALL_SCRIPT = (config) =>
  reinstallTemplate({
    SHELL_HELPERS,
    REINSTALL_DB_GUARD,
    CLEAN_INSTALL_DIR_FN,
    ENSURE_MASTER_KEY: ensureMasterKey('server/deployments/docker/.env'),
    MASTER_KEY_GEN,
    DB_NAME: shellQuote(config.dbName || 'NovusGate'),
    DB_USER: shellQuote(config.dbUser || 'NovusGate'),
    ADMIN_USERNAME: shellQuote(config.adminUsername || 'admin'),
    ADMIN_CIDR: shellQuote((config.vpnIp || '10.99.0.1').replace(/\.\d+$/, '.0/24')),
    DB_PASSWORD: shellQuote(config.dbPassword || ''),
    ADMIN_PASSWORD: shellQuote(config.adminPassword || ''),
  });

const UNINSTALL_SCRIPT = template('uninstall.sh')({ SHELL_HELPERS });

const UPDATE_SCRIPT = template('update.sh')({
  SHELL_HELPERS,
  CLEAN_INSTALL_DIR_FN,
  ENSURE_MASTER_KEY: ensureMasterKey('$INSTALL_DIR/server/deployments/docker/.env'),
});

// Database-only migration script (no file changes)
const DATABASE_MIGRATE_SCRIPT = template('migrate.sh')({ SHELL_HELPERS });

module.exports = {
  render,
  shellQuote,
  SHELL_HELPERS,
  MASTER_KEY_GEN,
  ensureMasterKey,
  CLEAN_INSTALL_DIR_FN,
  EXIT_ALREADY_INSTALLED,
  ALREADY_INSTALLED_GUARD,
  EXIT_DB_WITHOUT_ENV,
  REINSTALL_DB_GUARD,
  EXIT_PREFLIGHT,
  PREFLIGHT_FN,
  GENERATE_INSTALL_SCRIPT,
  GENERATE_REINSTALL_SCRIPT,
  UNINSTALL_SCRIPT,
  UPDATE_SCRIPT,
  DATABASE_MIGRATE_SCRIPT,
};
