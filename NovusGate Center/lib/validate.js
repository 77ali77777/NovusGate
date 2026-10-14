// Install values end up in shell scripts and in docker compose's .env, which
// interpolates "$" and treats quotes, spaces and "#" specially. Only
// characters that are literal in both are accepted.
const SAFE_VALUE = /^[A-Za-z0-9._@%+=:,!^*~-]*$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

// DB values are also written into DATABASE_URL (postgres://user:pass@host/db),
// where @ : / ? # % would change the URL: only URL-unreserved characters.
const URL_SAFE_VALUE = /^[A-Za-z0-9._~-]*$/;

const SAFE_FIELDS = ['adminUsername', 'adminPassword'];
const DB_FIELDS = ['dbName', 'dbUser', 'dbPassword'];

// validateInstallConfig returns '' when config is usable, else the reason.
function validateInstallConfig(config) {
  for (const field of DB_FIELDS) {
    const value = config[field];
    if (value !== undefined && value !== null && !URL_SAFE_VALUE.test(String(value))) {
      return `${field} may only contain letters, digits and . _ ~ - (it is part of the database URL)`;
    }
  }
  for (const field of SAFE_FIELDS) {
    const value = config[field];
    if (value !== undefined && value !== null && !SAFE_VALUE.test(String(value))) {
      return `${field} may only contain letters, digits and . _ @ % + = : , ! ^ * ~ - (no spaces, quotes, $, # or backslashes)`;
    }
  }
  if (config.vpnIp && !IPV4.test(config.vpnIp)) {
    return 'vpnIp must be an IPv4 address';
  }
  return '';
}

module.exports = { validateInstallConfig };
