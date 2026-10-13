const scripts = require('../lib/scripts');

const sampleConfig = {
  adminUsername: 'admin',
  adminPassword: '',
  networkName: 'Admin',
  networkCidr: '10.99.0.0/24',
  vpnIp: '10.99.0.1',
  dbName: 'novusgate',
  dbUser: 'novusgate',
  dbPassword: '',
};

function generateAll(config) {
  return {
    install: scripts.GENERATE_INSTALL_SCRIPT(config),
    reinstall: scripts.GENERATE_REINSTALL_SCRIPT(config),
    uninstall: scripts.UNINSTALL_SCRIPT,
    update: scripts.UPDATE_SCRIPT,
    migrate: scripts.DATABASE_MIGRATE_SCRIPT,
  };
}

module.exports = { sampleConfig, generateAll };
