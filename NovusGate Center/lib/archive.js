const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

// What the install archive leaves out. A local compose run creates
// server/data (the Postgres data dir); shipping it would overwrite the
// preserved production database on reinstall.
const ARCHIVE_EXCLUDES = [
  '--exclude=node_modules',
  '--exclude=.git',
  '--exclude=*.exe',
  '--exclude=*.tar.gz',
  '--exclude=*.log',
  '--exclude=.env',
  '--exclude=.idea',
  '--exclude=.vscode',
  '--exclude=server/data',
  '--exclude=server/start_dev.sh',
  '--exclude=installer/node_modules',
];

// newArchivePath is a fresh file per install, so parallel installs to
// different servers never share (or delete) one archive.
function newArchivePath() {
  return path.join(os.tmpdir(), `novusgate-${crypto.randomBytes(8).toString('hex')}.tar.gz`);
}

// createProjectArchive packs server/ and web/ from projectRoot.
function createProjectArchive(projectRoot) {
  const archivePath = newArchivePath();
  const args = ['-czf', archivePath, '-C', projectRoot, ...ARCHIVE_EXCLUDES, 'server', 'web'];
  return new Promise((resolve, reject) => {
    execFile('tar', args, (error, stdout, stderr) => {
      if (error) reject(new Error((stderr || error.message).trim()));
      else resolve(archivePath);
    });
  });
}

module.exports = { ARCHIVE_EXCLUDES, newArchivePath, createProjectArchive };
