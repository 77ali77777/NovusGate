const fs = require('fs');
const path = require('path');

// The Center runs the copy of its own files baked into its image at build
// time (Dockerfile: COPY . .), while server/ and web/ are read live from the
// mounted project folder. After a `git pull` the Center's own files in the
// folder can be newer than the running copy: Install and Update would then
// use the old scripts. centerStale lists those files.
const WATCHED = ['server.js', 'package.json', 'lib', 'modules', 'scripts', 'public'];

function listFiles(root) {
  const out = new Map();
  const walk = (rel) => {
    const abs = path.join(root, rel);
    let st;
    try {
      st = fs.statSync(abs);
    } catch {
      return;
    }
    if (st.isDirectory()) {
      for (const name of fs.readdirSync(abs)) walk(path.posix.join(rel, name));
    } else if (st.isFile()) {
      // A Windows checkout may have CRLF; the content is what counts.
      out.set(rel, fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n'));
    }
  };
  for (const entry of WATCHED) walk(entry);
  return out;
}

// centerStale returns the watched files (sorted) that differ between the
// running copy (appDir) and the project folder (liveDir): changed, added or
// removed. An absent project folder (not mounted) gives no warning.
function centerStale(appDir, liveDir) {
  if (!fs.existsSync(liveDir)) return [];
  const app = listFiles(appDir);
  const live = listFiles(liveDir);
  const differ = new Set();
  for (const [rel, text] of live) if (app.get(rel) !== text) differ.add(rel);
  for (const rel of app.keys()) if (!live.has(rel)) differ.add(rel);
  return [...differ].sort();
}

module.exports = { centerStale };
