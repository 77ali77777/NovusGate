// createJobLock allows one long operation (install, update, uninstall,
// join-vpn, prune) per server at a time; parallel runs on one host would
// race on its files, containers and firewall.
function createJobLock() {
  const active = new Map(); // server id -> { action, token }

  // tryStart returns a release function, or null when a job already runs.
  function tryStart(id, action) {
    if (active.has(id)) return null;
    const token = Symbol(action);
    active.set(id, { action, token });
    return () => {
      const cur = active.get(id);
      if (cur && cur.token === token) active.delete(id);
    };
  }

  function running(id) {
    const cur = active.get(id);
    return cur ? cur.action : null;
  }

  return { tryStart, running };
}

module.exports = { createJobLock };
