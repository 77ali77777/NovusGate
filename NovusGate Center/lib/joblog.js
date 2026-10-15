const fs = require('fs');
const path = require('path');

// Job logs: the full output of every long operation (install, update,
// reinstall, migrate, join-vpn, uninstall, prune) is kept under
// data/jobs/<server id>/<YYYYMMDD-HHMMSS>-<action>.log. The output is kept
// as it is, passwords the scripts print included (user decision, 2026-10-15),
// so directories are 0700 and files 0600. Nothing is deleted automatically.

const NAME_RE = /^(\d{8}-\d{6})(?:-\d+)?-([a-z0-9_-]+)\.log$/;
const ID_RE = /^[A-Za-z0-9_-]+$/;

const pad = (n) => String(n).padStart(2, '0');
const stamp = (d) =>
  `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-` +
  `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;

// headAndTail reads the first headBytes and the last tailBytes of a file.
function headAndTail(file, headBytes, tailBytes) {
  const fd = fs.openSync(file, 'r');
  try {
    const { size } = fs.fstatSync(fd);
    const head = Buffer.alloc(Math.min(headBytes, size));
    fs.readSync(fd, head, 0, head.length, 0);
    const tailLen = Math.min(tailBytes, size);
    const tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, size - tailLen);
    return { head: head.toString('utf8'), tail: tail.toString('utf8'), size };
  } finally {
    fs.closeSync(fd);
  }
}

function createJobLogs(dir, now = () => new Date()) {
  const serverDir = (id) => (ID_RE.test(String(id)) ? path.join(dir, String(id)) : null);

  // start opens a new log; server is { name, host } for the header line.
  // Logging is best-effort: when the log cannot be written (disk full, no
  // permission) the job goes on without it and the error is printed.
  function start(serverId, action, server = {}) {
    try {
      return openLog(serverId, action, server);
    } catch (err) {
      console.error(`[joblog] ${action}: the job log is not written: ${err.message}`);
      return { name: null, path: null, append() {}, finish() {} };
    }
  }

  function openLog(serverId, action, server) {
    const sdir = serverDir(serverId);
    if (!sdir) throw new Error(`invalid server id for a job log: ${serverId}`);
    fs.mkdirSync(sdir, { recursive: true, mode: 0o700 });
    const started = now();
    const safeAction = String(action).toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    let name = `${stamp(started)}-${safeAction}.log`;
    for (let i = 2; fs.existsSync(path.join(sdir, name)); i++) {
      name = `${stamp(started)}-${i}-${safeAction}.log`;
    }
    const file = path.join(sdir, name);
    const who = server.name ? ` on ${server.name}${server.host ? ` (${server.host})` : ''}` : '';
    fs.writeFileSync(file, `# NovusGate Center job: ${safeAction}${who}, started ${started.toISOString()}\n`, { mode: 0o600 });
    let finished = false;
    let broken = false;
    const write = (text) => {
      if (broken) return;
      try {
        fs.appendFileSync(file, text);
      } catch (err) {
        broken = true; // stop trying; the job itself goes on
        console.error(`[joblog] ${name}: writing the log failed: ${err.message}`);
      }
    };
    return {
      name,
      path: file,
      append(text) {
        if (!finished && text) write(text);
      },
      finish(success, code) {
        if (finished) return;
        finished = true;
        const exit = code === undefined || code === null ? '' : ` (exit ${code})`;
        write(`\n# finished: ${success ? 'success' : 'failed'}${exit} at ${now().toISOString()}\n`);
      },
    };
  }

  // list returns the server's logs, newest first.
  function list(serverId) {
    const sdir = serverDir(serverId);
    if (!sdir || !fs.existsSync(sdir)) return [];
    return fs
      .readdirSync(sdir)
      .filter((n) => NAME_RE.test(n))
      .map((name) => {
        const file = path.join(sdir, name);
        // Only the header line and the tail are needed: a whole multi-MB
        // log read per entry blocked the event loop (200 x 2 MB: 760 ms).
        const { head, tail, size } = headAndTail(file, 512, 300);
        const started = /started (\S+)/.exec(head.split('\n', 1)[0]);
        const end = /# finished: (success|failed)/.exec(tail);
        return {
          name,
          action: NAME_RE.exec(name)[2],
          startedAt: started ? started[1] : null,
          status: end ? end[1] : 'running',
          size,
        };
      })
      .sort((a, b) => (a.name < b.name ? 1 : -1));
  }

  // open returns the path of an existing log, or null for anything else.
  function open(serverId, name) {
    const sdir = serverDir(serverId);
    if (!sdir || !NAME_RE.test(String(name))) return null;
    const file = path.join(sdir, name);
    return fs.existsSync(file) ? file : null;
  }

  // remove deletes a server's logs (the server was deleted; they may hold
  // its passwords).
  function remove(serverId) {
    const sdir = serverDir(serverId);
    if (sdir) fs.rmSync(sdir, { recursive: true, force: true });
  }

  return { start, list, open, remove };
}

// teeSSE copies the text of every SSE event written to res into log and
// finishes the log when the stream ends: success comes from the final
// {done, success} event.
function teeSSE(res, log) {
  const write = res.write.bind(res);
  const end = res.end.bind(res);
  let success = false;
  res.write = (chunk, ...rest) => {
    const s = String(chunk);
    if (s.startsWith('data: ')) {
      try {
        const ev = JSON.parse(s.slice(6));
        if (ev.text) log.append(ev.text);
        if (ev.done) {
          success = !!ev.success;
          if (ev.message) log.append(`${ev.message}\n`);
        }
      } catch {
        log.append(s);
      }
    }
    return write(chunk, ...rest);
  };
  res.end = (...args) => {
    log.finish(success);
    return end(...args);
  };
  return res;
}

module.exports = { createJobLogs, teeSSE };
