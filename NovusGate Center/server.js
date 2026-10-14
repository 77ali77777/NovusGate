const express = require('express');
const { Client } = require('ssh2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const logService = require('./modules/log_service'); // Import Log Service
const fail2banModule = require('./modules/fail2ban'); // Import Fail2ban Module
const {
  GENERATE_INSTALL_SCRIPT,
  GENERATE_REINSTALL_SCRIPT,
  UNINSTALL_SCRIPT,
  UPDATE_SCRIPT,
  DATABASE_MIGRATE_SCRIPT,
  EXIT_ALREADY_INSTALLED,
} = require('./lib/scripts');
const { endWithError } = require('./lib/sse');
const { runScript, doneMessage } = require('./lib/run');
const { validateInstallConfig } = require('./lib/validate');
const { createStore } = require('./lib/store');
const { createJobLock } = require('./lib/jobs');
const { createProjectArchive } = require('./lib/archive');
const { connect: connectSSH, sshConfig, ptyWindow } = require('./lib/ssh');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Project paths
const PROJECT_ROOT = '/project_root';
const DATA_DIR = path.join(__dirname, 'data');
const SERVERS_FILE = path.join(DATA_DIR, 'servers.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// servers.json: every change re-reads the file and writes it atomically, so a
// long job that records its result at the end keeps changes made meanwhile.
const store = createStore(SERVERS_FILE);
const loadServers = () => store.load();

// One long operation per server at a time. startJob answers 409 and returns
// null when another one runs; otherwise it returns the release function.
const jobs = createJobLock();
function startJob(res, server, action) {
  const release = jobs.tryStart(server.id, action);
  if (!release) {
    res.status(409).json({ error: `${jobs.running(server.id)} is still running on ${server.name}; wait for it to finish` });
  }
  return release;
}

// addHistory records an action on a server (newest first, last 50 kept).
function addHistory(id, entry, change = () => {}) {
  return store.updateServer(id, (s) => {
    change(s);
    s.history = [{ ...entry, timestamp: new Date().toISOString() }, ...(s.history || [])].slice(0, 50);
  });
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// SSH Connection helper
// Commands run as root: a non-root SSH user goes through sudo -n (lib/ssh).
const createSSHConnection = (server) => connectSSH(server);

// Execute SSH command
function execSSH(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      
      let stdout = '';
      let stderr = '';
      
      stream.on('close', (code) => {
        resolve({ code, stdout, stderr });
      });
      stream.on('data', (data) => { stdout += data.toString(); });
      stream.stderr.on('data', (data) => { stderr += data.toString(); });
    });
  });
}

// ============ API ENDPOINTS ============

// GET /api/servers - List all servers
app.get('/api/servers', (req, res) => {
  const data = loadServers();
  // Don't send passwords
  const servers = data.servers.map(s => ({
    id: s.id,
    name: s.name,
    host: s.host,
    port: s.port,
    username: s.username,
    status: s.status,
    lastCheck: s.lastCheck,
    installedAt: s.installedAt,
    history: s.history
  }));
  res.json(servers);
});

// POST /api/servers - Add new server
app.post('/api/servers', (req, res) => {
  const { name, host, port, username, password, privateKey, passphrase } = req.body;
  
  if (!name || !host || !username) {
    return res.status(400).json({ error: 'Name, host, and username are required' });
  }
  
  const server = {
    id: generateId(),
    name,
    host,
    port: port || 22,
    username,
    password,
    privateKey,
    passphrase,
    status: 'unknown',
    lastCheck: null,
    installedAt: null,
    history: []
  };
  
  store.update((data) => data.servers.push(server));

  res.json({ id: server.id, message: 'Server added' });
});

// DELETE /api/servers/:id
app.delete('/api/servers/:id', (req, res) => {
  store.update((data) => {
    data.servers = data.servers.filter(s => s.id !== req.params.id);
  });
  res.json({ message: 'Server deleted' });
});

// GET /api/servers/:id/status - Check server status
app.get('/api/servers/:id/status', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Check NovusGate installation
    const NovusGateCheck = await execSSH(conn, 'test -d /opt/NovusGate && echo "installed" || echo "not_installed"');
    const isInstalled = NovusGateCheck.stdout.trim() === 'installed';
    
    // Check Docker containers
    const dockerPs = await execSSH(conn, 'docker ps --format "{{.Names}}|{{.Status}}|{{.Ports}}" 2>/dev/null | grep -i novusgate || true');
    const containers = dockerPs.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, status, ports] = line.split('|');
      return { name, status, ports };
    });
    
    // Check disk space - total and used
    const diskCheck = await execSSH(conn, "df -h / | tail -1 | awk '{print $2\"|\"$3\"|\"$4\"|\"$5}'");
    const diskParts = diskCheck.stdout.trim().split('|');
    const totalDisk = diskParts[0] || 'N/A';
    const usedDisk = diskParts[1] || 'N/A';
    const freeSpace = diskParts[2] || 'N/A';
    const diskPercent = diskParts[3] || 'N/A';
    
    // Check memory - total, used, available
    const memCheck = await execSSH(conn, "free -h | grep Mem | awk '{print $2\"|\"$3\"|\"$7}'");
    const memParts = memCheck.stdout.trim().split('|');
    const totalMemory = memParts[0] || 'N/A';
    const usedMemory = memParts[1] || 'N/A';
    const freeMemory = memParts[2] || 'N/A';
    
    // Check CPU usage
    const cpuCheck = await execSSH(conn, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
    const cpuUsage = cpuCheck.stdout.trim() || 'N/A';
    
    // Check uptime
    const uptimeCheck = await execSSH(conn, "uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}'");
    const uptime = uptimeCheck.stdout.trim() || 'N/A';
    
    conn.end();
    
    // Update server status
    server.status = isInstalled ? 'installed' : 'not_installed';
    server.lastCheck = new Date().toISOString();
    store.updateServer(server.id, (s) => {
      s.status = server.status;
      s.lastCheck = server.lastCheck;
    });

    res.json({
      id: server.id,
      name: server.name,
      host: server.host,
      status: server.status,
      isInstalled,
      containers,
      // Disk info
      totalDisk,
      usedDisk,
      freeSpace,
      diskPercent,
      // Memory info
      totalMemory,
      usedMemory,
      freeMemory,
      // CPU & Uptime
      cpuUsage,
      uptime,
      lastCheck: server.lastCheck
    });
    
  } catch (err) {
    store.updateServer(server.id, (s) => {
      s.status = 'offline';
      s.lastCheck = new Date().toISOString();
    });

    res.status(500).json({ error: 'Unable to connect to server: ' + err.message });
  }
});

// GET /api/servers/:id/docker - Get Docker containers
app.get('/api/servers/:id/docker', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    const result = await execSSH(conn, `
      docker ps -a --format '{"name":"{{.Names}}","status":"{{.Status}}","image":"{{.Image}}","ports":"{{.Ports}}"}' 2>/dev/null || echo "[]"
    `);
    
    conn.end();
    
    const containers = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter(Boolean);
    
    res.json(containers);
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Stream Docker Logs (Live) - Add this BEFORE or AFTER generic docker actions
app.get('/api/servers/:id/docker/logs/stream', async (req, res) => {
  const { container } = req.query;
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) return res.status(404).json({ error: 'Server not found' });
  if (!container) return res.status(400).json({ error: 'Container name required' });
  
  await logService.streamContainerLogs(server, container, req, res);
});

// POST /api/servers/:id/docker/:action - Control Docker container
app.post('/api/servers/:id/docker/:action', async (req, res) => {
  const { container } = req.body;
  const action = req.params.action; // start, stop, restart, remove
  
  if (!['start', 'stop', 'restart', 'remove', 'logs'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    let command;
    if (action === 'logs') {
      command = `docker logs --tail 100 ${container}`;
    } else if (action === 'remove') {
      command = `docker rm -f ${container}`;
    } else {
      command = `docker ${action} ${container}`;
    }
    
    const result = await execSSH(conn, command);
    conn.end();
    
    addHistory(server.id, { action: `docker_${action}`, container, success: result.code === 0 });
    
    if (action === 'logs') {
      res.json({ logs: result.stdout + result.stderr });
    } else {
      res.json({ 
        success: result.code === 0, 
        output: result.stdout + result.stderr 
      });
    }
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/images - Get Docker images
app.get('/api/servers/:id/images', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    // Include ID for dangling images that have no repository/tag
    const result = await execSSH(conn, `docker images --format '{"id":"{{.ID}}","repository":"{{.Repository}}","tag":"{{.Tag}}","size":"{{.Size}}","created":"{{.CreatedSince}}"}' 2>/dev/null`);
    conn.end();
    
    const images = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    
    res.json(images);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/prune - Prune unused Docker resources
app.post('/api/servers/:id/prune', async (req, res) => {
  const { type = 'all' } = req.body; // images, containers, volumes, all
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  const release = startJob(res, server, 'prune');
  if (!release) return;
  try {
    const conn = await createSSHConnection(server);

    let command;
    switch (type) {
      case 'images':
        command = 'docker image prune -af';
        break;
      case 'containers':
        command = 'docker container prune -f';
        break;
      case 'volumes':
        command = 'docker volume prune -f';
        break;
      default:
        command = 'docker system prune -af --volumes';
    }
    
    const result = await execSSH(conn, command);
    conn.end();
    
    addHistory(server.id, { action: `prune_${type}`, success: result.code === 0 });

    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    release();
  }
});

// DELETE /api/servers/:id/images/:name - Delete Docker image
app.delete('/api/servers/:id/images/:name', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker rmi -f ${decodeURIComponent(req.params.name)}`);
    conn.end();
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/volumes - Get Docker volumes
app.get('/api/servers/:id/volumes', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker volume ls --format '{"name":"{{.Name}}","driver":"{{.Driver}}"}' 2>/dev/null`);
    conn.end();
    
    const volumes = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    
    res.json(volumes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:id/volumes/:name - Delete Docker volume
app.delete('/api/servers/:id/volumes/:name', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, `docker volume rm -f ${req.params.name}`);
    conn.end();
    
    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/credentials - Get credentials from server's .env file
app.get('/api/servers/:id/credentials', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Read .env file from server
    const envResult = await execSSH(conn, 'cat /opt/NovusGate/server/deployments/docker/.env 2>/dev/null || echo "NOT_FOUND"');
    
    if (envResult.stdout.trim() === 'NOT_FOUND') {
      conn.end();
      return res.status(404).json({ error: 'NovusGate not installed or .env file not found' });
    }
    
    // Parse .env file
    const envContent = envResult.stdout;
    const parseEnv = (key) => {
      const match = envContent.match(new RegExp(`^${key}=(.*)$`, 'm'));
      return match ? match[1].trim() : null;
    };
    
    const credentials = {
      adminUser: parseEnv('ADMIN_USERNAME') || 'admin',
      adminPass: parseEnv('ADMIN_PASSWORD'),
      apiKey: parseEnv('API_KEY'),
      dbName: parseEnv('DB_NAME'),
      dbUser: parseEnv('DB_USER'),
      dbPass: parseEnv('DB_PASSWORD'),
      jwtSecret: parseEnv('JWT_SECRET'),
      vpnIp: parseEnv('VPN_IP') || '10.99.0.1'
    };
    
    conn.end();
    res.json(credentials);
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/vpn-config - Get admin VPN config from server
app.get('/api/servers/:id/vpn-config', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    
    // Try to read admin VPN config - check multiple locations
    const configResult = await execSSH(conn, `
      if [ -f /tmp/admin-vpn.conf ]; then
        cat /tmp/admin-vpn.conf
      elif [ -f /opt/NovusGate/admin-vpn.conf ]; then
        cat /opt/NovusGate/admin-vpn.conf
      elif [ -f /root/admin-vpn.conf ]; then
        cat /root/admin-vpn.conf
      else
        echo "NOT_FOUND"
      fi
    `);
    
    conn.end();
    
    if (configResult.stdout.trim() === 'NOT_FOUND') {
      return res.status(404).json({ error: 'VPN config not found. It may have been deleted after installation.' });
    }
    
    res.json({ config: configResult.stdout.trim() });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/uninstall - Clean uninstall NovusGate
app.post('/api/servers/:id/uninstall', async (req, res) => {
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  const release = startJob(res, server, 'uninstall');
  if (!release) return;
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, UNINSTALL_SCRIPT);
    conn.end();

    addHistory(server.id, { action: 'uninstall', success: result.code === 0 }, (s) => {
      s.status = 'not_installed';
    });

    res.json({ success: result.code === 0, output: result.stdout + result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    release();
  }
});

// POST /api/servers/:id/install - Install NovusGate
app.post('/api/servers/:id/install', async (req, res) => {
  const { source = 'local', reinstall = false, update = false, migrateOnly = false } = req.body;
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  // Form values end up in shell scripts and the compose .env.
  const invalid = validateInstallConfig(req.body);
  if (invalid) {
    return res.status(400).json({ error: invalid });
  }
  const jobAction = migrateOnly ? 'migrate' : update ? 'update' : reinstall ? 'reinstall' : 'install';
  const release = startJob(res, server, jobAction);
  if (!release) return;

  // STREAM RESPONSE IMMEDIATELY
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendLog = (text, isError = false) => {
    res.write(`data: ${JSON.stringify({ text: text + '\n', stderr: isError })}\n\n`);
  };

  // Declared outside the try so the catch below can clean up the archive
  // and close the SSH connection.
  let archivePath = null;
  let conn = null;
  try {
    sendLog('[INFO] Initializing installation...');

    // 1. Create Archive (Local only)
    if (source === 'local') {
      sendLog('[INFO] Creating project archive...');
      try {
        archivePath = await createProjectArchive(PROJECT_ROOT);
        sendLog('[INFO] Archive created successfully.');
      } catch (err) {
        release();
        endWithError(res, new Error(`Failed to create archive: ${err.message}`));
        return;
      }
    }

    // 2. Connect SSH
    sendLog(`[INFO] Connecting to server ${server.host}...`);
    conn = await createSSHConnection(server);
    sendLog('[INFO] Connected!');

    // 3. Upload Archive
    if (archivePath) {
      sendLog('[INFO] Uploading archive to server (this may take a moment)...');
      try {
        await uploadFile(conn, archivePath, '/tmp/NovusGate.tar.gz');
        sendLog('[INFO] Upload complete.');
      } catch (uploadErr) {
        sendLog(`[ERROR] Upload failed: ${uploadErr.message}`, true);
        throw uploadErr; // Rethrow to trigger outer catch
      } finally {
         if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath); // Cleanup local
      }
    }

    // 4. Prepare Config & Script
    const config = {
      adminUsername: req.body.adminUsername,
      adminPassword: req.body.adminPassword,
      networkName: req.body.networkName,
      networkCidr: req.body.networkCidr,
      vpnIp: req.body.vpnIp,
      dbName: req.body.dbName,
      dbUser: req.body.dbUser,
      dbPassword: req.body.dbPassword
    };

    let script = GENERATE_INSTALL_SCRIPT(config);
    if (migrateOnly) script = DATABASE_MIGRATE_SCRIPT;
    else if (update) script = UPDATE_SCRIPT;
    else if (reinstall) script = GENERATE_REINSTALL_SCRIPT(config);

    const envs = `export DEBIAN_FRONTEND=noninteractive`;

    // 5. Execute Script
    sendLog('[INFO] Executing installation script...');
    
    // The API key is no longer copied into web/.env: since P4b the panel
    // calls the API through its own nginx, which adds the key.
    const isInstall = !update && !reinstall && !migrateOnly;
    runScript(conn, `${envs}\n${script}`, res, (code) => {
      release();
      // A refused install on an already-installed server keeps its status.
      const alreadyInstalled = code === EXIT_ALREADY_INSTALLED && isInstall;
      const action = update ? 'update' : (reinstall ? 'reinstall' : 'install');
      addHistory(server.id, { action, source, success: code === 0 }, (s) => {
        if (!alreadyInstalled) {
          s.status = code === 0 ? 'installed' : 'error';
          s.installedAt = new Date().toISOString();
        }
      });

      res.write(`data: ${JSON.stringify({ done: true, success: code === 0, message: doneMessage(code, { install: isInstall }) })}\n\n`);
      res.end();
    }, release);

  } catch (err) {
    release();
    try {
      if (archivePath && fs.existsSync(archivePath)) fs.unlinkSync(archivePath);
    } catch (cleanupErr) {
      console.error('Failed to remove archive:', cleanupErr);
    }
    if (conn) conn.end(); // an upload failure must not leave the SSH session open
    endWithError(res, err);
  }
});

// POST /api/servers/:id/command - Run custom command
app.post('/api/servers/:id/command', async (req, res) => {
  const { command } = req.body;
  
  if (!command) {
    return res.status(400).json({ error: 'Command is required' });
  }
  
  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server not found' });
  }
  
  try {
    const conn = await createSSHConnection(server);
    const result = await execSSH(conn, command);
    conn.end();
    
    res.json({
      success: result.code === 0,
      code: result.code,
      stdout: result.stdout,
      stderr: result.stderr
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/join-vpn - Join server to VPN
app.post('/api/servers/:id/join-vpn', async (req, res) => {
  const { networkId, controlPlaneUrl, apiKey } = req.body;
  
  if (!networkId || !controlPlaneUrl || !apiKey) {
    return res.status(400).json({ error: 'NetworkId, ControlPlaneUrl and ApiKey are required' });
  }

  const data = loadServers();
  const server = data.servers.find(s => s.id === req.params.id);
  
  if (!server) {
    return res.status(404).json({ error: 'Server tapılmadı' });
  }

  try {
    const conn = await createSSHConnection(server);
    
    // 1. Install WireGuard
    await execSSH(conn, 'apt-get update && apt-get install -y wireguard curl');
    
    // 2. Generate Keys
    const privKeyResult = await execSSH(conn, 'wg genkey');
    const privateKey = privKeyResult.stdout.trim();
    const pubKeyResult = await execSSH(conn, `echo "${privateKey}" | wg pubkey`);
    const publicKey = pubKeyResult.stdout.trim();
    
    // 3. Register with Control Plane
    // We need to make an HTTP request from the Installer Service to the Control Plane
    // Or we can do it via curl from the target server? 
    // Let's do it from the Installer Service using fetch/axios (need to install axios or use fetch if node 18+)
    // But easier via curl on target to avoid connectivity issues from Installer -> CP
    
    // Construct curl command to register and get config
    // POST /api/v1/networks/{networkId}/servers
    const registerCmd = `curl -s -X POST "${controlPlaneUrl}/api/v1/networks/${networkId}/servers" \
      -H "X-API-Key: ${apiKey}" \
      -H "Content-Type: application/json" \
      -d '{"name":"${server.name}","publicKey":"${publicKey}","labels":{"installer":"true"}}'`;
      
    const registerResult = await execSSH(conn, registerCmd);
    if (registerResult.code !== 0) {
      throw new Error(`Registration failed: ${registerResult.stderr}`);
    }
    
    const response = JSON.parse(registerResult.stdout);
    if (!response.config) {
        // Access config via dedicated endpoint if not returned directly (our API returns full object?)
        // Our config_handlers.go createServerWithConfig returns: { node: ..., config: ... }
        throw new Error('No config received from Control Plane');
    }
    
    const wgConfig = response.config;
    
    // 4. Write Config
    await execSSH(conn, `echo "${wgConfig}" > /etc/wireguard/wg0.conf`);
    
    // 5. Enable IP Forwarding
    await execSSH(conn, 'sysctl -w net.ipv4.ip_forward=1');
    await execSSH(conn, 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf');
    
    // 6. Start WireGuard
    await execSSH(conn, 'systemctl enable --now wg-quick@wg0');
    
    conn.end();
    
    server.history = server.history || [];
    server.history.unshift({
      action: 'join-vpn',
      timestamp: new Date().toISOString(),
      success: true
    });
    saveServers(data);
    
    res.json({ success: true, message: 'Successfully joined VPN!' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function uploadFile(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      
      const readStream = fs.createReadStream(localPath);
      const writeStream = sftp.createWriteStream(remotePath);
      
      writeStream.on('close', resolve);
      writeStream.on('error', reject);
      readStream.pipe(writeStream);
    });
  });
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0.0' });
});

// Register Fail2ban routes
fail2banModule.registerRoutes(app, loadServers, createSSHConnection);

// Start server
// Start server
const http = require('http');
const { Server } = require("socket.io");

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // allow all for now
    methods: ["GET", "POST"]
  }
});

// Socket.IO SSH Terminal Logic
io.on('connection', (socket) => {
  console.log('Client connected to terminal:', socket.id);
  let conn = null;
  let stream = null;
  let lastWindow = null; // latest valid size from the browser

  socket.on('start-session', async (serverId) => {
    try {
      const data = loadServers();
      const serverConfig = data.servers.find(s => s.id === serverId);
      
      if (!serverConfig) {
        socket.emit('output', '\r\nServer not found.\r\n');
        return;
      }

      socket.emit('output', `\r\nConnecting to ${serverConfig.host}...\r\n`);
      
      conn = new Client();
      
      conn.on('ready', () => {
        socket.emit('output', '\r\nConnected! Opening shell...\r\n');
        
        // Open the shell at the browser's size; a resize sent before the
        // shell existed would otherwise be lost (80x24 until the next one).
        conn.shell({ term: 'xterm-256color', ...(lastWindow || {}) }, (err, s) => {
          if (err) {
            socket.emit('output', `\r\nShell error: ${err.message}\r\n`);
            return;
          }
          
          stream = s;
          
          // Data from server -> Client
          stream.on('data', (data) => {
            socket.emit('output', data.toString());
          });
          
          stream.on('close', () => {
            socket.emit('output', '\r\nConnection closed by remote host.\r\n');
            conn.end();
          });
          
        });
      });
      
      conn.on('error', (err) => {
        socket.emit('output', `\r\nConnection error: ${err.message}\r\n`);
      });
      
      conn.on('close', () => {
        socket.emit('output', '\r\nDisconnected.\r\n');
      });

      // Same authentication as installs (the key passphrase included).
      conn.connect(sshConfig(serverConfig));

    } catch (err) {
      socket.emit('output', `\r\nError: ${err.message}\r\n`);
    }
  });

  // Data from Client -> Server
  socket.on('input', (data) => {
    if (stream) {
      stream.write(data);
    }
  });

  socket.on('resize', (size) => {
    const win = ptyWindow(size);
    if (!win) return;
    lastWindow = win;
    if (stream) {
      stream.setWindow(win.rows, win.cols, win.height, win.width);
    }
  });

  socket.on('disconnect', () => {
    if (conn) conn.end();
    console.log('Client disconnected:', socket.id);
  });
});

// One failed request must not take down installs running for other servers.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
});

const PORT = process.env.PORT || 3017;
server.listen(PORT, () => {
  console.log(`NovusGate Center: http://localhost:${PORT}`);
  console.log(`Server data: ${SERVERS_FILE}`);
});
