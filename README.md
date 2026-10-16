# NovusGate

[![GitHub stars](https://img.shields.io/github/stars/Ali7Zeynalli/NovusGate?style=social)](https://github.com/Ali7Zeynalli/NovusGate/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![WireGuard](https://img.shields.io/badge/Protocol-WireGuard-88171A.svg)](https://www.wireguard.com/)
[![VPN Type](https://img.shields.io/badge/VPN%20Type-Remote%20Access-blue.svg)](#-vpn-type)

🚀 **Build your own private VPN network — without SaaS lock-in or painful configurations.**

**NovusGate** is a modern, fully self-hosted **VPN control plane** built on top of the **WireGuard®** protocol.
It connects servers, cloud instances and personal devices through a clean **Hub-and-Spoke architecture**, all managed from a single web dashboard.

Whether you're running production infrastructure or simply want full ownership of your private network, **NovusGate gives you clarity, security, and control**.

![NovusGate Dashboard](web/public/novusgate_banner.png)

> 🇦🇿 **Azərbaycanca:** [README_AZ.md](./README_AZ.md)

---

## ⚠️ Important: What NovusGate Is (and Isn't)

**NovusGate is NOT a commercial "hide my IP" or "bypass geo-restrictions" VPN service.**

It is a **private network infrastructure tool** for:
- ✅ Secure server-to-server communication
- ✅ Remote access to internal services
- ✅ Connecting distributed infrastructure
- ✅ Building trusted private networks

**Traffic routing:**
- **Default — split tunnel:** only traffic for your VPN networks (e.g. `10.x.x.x`) goes through the tunnel; your normal internet traffic goes straight through your ISP.
- **Optional — full tunnel:** turn on full tunnel for a node in the panel and all its internet traffic leaves through your server (DNS goes through the tunnel too).

---

## 🎯 The Problem NovusGate Solves

**Scenario:** You have a server somewhere (cloud, home, office) but:
- ❌ You don't have a static IP to reach it
- ❌ You don't want to expose its ports to the internet
- ❌ NAT/firewall makes direct connections impossible

**The NovusGate solution:**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Your Server   │     │  NovusGate Hub  │     │  Your Computer  │
│ (No Static IP)  │     │   (Cloud VPS)   │     │  (Home/Office)  │
│                 │     │                 │     │                 │
│   10.10.10.3    │────▶│   10.10.10.1    │◀────│   10.10.10.4    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                     ▲                     │
         └───────── Both connect to Hub ────────────┘
```

Once both devices are connected to NovusGate:
- ✅ They see each other as if on the **same local network**
- ✅ Your server becomes `10.10.10.3` — always reachable
- ✅ Your computer becomes `10.10.10.4` — SSH, RDP or any service
- ✅ No port forwarding and no static IP needed
- ✅ Works behind NAT and firewalls

(The hub takes the network's first address and the second is reserved; devices start at the third.)

**Real example:**
```bash
# From your computer (10.10.10.4), connect to your server:
ssh user@10.10.10.3

# Reach a web service running on your server:
curl http://10.10.10.3:8080
```

---

## ✨ Why NovusGate?

Most private networking solutions today are either:
- ❌ SaaS black boxes
- ❌ Hard to manage at scale
- ❌ Overly complex for small teams
- ❌ Or painful to self-host

**NovusGate is built to be different:** ownership over convenience, simplicity over complexity, transparency over abstraction.

You run it. You control it. Your network — your rules.

---

## 🚀 Key Features

**Networks and devices**
- **Multiple networks** — each with its own WireGuard interface (wg0, wg1…), subnet and UDP port.
- **Device (node) management** — QR code for mobile, `.conf` for desktop, a one-line install script for Linux (one-time, 15-minute token). Access can expire on a date.
- **Full tunnel** — all internet traffic of a chosen node goes through the hub.
- **Per-network client DNS** — the DNS servers written into device configs.
- **Topology map**, network details and **traffic history** per node.

**Firewall and control**
- **VPN rules** — allow/block between networks, nodes, groups and IPs, by protocol and port, in priority order; a **network policy matrix** shows who can reach whom and why.
- **Node groups** — apply rules and limits to several nodes at once.
- **Host firewall** — open ports, block/allow IPs; the management ports (3007, 5432, 8080, 8443) stay reachable over the VPN only.
- **nftables engine** (optional, see below) — Advanced tab (services, IP rules, port forwarding), changes rolled back unless confirmed within 60 seconds, **Live** (counters, conntrack) and **History** (change history, restore).
- **Limit profiles** (with the nftables engine) — speed limits, concurrent connection limits, schedules and a **monthly traffic quota** (block or slow down, 80%/100% notices).
- **Fail2Ban** — SSH protection, jail settings, whitelist, manual and permanent bans, ban history, logs.

**Administration and security**
- **Roles** — Admin, Operator, Viewer; each sees and does only what it may.
- **Sessions** — a sign-in lasts 24 hours; view and end active sessions; failed sign-ins are rate-limited.
- **Audit log** — changes made through the API and sign-in attempts.
- **Server page** (admin only, asks for the password again) — services (docker, fail2ban, WireGuard), host network, kernel settings (undone after 90 seconds unless kept), host name, time zone/NTP, package upgrades and reboot.
- **Backups** and **Telegram notifications**.
- **Panel in two languages** (English / Azerbaijani) and **a "?" beside every field** explaining what it is, who needs it and what changing it does.

**NovusGate Center**
- **Install and update** a server over SSH (backup first, automatic rollback on failure), reinstall, uninstall, **Join VPN** (connect another server as a node), web terminal, server monitoring and job logs.

---

## 📡 VPN Type

**NovusGate is a client-based Remote Access VPN.**

| VPN Type | NovusGate? | Description |
|----------|------------|-------------|
| ☁️ Cloud VPN | ⚠️ | Not a managed service like AWS/Azure VPN Gateway; runs on any cloud or on-prem server |
| 🔐 IPsec VPN | ❌ | Uses WireGuard instead of IPsec |
| 🌐 SSL VPN | ❌ | Not browser-based; needs a WireGuard client |
| 💻 **Client-based VPN** | ✅ | With the WireGuard client |
| 🏢 Site-to-Site VPN | ⚠️ | Possible by joining a Linux server as a node |
| 📡 **Remote Access VPN** | ✅ | The main use case |

- **Protocol:** WireGuard · **Architecture:** Hub-and-Spoke · **Tunnel:** split by default, full optional
- **Clients:** mobile (QR), desktop (.conf), Linux (script)

---

## 👥 Who Is NovusGate For?

- **System administrators** — secure access between servers and data centres
- **DevOps engineers** — connecting infrastructure across environments
- **Developers** — internal or self-hosted platforms
- **Privacy-minded users** — full control over their own VPN

---

## 🧠 How It Works (Short)

1. A **central server (hub)** runs the control plane, the panel and PostgreSQL in Docker.
2. You create **separate networks**, each with its own subnet (e.g. `10.20.0.0/24`).
3. Devices get a config (QR, `.conf` or Linux script).
4. WireGuard tunnels come up; traffic is routed through the hub according to the firewall rules.

---

## 📂 System Architecture

```
+-------------------------------------------------------------+
|                     NovusGate Server (hub)                  |
|  +-------------+  +-------------+  +-------------+          |
|  |  Network 1  |  |  Network 2  |  |  Network N  |          |
|  |  wg0:51820  |  |  wg1:51821  |  |  wgN:518XX  |          |
|  | 10.99.0.0/24|  | 10.20.0.0/24|  | 10.XX.0.0/24|          |
|  +------+------+  +------+------+  +------+------+          |
|         |                |                |                 |
|  +------+----------------+----------------+------+          |
|  |  Control plane (Go, REST API) · PostgreSQL    |          |
|  |  Panel (React, nginx, HTTPS :3007)            |          |
|  +-----------------------------------------------+          |
+-------------------------------------------------------------+
                            |
              +-------------+-------------+
              |             |             |
         +----+----+   +----+----+   +----+----+
         |  Phone  |   | Laptop  |   | Server  |
         +---------+   +---------+   +---------+
```

| Part | Folder | Guides |
|------|--------|--------|
| **Server (backend)** — Go; WireGuard, firewall, PostgreSQL, REST API | `./server` | [Developer](./server/DEVELOPER_GUIDE.md) · [User](./server/USER_GUIDE.md) |
| **Web panel (frontend)** — React, TypeScript, Tailwind | `./web` | [Developer](./web/DEVELOPER_GUIDE.md) |
| **NovusGate Center** — install and manage over SSH, Node.js | `./NovusGate Center` | [Developer](./NovusGate%20Center/DEVELOPER_GUIDE.md) · [User](./NovusGate%20Center/USER_GUIDE.md) |

Technical documentation: [`docs/`](./docs) (API, data model, security, deployment, runbooks; mostly in Azerbaijani).

---

## ⚡ Quick Start

### Requirements

**On your own computer (for the Center):**
- Docker and Docker Compose

**The server (hub):**
- **Ubuntu 22.04 or newer** (24.04 and 26.04 checked) or **Debian 12 or newer** (13 checked)
- x86_64 or aarch64; at least 1 GB RAM (2 GB recommended), 3 GB free disk
- SSH access as root or as a user with passwordless `sudo`
- Ports open from the internet: **22/tcp** (SSH) and **51820/udp** (each new network takes the next port: 51821, 51822…)
- Do **not** open 3007 (panel), 5432 (DB), 8080 (API) or 8443 to the internet — NovusGate opens them to the VPN only.

The Center checks the server first (OS version, CPU, RAM, disk, ports) and stops if it does not fit.

---

### Installation (step by step)

#### 1. Clone the repository
```bash
git clone https://github.com/Ali7Zeynalli/NovusGate.git
cd NovusGate
```

#### 2. Start NovusGate Center
```bash
cd "NovusGate Center"
docker compose up -d --build
```

#### 3. Open the Center
In your browser: `http://localhost:3017`

#### 4. Add your server
| Field | Description |
|-------|-------------|
| **Server Name** | Any name you like |
| **Host** | The server's IP address (e.g. `203.0.113.50`) |
| **SSH Port** | Default `22` |
| **Username** | `root` or a user with passwordless `sudo` |
| **Password / Private Key** | SSH password or a PEM key (a passphrase is supported) |

#### 5. Installation settings
| Setting | Description |
|---------|-------------|
| **Admin Username** | The panel's first admin user (default `admin`) |
| **Admin Password** | Leave empty to get a random one |
| **Admin VPN Gateway IP** | The hub's address on the admin VPN (default `10.99.0.1`, network `10.99.0.0/24`) |
| **Database Name / User / Password** | For PostgreSQL; an empty password is generated |

The **"?"** beside each field explains what it does.

#### 6. Install
The Center updates the system, installs Docker, WireGuard and Fail2Ban, uploads NovusGate to `/opt/NovusGate`, generates the secrets (DB password, API key, master key), builds and starts the containers and creates the **admin VPN** (`wg0`).

#### 7. Get the admin VPN config
When the install finishes, the Center shows the **admin VPN configuration**: **📥 Download admin-vpn.conf**. It is also kept on the server at `/opt/NovusGate/admin-vpn.conf`.

#### 8. Connect to the VPN
1. Install a WireGuard client (Windows, macOS, Linux, Android, iOS).
2. Import `admin-vpn.conf` and activate it.
3. Your VPN address will be `10.99.0.2`; `ping 10.99.0.1` should answer.

#### 9. Open the panel
```
https://10.99.0.1:3007
```
(If you changed the gateway IP, use that IP.)

- Type **`https://`** — `http://` does not work.
- The browser warns about the certificate (the panel uses a self-signed one): **Advanced → Proceed**.
- **User name and password:** in the Center select the server → **Server Credentials** (available at any time), or at the end of the install log under `ADMIN USER` / `ADMIN PASS`.

🎉 Done.

#### If the panel does not open
| Symptom | What to do |
|---------|-----------|
| The page does not load | Check "Latest handshake" in WireGuard; `ping 10.99.0.1` |
| You use the server's public IP | It will not work: the panel is reachable over the VPN only |
| The password is refused | After 10 failed sign-ins in 15 minutes sign-in is blocked for a while; wait, and take the password from Center → Server Credentials |

On the server:
```bash
docker ps --format '{{.Names}} {{.Status}}'
sudo wg show wg0 | head -12
curl -sk -o /dev/null -w '%{http_code}\n' https://10.99.0.1:3007
```

---

### After installation
- Create more VPN networks and add devices (QR, `.conf`, Linux script).
- **Settings → Users**: give everyone the role they need (Admin / Operator / Viewer).
- Set up Telegram notifications and backups.
- To join another Linux server as a node: panel → Nodes → Connect → Linux → install script; then Center → **Join VPN** (it refuses to run on the hub itself, where it would replace the hub's `wg0`).

### nftables firewall engine (for limits, quota, Advanced tab)
An installation runs in **iptables** mode by default. **Limit profiles, the traffic quota, the Advanced tab (port forwarding etc.), Live and History** need the nftables engine. Steps, checks and the way back: [`docs/runbooks/p3b2-firewall-cutover.md`](./docs/runbooks/p3b2-firewall-cutover.md). In short: Center → Update → add `FIREWALL_ENGINE=nft` to `server/deployments/docker/.env` → `docker compose up -d control-plane` → Center → Update once more.

### Updating
Center → **Update**: updates the code and keeps `.env`, the database and the VPN configs; a backup is taken first (`/var/backups/novusgate/`) and the previous version is restored automatically if the update fails. Database migrations run by themselves when the control plane starts.

**Upgrading from an old version:** roles did not exist before, so all existing users become **Admin** — check the roles under Settings → Users after the upgrade.

---

### What NovusGate Center does behind the scenes
1. **Preflight:** OS, CPU, RAM, disk, ports.
2. **Packages:** `apt-get update`, Docker (get.docker.com), WireGuard, Fail2Ban.
3. **Files:** `/opt/NovusGate`; the admin VPN config at `/opt/NovusGate/admin-vpn.conf`.
4. **Security:** generates the DB password, API key and master key (which encrypts node keys) and keeps them root-only in `server/deployments/docker/.env`; a Fail2Ban jail for SSH (3 failures = 1 hour ban); the `wg0` admin VPN.
5. **Services:** `docker compose up -d` — PostgreSQL, control plane, panel.

---

### Local development / manual start
```bash
cd server/deployments/docker
cp .env.example .env     # set at least ADMIN_PASSWORD, API_KEY and MASTER_KEY (openssl rand -hex 32)
docker compose up -d --build
```
This starts PostgreSQL, the control plane (API, port 8080) and the panel (port 3007). Panel: `https://localhost:3007`.

> **Note:** full VPN functionality needs Linux with WireGuard. On Windows/macOS the UI and API work, but VPN functions may be limited.

Manual production setup: 👉 **[Server User Guide](./server/USER_GUIDE.md)**

---

## 🌐 Network Management

| Feature | Description |
|---------|-------------|
| **Separate subnets** | Each network has its own CIDR (e.g. 10.10.0.0/24, 10.20.0.0/24); they may not overlap |
| **Own interface** | Assigned automatically: wg0, wg1, wg2… |
| **Own port** | Each network listens on the next free UDP port (51820, 51821…) |
| **Client DNS** | The DNS servers the network's devices use (up to 3 IPv4 addresses) |

**Create a network:** panel → **Networks** → new network → name and CIDR (e.g. `10.50.0.0/24`). The interface and port are assigned automatically; open that port (UDP) to the internet.

---

## 🛡️ Security

* The panel, API and database are reachable **over the VPN only** (3007, 5432, 8080, 8443 are closed to the internet).
* The API key never reaches the browser: the panel's nginx adds it to each request itself.
* A sign-in lasts 24 hours; failed sign-ins are rate-limited; roles are checked on every request.
* Changes on the Server page ask for the password **again** (valid for 5 minutes).
* Node private keys are stored encrypted with the master key.
* Every API change is written to the audit log.
* **Fail2Ban** protects SSH (3 failures = 1 hour ban).
* Keep the credentials shown at the end of the installation somewhere safe.

---

## 📊 Server Monitoring

The main dashboard shows live **CPU**, **RAM**, **disk** usage and **uptime**, network and node statistics, and which nodes are online.

---

## 🔒 Fail2Ban

| Feature | Description |
|---------|-------------|
| **Jail status and settings** | bantime, findtime, maxretry |
| **Banned IPs** | Per jail; unban with one click |
| **Manual and permanent bans** | Ban an IP by hand; permanent bans live in the firewall |
| **Whitelist** | IPs/CIDRs that are never banned |
| **History and logs** | Ban history, logs with a filter |

The **Fail2Ban** page in the panel.

---

## 🔥 Firewall

### Host firewall
| Feature | Description |
|---------|-------------|
| **Open ports** | Open and close the server's ports |
| **Block / allow IPs** | IPs or CIDRs; the management ports are never opened to the internet |
| **Protected ports** | SSH, WireGuard and management ports are protected from accidental closing |
| **Export / Reset** | Download the rules, go back to the defaults |
| **Advanced, Live, History** | With the nftables engine (see above): services, IP rules, port forwarding, 60-second confirm, live counters, change history and restore |

### VPN firewall (rules between networks)
| Feature | Description |
|---------|-------------|
| **Source / destination** | Network, node, group or a custom IP |
| **Protocol and port** | TCP, UDP, ICMP or all; a port, a list or a range |
| **Priority** | Lower number first; the first matching rule decides |
| **Policy matrix** | Shows which network can reach which, and why |
| **Automatic AllowedIPs** | Device configs include the networks they are allowed to reach |

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│ Source Node │ ──► │   VPN Server    │ ──► │  Dest Node  │
│ (10.10.0.3) │     │    VPN rules    │     │ (10.20.0.5) │
└─────────────┘     └─────────────────┘     └─────────────┘
```

All VPN traffic passes through the hub; the VPN rules decide which traffic may pass between networks.

**Examples:** let the office network reach the admin network, block development from production, allow only HTTP/HTTPS, isolate a guest network.

---

## 🐳 Docker Management

> **💡 Looking for an easy way to manage your Docker environment?**
>
> Use **[DockGate](https://github.com/Ali7Zeynalli/dockgate)** — a lightweight, self-hosted Docker management panel. Monitor containers, images, and volumes from a clean web interface without complex setup.
>
> 👉 **[View DockGate on GitHub](https://github.com/Ali7Zeynalli/dockgate)**

---

## 📸 Screenshots

### Web Dashboard
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/web/0.png" alt="Web 0" width="45%">
  <img src="web/public/photo/web/1.png" alt="Web 1" width="45%">
  <img src="web/public/photo/web/2.png" alt="Web 2" width="45%">
  <img src="web/public/photo/web/3.png" alt="Web 3" width="45%">
  <img src="web/public/photo/web/4.png" alt="Web 4" width="45%">
  <img src="web/public/photo/web/5.png" alt="Web 5" width="45%">
  <img src="web/public/photo/web/6.png" alt="Web 6" width="45%">
  <img src="web/public/photo/web/7.png" alt="Web 7" width="45%">
  <img src="web/public/photo/web/8.png" alt="Web 8" width="45%">
  <img src="web/public/photo/web/9.png" alt="Web 9" width="45%">
  <img src="web/public/photo/web/10.png" alt="Web 10" width="45%">
  <img src="web/public/photo/web/11.png" alt="Web 11" width="45%">
  <img src="web/public/photo/web/12.png" alt="Web 12" width="45%">
</div>

### NovusGate Center
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/installer/0.png" alt="Center 0" width="45%">
  <img src="web/public/photo/installer/1.png" alt="Center 1" width="45%">
  <img src="web/public/photo/installer/2.png" alt="Center 2" width="45%">
  <img src="web/public/photo/installer/3.png" alt="Center 3" width="45%">
  <img src="web/public/photo/installer/4.png" alt="Center 4" width="45%">
</div>

> Note: the screenshots are from an earlier version; newer pages (Groups, Limits, Server, Audit and others) are not in them.

---

## 🤝 Contributing

Contributions are welcome ❤️ Bug reports, feature ideas and pull requests are appreciated. Please read the **Developer Guides** before contributing.

---

## ⭐ Support the Project

* ⭐ Star the repository
* 🐛 Report bugs (Issues)
* 💡 Suggest new ideas
* 📣 Share it with others

---

## 🤝 Professional Support / Enterprise Support

> **Finding the installation difficult?** We can help!

### Paid services
| Service | Description |
|---------|-------------|
| 🛠️ **Full installation** | Complete NovusGate setup on your infrastructure |
| 🔧 **Server configuration** | Linux, Docker, firewall and security |
| 📞 **Technical support** | Troubleshooting and ongoing support |
| 📚 **Training** | NovusGate training for your team |

> 💰 **Pricing** depends on the scope and complexity of the work. Contact us for a free consultation.

### Contact
📧 **Email**: Ali.Z.Zeynalli@gmail.com  
💼 **LinkedIn**: [linkedin.com/in/ali7zeynalli](https://linkedin.com/in/ali7zeynalli)  
📱 **Phone**: +49 152 2209 4631 (whatsapp)

> 💼 SLA-backed support is available for enterprise customers.

### 🌍 Supported languages
| Language | Dil |
|----------|-----|
| 🇬🇧 English | İngilis |
| 🇦🇿 Azerbaijani | Azərbaycan |
| 🇩🇪 German | Alman |
| 🇷🇺 Russian | Rus |
| 🇹🇷 Turkish | Türk |

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).

**© 2025 Ali Zeynalli**

Apache 2.0 lets you:
- ✅ Use the software for any purpose (including commercial)
- ✅ Modify and distribute it
- ✅ Use contributors' patent rights

You must:
- 📋 Keep the original copyright notice
- 📋 Include the LICENSE and NOTICE files
- 📋 State significant changes you made
- 📋 Credit the original author

> 📜 See [NOTICE](NOTICE) for attribution requirements.

---

**Made by [Ali Zeynalli](https://github.com/Ali7Zeynalli)**  
*Project NovusGate*
