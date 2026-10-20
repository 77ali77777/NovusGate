# NovusGate Web Dashboard - User Guide

## Introduction

The NovusGate Web Dashboard is your visual command center for managing the WireGuard VPN network. It allows you to add devices, monitor connections, download configurations, and manage user access from any browser.

## Getting Started

### Accessing the Dashboard

After installation, the dashboard is available at:
- **URL:** `https://YOUR_SERVER_IP:3007` (or your configured domain)
- **Default Port:** 3007 (HTTPS)

### First Login

1. Open the dashboard URL in your browser
2. Accept the self-signed certificate warning (if applicable)
3. Enter your credentials:
   - **Username:** `admin` (or your configured username)
   - **Password:** Generated during installation (check installation logs)
4. Click **Login**

## Dashboard Overview

```
┌─────────────────────────────────────────────────────────────┐
│  🔷 NovusGate                              [Dark Mode] [👤] │
├─────────────┬───────────────────────────────────────────────┤
│             │                                               │
│  📊 Dashboard│   Welcome to NovusGate                       │
│  🖥️ Nodes    │                                               │
│  🌐 Networks │   ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  ⚙️ Settings │   │ Total   │ │ Online  │ │ Offline │        │
│             │   │   12    │ │    8    │ │    4    │        │
│             │   └─────────┘ └─────────┘ └─────────┘        │
│             │                                               │
│             │   Recent Activity                             │
│             │   ├─ Ali's Phone      Online   2 min ago     │
│             │   ├─ Office Laptop    Online   5 min ago     │
│             │   └─ Home Server      Offline  1 hour ago    │
│             │                                               │
│  [Logout]   │                                               │
└─────────────┴───────────────────────────────────────────────┘
```

## Features

### 📊 Dashboard

The main overview page showing:
- **Total Nodes:** All registered devices
- **Online Nodes:** Currently connected devices
- **Offline Nodes:** Disconnected devices
- **Recent Activity:** Latest connection events

### 🖥️ Nodes (Peer Management)

This is where you manage all VPN-connected devices.

#### Viewing Nodes

The nodes table displays:
| Column | Description |
|--------|-------------|
| Name | Device friendly name |
| Status | Online (🟢), Offline (⚫), Pending (🟡), Expired (🔴) |
| IP Address | Assigned VPN IP |
| Last Handshake | Last successful connection time |
| Transfer | Data sent/received (↑/↓) |
| Expires | Access expiration date (if set) |
| Actions | Edit, Config, Delete buttons |

#### Adding a New Device (Peer)

1. Click **+ Create Peer** button
2. Fill in the form:
   - **Peer Name:** Friendly name (e.g., "Ali's iPhone", "Office PC")
   - **Expiration:** Choose access duration:
     - **Forever:** No time limit
     - **1 Hour:** Temporary access
     - **1 Day:** Daily access
     - **1 Week:** Weekly access
     - **Custom:** Set specific date/time
3. Click **Create & Download Config**
4. A modal appears with connection options

#### Connecting a Device

After creating a peer, you'll see the **Server Config Modal** with multiple tabs:

**Config & QR Tab:**
- View the WireGuard configuration text
- Copy config to clipboard
- Download `.conf` file
- Scan QR code with mobile app

**Windows Tab:**
1. Download WireGuard installer
2. Install the application
3. Click "Import tunnel(s) from file"
4. Select the downloaded `.conf` file
5. Click "Activate"

**macOS Tab:**
1. Download WireGuard from Mac App Store
2. Open the application
3. Import the configuration file
4. Activate the tunnel

**Linux Tab:**
- **Easy Install:** Copy and run the one-line install script
- **Manual Install:**
  ```bash
  sudo apt install wireguard
  sudo nano /etc/wireguard/wg0.conf
  # Paste config
  sudo wg-quick up wg0
  ```

**Docker Tab:**
```bash
docker run -d \
  --name=wireguard-client \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  -v /path/to/wg0.conf:/config/wg0.conf \
  linuxserver/wireguard
```

#### Editing a Device

1. Click the **✏️ Edit** button on any node
2. Modify settings:
   - **Name:** Change device name
   - **Status:** 
     - **Active:** Device can connect
     - **Disabled:** Immediately revoke access
   - **Expiration:** Extend or modify time limit
   - **Device Info:** Update OS, Architecture, Hostname
3. Click **Save Changes**

#### Deleting a Device

1. Click the **🗑️ Delete** button
2. Confirm the deletion
3. Device is permanently removed and access revoked

### 🌐 Networks

Manage VPN network configurations:
- View existing networks
- Create new networks — the CIDR may stay empty, the server takes the next free /24 of the address pool
- See "DNS through the hub" on the network page (whether the hub answers DNS, and why not)
- Edit network settings
- Delete unused networks

### 🔥 Firewall

The Firewall page provides comprehensive control over both host-level and VPN inter-network traffic.

#### Overview Tab

Shows summary statistics:
- **Total Rules:** All firewall rules across chains
- **Blocked IPs:** Number of blocked IP addresses
- **Open Ports:** Ports accepting incoming traffic
- **VPN Rules:** Inter-network traffic rules

#### Host Rules Tab

Manage iptables rules for the server:

| Feature | Description |
|---------|-------------|
| **Chain Selection** | Switch between INPUT, OUTPUT, FORWARD chains |
| **View Rules** | See all rules with target, protocol, source, destination |
| **Delete Rules** | Remove non-protected rules |
| **Protected Rules** | SSH, WireGuard, API rules cannot be deleted |

#### Open Ports Tab

Manage ports accepting incoming connections:

| Column | Description |
|--------|-------------|
| Port | Port number |
| Protocol | TCP, UDP, or Both |
| Source | Allowed source IP (Any = all) |
| Interface | Network interface |
| Status | Open or Protected |
| Actions | Close port (if not protected) |

**Protected Ports:** SSH (22), WireGuard (51820+), and Admin API ports cannot be closed to prevent lockout.

#### VPN Rules Tab

Control traffic flow between VPN networks:

Networks cannot see each other by default (like VLANs); only what a rule allows passes.

**Creating a VPN Rule** (Firewall → Between networks → **VPN rule**) — five questions:
1. **Who?** — the side that starts the connection: a network, one device, a group, an IP address or anyone
2. **To whom?** — what it wants to reach
3. **What?** — everything, a common service (web, SSH, remote desktop, file sharing, ping) or protocol + port
4. **Direction** — **one-way** (A → B; B only answers) or **both ways** (A ⇄ B)
5. **Decision** — Allow, Block or Refuse

The result is written below in one plain sentence. Name, order (priority) and note are under **More**; an empty name becomes "A ⇄ B".

In **Who can reach whom?** pick two networks, devices or groups: the answer comes in one sentence, with the reason and the deciding rule for each direction, and "Write a rule for this pair" right there.

**Example Use Cases:**
- Allow office network to access admin panel
- Block development network from production
- Allow only HTTP/HTTPS between networks
- Isolate guest network from internal resources

**How VPN Rules Work:**
```
Source Node → VPN Server (FORWARD chain) → Destination Node
```
All VPN traffic flows through the server. VPN rules control which traffic can be forwarded.

**Important:** rules do not change device configs — a rule takes effect on the server as soon as it is saved; nothing needs doing on the devices.

#### Blocked IPs Tab

View and manage blocked IP addresses:
- See all blocked IPs with chain and rule number
- One-click unblock functionality
- View associated ports (if port-specific block)

#### Quick Actions

Available on all tabs (except Overview):
- **Open Port:** Allow incoming traffic on a port
- **Block IP:** Block traffic from an IP/CIDR
- **Allow IP:** Whitelist an IP address
- **Export Rules:** Download current firewall rules
- **Refresh:** Reload firewall status

### ⚙️ Settings

#### VPN address pool and server address (admin only)
- **VPN address pool** (default `10.0.0.0/8`): the block every device config routes; networks are made inside it. Choose it once — changing it means every device downloads its config again.
- **Server address (domain)**: configs reach the server by this name (e.g. `vpn.example.com`). When the server moves to a new IP, change only the DNS record.

#### Renewing a device's key
**New key** on the device page: when a config leaked, or the server does not hold the device's key. The old config stops working at once; download the new one. You cannot renew the key of the device you are connected through (it would cut you off) — do it from another device.

#### Change Password

1. Go to **Settings** page
2. Enter **Current Password**
3. Enter **New Password**
4. Confirm new password
5. Click **Update Password**

#### User Management (Admin Only)

**Adding a User:**
1. Click **+ Add User**
2. Enter username and password
3. Select role (Admin/User)
4. Click **Create**

**Deleting a User:**
1. Find the user in the list
2. Click **🗑️ Delete**
3. Confirm deletion

> **Note:** The main `admin` user cannot be deleted.

## Status Indicators

| Status | Icon | Meaning |
|--------|------|---------|
| Online | 🟢 | Device is connected and active |
| Offline | ⚫ | Device is not currently connected |
| Pending | 🟡 | Device created but never connected |
| Expired | 🔴 | Access time has expired |

## Dark Mode

Toggle dark mode using the theme button in the top navigation bar. Your preference is saved automatically.

## Security Best Practices

1. **Change Default Password:** Update the admin password immediately after first login
2. **Use Strong Passwords:** Minimum 12 characters with mixed case, numbers, and symbols
3. **Set Expiration Dates:** Use time-limited access for temporary users
4. **Regular Audits:** Review and remove unused nodes periodically
5. **Secure Config Files:** Keep downloaded `.conf` files secure - they grant VPN access
6. **HTTPS Only:** Always access the dashboard via HTTPS
7. **Logout:** Always log out when finished, especially on shared computers

## Troubleshooting

### Cannot Access Dashboard

| Issue | Solution |
|-------|----------|
| Connection refused | Check if server is running, verify port 3007 is open |
| Certificate error | Accept self-signed certificate or install proper SSL |
| Login failed | Verify credentials, check caps lock |

### Device Won't Connect

| Issue | Solution |
|-------|----------|
| Handshake timeout | Check firewall allows UDP 51820 |
| No internet after connecting | Verify AllowedIPs in config |
| Config not working | Re-download config, check for typos |

### Node Shows Offline

| Issue | Solution |
|-------|----------|
| Just created | Wait for first connection |
| Was online before | Check device's WireGuard app status |
| Expired status | Edit node and extend expiration |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + K` | Quick search |
| `Esc` | Close modal |

## Mobile Access

The dashboard is fully responsive and works on mobile devices:
- Use the hamburger menu (☰) to access navigation
- QR codes are optimized for mobile scanning
- Touch-friendly buttons and controls

## Support

- **Developer:** [Ali Zeynalli](https://github.com/Ali7Zeynalli)
- **Documentation:** See DEVELOPER_GUIDE.md for technical details
- **Issues:** Report bugs on GitHub repository
