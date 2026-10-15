// System Rules view: the rules NovusGate itself puts into table inet
// novusgate, read from the compiled ruleset (GET /firewall/v2/preview), with
// a short explanation. Panel-made entries (services, IP rules, VPN rules,
// forwards) carry a "svc:", "ip:", "rule:" or "fwd:" comment and are left
// out. Kept free of imports so it runs under `node --experimental-strip-types`.

export interface SystemRule {
  chain: string
  policy: string // the chain's policy ("drop", "accept"), "" for a regular chain
  rule: string
  explanation: string
}

const userComment = /comment "(svc|ip|rule|fwd):/

// Most specific patterns first; the first match explains the rule.
const explanations: [RegExp, string][] = [
  [/iif "lo" accept/, 'Traffic of the server to itself (loopback).'],
  [
    /@blocked_v[46] .*drop/,
    'Blocked addresses (Blocked IPs, Fail2Ban permanent bans) are dropped before anything else.',
  ],
  [/ct state established,related accept/, 'Replies to connections that were already allowed.'],
  [/ct state invalid drop/, 'Malformed or out-of-state packets are dropped.'],
  [
    /@ssh_ports accept/,
    'SSH stays reachable on every detected SSH port, whatever the other rules say.',
  ],
  [/@wg_ports accept/, 'WireGuard ports of all VPN networks.'],
  [/dhcpv6 client/, "DHCPv6 replies for the server's own IPv6 address."],
  [
    /admin ports: VPN only/,
    'Panel, database and API ports are dropped on every interface other than the VPN.',
  ],
  [/tcp dport \{ 8080, 8443 \} accept/, 'The API is reachable from the VPN networks.'],
  [/tcp dport \{ 3007, 5432 \} accept/, 'Panel and database: admin VPN (wg0) only.'],
  [/icmp/, 'Ping and other ICMP messages.'],
  [
    /update @dropped_v[46]/,
    'Records the sources that reach the default drop (shown on the Live tab).',
  ],
  [/comment "default drop"/, 'Everything not allowed above is dropped by the chain policy.'],
  [
    /admin VPN to docker-published postgres/,
    'The admin VPN keeps access to the database Docker publishes.',
  ],
  [
    /docker-published postgres/,
    'Docker publishes the database on all addresses; other interfaces cannot reach it.',
  ],
  [/jump vpn_policy/, 'Traffic from VPN clients goes through the VPN rules and network policies.'],
  [/oifname "wg\*" ct status dnat accept/, 'Port forwards to VPN nodes.'],
  [/oifname "wg\*" counter drop/, 'Other traffic into the VPN networks is dropped.'],
  [/iifname "([^"]+)" oifname "\1" accept/, 'Peers of the same network can reach each other.'],
  [/@egress_v4 accept/, 'Full-tunnel nodes may reach the internet through the server.'],
  [/@egress_v4 masquerade/, 'Full-tunnel traffic leaves with the server address (NAT).'],
  [/vpn default drop/, 'Traffic between VPN networks without an allowing rule is dropped.'],
]

function explain(rule: string): string {
  for (const [re, text] of explanations) {
    if (re.test(rule)) return text
  }
  return ''
}

export function systemRules(script: string): SystemRule[] {
  const out: SystemRule[] = []
  let chain = ''
  let policy = ''
  let inSet = false
  for (const raw of script.split('\n')) {
    const line = raw.trim()
    if (line === '') continue
    const set = /^set \S+ \{$/.exec(line)
    if (set) {
      inSet = true
      continue
    }
    if (inSet) {
      if (line === '}') inSet = false
      continue
    }
    const ch = /^chain (\S+) \{$/.exec(line)
    if (ch) {
      chain = ch[1]
      policy = ''
      continue
    }
    if (line === '}') {
      chain = ''
      continue
    }
    if (!chain) continue
    const hook = /^type .* hook .*;\s*policy (\w+);$/.exec(line)
    if (hook) {
      policy = hook[1]
      continue
    }
    if (userComment.test(line)) continue
    out.push({ chain, policy, rule: line, explanation: explain(line) })
  }
  return out
}
