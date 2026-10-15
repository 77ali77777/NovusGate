// System Rules view: the rules NovusGate itself puts into table inet
// novusgate, read from the compiled ruleset (GET /firewall/v2/preview), with
// a short explanation (a translation key the view resolves). Panel-made entries (services, IP rules, VPN rules,
// forwards) carry a "svc:", "ip:", "rule:" or "fwd:" comment and are left
// out. Kept free of imports so it runs under `node --experimental-strip-types`.

export interface SystemRule {
  chain: string
  policy: string // the chain's policy ("drop", "accept"), "" for a regular chain
  rule: string
  explanation: string // translation key (firewallv2 namespace), '' when unknown
}

const userComment = /comment "(svc|ip|rule|fwd):/

// Most specific patterns first; the first match explains the rule. Each
// explanation is a translation key in the firewallv2 namespace.
const explanations: [RegExp, string][] = [
  [/iif "lo" accept/, 'systemRules.explain.loopback'],
  [/@blocked_v[46] .*drop/, 'systemRules.explain.blocked'],
  [/ct state established,related accept/, 'systemRules.explain.established'],
  [/ct state invalid drop/, 'systemRules.explain.invalid'],
  [/@ssh_ports accept/, 'systemRules.explain.ssh'],
  [/@wg_ports accept/, 'systemRules.explain.wireguard'],
  [/dhcpv6 client/, 'systemRules.explain.dhcpv6'],
  [/admin ports: VPN only/, 'systemRules.explain.adminPortsVpnOnly'],
  [/tcp dport \{ 8080, 8443 \} accept/, 'systemRules.explain.apiFromVpn'],
  [/tcp dport \{ 3007, 5432 \} accept/, 'systemRules.explain.panelDbAdminVpn'],
  [/icmp/, 'systemRules.explain.icmp'],
  [/update @dropped_v[46]/, 'systemRules.explain.recordDropped'],
  [/comment "default drop"/, 'systemRules.explain.defaultDrop'],
  [/admin VPN to docker-published postgres/, 'systemRules.explain.adminVpnPostgres'],
  [/docker-published postgres/, 'systemRules.explain.dockerPostgres'],
  [/jump vpn_policy/, 'systemRules.explain.vpnPolicy'],
  [/oifname "wg\*" ct status dnat accept/, 'systemRules.explain.forwardsToNodes'],
  [/oifname "wg\*" counter drop/, 'systemRules.explain.vpnInboundDrop'],
  [/iifname "([^"]+)" oifname "\1" accept/, 'systemRules.explain.sameNetwork'],
  [/@egress_v4 accept/, 'systemRules.explain.egressAccept'],
  [/@egress_v4 masquerade/, 'systemRules.explain.egressMasquerade'],
  [/vpn default drop/, 'systemRules.explain.vpnDefaultDrop'],
]

// explain returns the translation key of the rule's explanation, '' if none.
function explain(rule: string): string {
  for (const [re, key] of explanations) {
    if (re.test(rule)) return key
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
