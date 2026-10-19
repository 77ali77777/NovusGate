// withProtocol sets a VPN rule form's protocol. Ports belong to TCP and UDP
// only: for All and ICMP the port is cleared, since the server refuses a rule
// that keeps one.
export function withProtocol<F extends { protocol?: string; port?: string }>(
  form: F,
  protocol: string
): F {
  const port = protocol === 'tcp' || protocol === 'udp' ? form.port : ''
  return { ...form, protocol, port }
}

// The rule form (VLAN plan M2) asks, in order: who starts the connection,
// whom it reaches, what traffic, which direction and the decision.

interface RuleSides {
  source_type?: string | null
  source_network_id?: string | null
  source_node_id?: string | null
  source_group_id?: string | null
  source_ip?: string | null
  dest_type?: string | null
  dest_network_id?: string | null
  dest_node_id?: string | null
  dest_group_id?: string | null
  dest_ip?: string | null
}

function sideChosen(
  type?: string | null,
  networkId?: string | null,
  nodeId?: string | null,
  groupId?: string | null,
  ip?: string | null
) {
  switch (type) {
    case 'network':
      return !!networkId
    case 'node':
      return !!nodeId
    case 'group':
      return !!groupId
    case 'custom':
      return !!ip?.trim()
    default:
      return true
  }
}

// missingStep returns the first side whose choice is incomplete, or null.
export function missingStep(form: RuleSides): 'source' | 'dest' | null {
  if (
    !sideChosen(
      form.source_type,
      form.source_network_id,
      form.source_node_id,
      form.source_group_id,
      form.source_ip
    )
  ) {
    return 'source'
  }
  if (
    !sideChosen(
      form.dest_type,
      form.dest_network_id,
      form.dest_node_id,
      form.dest_group_id,
      form.dest_ip
    )
  ) {
    return 'dest'
  }
  return null
}

// autoRuleName names a rule the user left unnamed; the column holds 255.
export function autoRuleName(from: string, to: string, mutual: boolean): string {
  return `${from} ${mutual ? '⇄' : '→'} ${to}`.slice(0, 255)
}

// Common services, so nobody has to know port numbers.
export const SERVICE_PRESETS = [
  { id: 'web', protocol: 'tcp', port: '80,443' },
  { id: 'ssh', protocol: 'tcp', port: '22' },
  { id: 'rdp', protocol: 'tcp', port: '3389' },
  { id: 'files', protocol: 'tcp', port: '445' },
  { id: 'ping', protocol: 'icmp', port: '' },
] as const

export type ServicePreset = (typeof SERVICE_PRESETS)[number]['id']

export function withPreset<F extends { protocol?: string; port?: string }>(
  form: F,
  id: ServicePreset
): F {
  const p = SERVICE_PRESETS.find((s) => s.id === id)
  return p ? { ...form, protocol: p.protocol, port: p.port } : form
}

export function presetOf(form: { protocol?: string; port?: string }): ServicePreset | undefined {
  return SERVICE_PRESETS.find((s) => s.protocol === form.protocol && s.port === (form.port ?? ''))
    ?.id
}

// ruleSummary picks the translation keys of the plain-language sentence
// under the form: firewall:ruleForm.summary.<key> and .what.<what.key>.
export function ruleSummary(form: {
  protocol?: string
  port?: string
  action?: string
  bidirectional?: boolean
}) {
  const decision = form.action === 'accept' ? 'allow' : 'block'
  const key = `${decision}.${form.bidirectional ? 'mutual' : 'oneWay'}`
  const proto = (form.protocol ?? 'all').toUpperCase()
  let what: { key: string; params: Record<string, string> }
  if (form.protocol === 'icmp') what = { key: 'ping', params: {} }
  else if (form.protocol === 'tcp' || form.protocol === 'udp') {
    what = form.port
      ? { key: 'port', params: { proto, port: form.port } }
      : { key: 'proto', params: { proto } }
  } else what = { key: 'all', params: {} }
  return { key, what }
}
