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
