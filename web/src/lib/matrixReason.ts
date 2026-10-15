// matrixReason turns a policy matrix cell's reason_key (+ rule name) into a
// translated sentence; an unknown key falls back to the server's English
// text. t is i18next's t; kept free of imports so it runs in web/tests.

type T = (key: string, vars?: Record<string, string>) => string

const KEYS = new Set(['rule', 'same_network', 'isolated', 'iptables_default'])

export function matrixReason(
  t: T,
  cell: { verdict: string; reason: string; reason_key?: string; rule?: string }
): string {
  if (!cell.reason_key || !KEYS.has(cell.reason_key)) return cell.reason
  const base = t(`firewall:matrix.reason.${cell.reason_key}`, { rule: cell.rule ?? '' })
  return cell.verdict === 'partial' ? t('firewall:matrix.reason.partial', { reason: base }) : base
}
