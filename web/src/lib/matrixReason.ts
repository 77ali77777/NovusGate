// matrixReason turns a policy matrix cell's reason_key (+ rule name) into a
// translated sentence; an unknown key falls back to the server's English
// text. t is i18next's t; kept free of imports so it runs in web/tests.

type T = (key: string, vars?: Record<string, string>) => string

interface Cell {
  verdict: string
  reason: string
  reason_key?: string
  rule?: string
}

const KEYS = new Set(['rule', 'same_network', 'isolated', 'iptables_default'])

export function matrixReason(t: T, cell: Cell): string {
  if (!cell.reason_key || !KEYS.has(cell.reason_key)) return cell.reason
  const base = t(`firewall:matrix.reason.${cell.reason_key}`, { rule: cell.rule ?? '' })
  return cell.verdict === 'partial' ? t('firewall:matrix.reason.partial', { reason: base }) : base
}

// SHORT_MAX is the longest short reason a matrix cell shows.
export const SHORT_MAX = 24

// clip cuts text to max characters, ending with an ellipsis when cut.
export function clip(text: string, max = SHORT_MAX): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

// matrixShortReason is the few words shown under a cell's verdict (visible
// on touch screens, unlike a hover title): the deciding rule's name, or
// same network / isolated / iptables default. Unknown keys show the
// server's text, clipped.
export function matrixShortReason(t: T, cell: Cell): string {
  if (!cell.reason_key || !KEYS.has(cell.reason_key)) return clip(cell.reason)
  if (cell.reason_key === 'rule') {
    return cell.rule ? clip(cell.rule) : t('firewall:matrix.short.rule')
  }
  return clip(t(`firewall:matrix.short.${cell.reason_key}`))
}
