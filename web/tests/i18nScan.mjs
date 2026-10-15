// i18n checks shared by tests/i18n.test.mjs and the command line:
//   node tests/i18nScan.mjs [files...]   (default: every .tsx under src)
// prints hard-coded UI text and t() keys missing from the English locale.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

export const LOCALES = fileURLToPath(new URL('../src/i18n/locales', import.meta.url))

export function listFiles(dir, ext) {
  const out = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...listFiles(p, ext))
    else if (p.endsWith(ext)) out.push(p)
  }
  return out
}

export function loadLocale(lang) {
  const out = {}
  for (const f of listFiles(join(LOCALES, lang), '.json')) {
    out[f.split(/[\\/]/).pop().replace(/\.json$/, '')] = JSON.parse(readFileSync(f, 'utf8'))
  }
  return out
}

// flatKeys lists "a.b.c" paths of the string leaves.
export function flatKeys(obj, prefix = '') {
  const out = []
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object') out.push(...flatKeys(v, key))
    else out.push(key)
  }
  return out
}

// Words that stay as they are in every language.
const ALLOWED = new Set([
  'NovusGate', 'WireGuard', 'Fail2Ban', 'GitHub', 'LinkedIn', 'Telegram', 'nftables', 'iptables',
  'Ali Zeynalli', 'admin',
  'Windows', 'macOS', 'Linux', 'Docker', 'Android', 'iOS',
  'QR', 'OK', 'IP', 'CIDR', 'API', 'SSH', 'DNS', 'NAT', 'VPN', 'TCP', 'UDP', 'ICMP', 'IPv4', 'IPv6',
])

function isTechnical(text) {
  const t = text.trim()
  if (ALLOWED.has(t)) return true
  // a list of names that stay as they are: "SSH/WireGuard/API"
  if (t.split(/\s*[/,]\s*/).every((w) => ALLOWED.has(w) || /^[A-Z0-9_\-.:+]+$/.test(w))) return true
  if (/^NovusGate v[\d.]+$/.test(t)) return true // brand and version
  if (/^(sudo|wg|wg-quick|docker|curl|apt|systemctl|nft|iptables)\s/.test(t)) return true // shell commands
  if (/^[A-Z0-9_\-/.:+ ]+$/.test(t)) return true // TCP, UDP/TCP, wg0-style tokens in caps
  if (/^[\d\s.,:/%+\-–—()×·→←↑↓•…]*$/.test(t)) return true // numbers and symbols
  if (/^(&[a-z]+;|\s)+$/.test(t)) return true
  return false
}

function stripComments(src) {
  return src
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:'"`])\/\/[^\n]*/g, (m, p) => p + ' '.repeat(m.length - p.length))
}

const lineOf = (src, index) => src.slice(0, index).split('\n').length

// scanHardcoded finds UI text written into a .tsx file instead of t().
export function scanHardcoded(file) {
  const raw = readFileSync(file, 'utf8')
  const src = stripComments(raw)
  const found = []
  const add = (index, text, kind) => {
    if (!isTechnical(text)) found.push({ file, line: lineOf(src, index), kind, text: text.trim().slice(0, 60) })
  }
  // JSX text between tags: >Text<
  for (const m of src.matchAll(/>([^<>{}]*[A-Za-zƏəÖöÜüĞğİıŞşÇç][^<>{}]*)</g)) {
    const text = m[1]
    // code, not text: operators, or keywords of a switch/interface the regex ran across
    if (/[=;()]|=>|&&|\|\||\b(return|void|default:|case|const|let|interface|type)\b/.test(text) || !text.trim()) continue
    add(m.index + 1, text, 'jsx-text')
  }
  // Text attributes
  for (const m of src.matchAll(/\b(placeholder|title|aria-label|alt|label|description|emptyMessage|helperText)=(["'])([^"']*[A-Za-z][^"']*)\2/g)) {
    add(m.index, m[3], `attr ${m[1]}`)
  }
  // Text properties in object literals (table headers, toasts, nav items)
  for (const m of src.matchAll(/\b(header|label|title|message|description|errorTitle|successTitle|emptyMessage|name):\s*(['"`])([A-Z][^'"`]*)\2/g)) {
    add(m.index, m[3], `prop ${m[1]}`)
  }
  // Browser dialogs
  for (const m of src.matchAll(/\b(confirm|alert|prompt)\(\s*(['"`])([^'"`]*[A-Za-z][^'"`]*)\2/g)) {
    add(m.index, m[3], m[1])
  }
  return found
}

function getPath(obj, path) {
  return path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj)
}

// scanKeys finds t('key') calls whose key is missing from the English locale.
export function scanKeys(file, en) {
  const src = stripComments(readFileSync(file, 'utf8'))
  const ns = /useTranslation\(\s*\[?\s*'([^']+)'/.exec(src)?.[1] ?? 'common'
  const missing = []
  for (const m of src.matchAll(/\b(?:i18n\.)?t\(\s*'([^']+)'/g)) {
    let key = m[1]
    let space = ns
    if (key.includes(':')) [space, key] = key.split(':')
    const tree = en[space]
    const ok = tree && ['', '_one', '_other'].some((s) => typeof getPath(tree, key + s) === 'string')
    if (!ok) missing.push({ file, line: lineOf(src, m.index), key: `${space}:${key}` })
  }
  return missing
}

if (process.argv[1] && process.argv[1].endsWith('i18nScan.mjs')) {
  const files = process.argv.length > 2 ? process.argv.slice(2) : listFiles('src', '.tsx')
  const en = loadLocale('en')
  let n = 0
  for (const f of files) {
    for (const h of scanHardcoded(f)) {
      n++
      console.log(`${relative('.', h.file)}:${h.line}  [${h.kind}]  ${h.text}`)
    }
    for (const k of scanKeys(f, en)) {
      n++
      console.log(`${relative('.', k.file)}:${k.line}  [missing key]  ${k.key}`)
    }
  }
  console.log(`${n} problem(s)`)
  process.exitCode = n ? 1 : 0
}
