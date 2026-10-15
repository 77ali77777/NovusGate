// Help-tip checks (every input says what it is, who needs it and what
// changing it does), shared by tests/helpTips.test.mjs and the command line:
//   node tests/helpScan.mjs [files...]   (default: every .tsx under src)
// Rules:
// - <Input …> and <Select …> carry help="ns:key";
// - a raw <input>, <select> or <textarea> carries data-help="ns:key" and the
//   same file renders <HelpTip k="ns:key"> (once is enough for a list);
// - every key has non-empty what, who and effect texts in en and az.
import { readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { listFiles, loadLocale } from './i18nScan.mjs'

const SRC = fileURLToPath(new URL('../src', import.meta.url))
// The components that implement the tip are not scanned.
const SKIP = [join('components', 'ui.tsx'), join('components', 'HelpTip.tsx')]
const NO_HELP_TYPES = new Set(['hidden', 'submit', 'button', 'file'])
export const PARTS = ['what', 'who', 'effect']

// jsxTags returns the opening tags named in names, attributes included; a
// ">" inside {…} or a string does not end the tag.
export function jsxTags(text, names) {
  const out = []
  const re = new RegExp(`<(${names.join('|')})(?=[\\s/>])`, 'g')
  let m
  while ((m = re.exec(text)) !== null) {
    let depth = 0
    let quote = ''
    let i = m.index + m[0].length
    for (; i < text.length; i++) {
      const c = text[i]
      if (quote) {
        if (c === quote && text[i - 1] !== '\\') quote = ''
      } else if (c === '"' || c === "'" || c === '`') quote = c
      else if (c === '{') depth++
      else if (c === '}') depth--
      else if (c === '>' && depth === 0) break
    }
    out.push({ name: m[1], tag: text.slice(m.index, i + 1), line: text.slice(0, m.index).split('\n').length })
  }
  return out
}

const attr = (tag, name) => {
  const m = new RegExp(`\\s${name}="([^"]*)"`).exec(tag)
  return m ? m[1] : undefined
}

function lookup(tree, key) {
  const [ns, path] = key.split(':')
  if (!ns || !path) return undefined
  return path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), tree[ns])
}

export function scanHelp(files, locales = { en: loadLocale('en'), az: loadLocale('az') }) {
  const problems = []
  const keys = new Map() // key -> first place it is used
  for (const file of files) {
    const rel = relative(SRC, file)
    if (SKIP.includes(rel)) continue
    const text = readFileSync(file, 'utf8')
    const tips = new Set(jsxTags(text, ['HelpTip']).map((t) => attr(t.tag, 'k')))
    for (const t of jsxTags(text, ['Input', 'Select', 'input', 'select', 'textarea'])) {
      const where = `${rel}:${t.line}`
      if (NO_HELP_TYPES.has(attr(t.tag, 'type') ?? '')) continue
      if (t.name === 'Input' || t.name === 'Select') {
        const k = attr(t.tag, 'help')
        if (!k) problems.push(`${where} <${t.name}> has no help="ns:key"`)
        else keys.set(k, keys.get(k) ?? where)
      } else {
        const k = attr(t.tag, 'data-help')
        if (!k) problems.push(`${where} <${t.name}> has no data-help="ns:key"`)
        else {
          keys.set(k, keys.get(k) ?? where)
          if (!tips.has(k)) problems.push(`${where} <${t.name}> data-help="${k}" but no <HelpTip k="${k}"> in the file`)
        }
      }
    }
    for (const k of tips) if (k) keys.set(k, keys.get(k) ?? rel)
  }
  for (const [k, where] of keys) {
    for (const [lang, tree] of Object.entries(locales)) {
      for (const part of PARTS) {
        const v = lookup(tree, `${k}.${part}`)
        if (typeof v !== 'string' || v.trim() === '') problems.push(`${where} help "${k}": ${lang} ${part} missing`)
      }
    }
  }
  return problems
}

export const sourceFiles = () => listFiles(SRC, '.tsx')

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const files = process.argv.length > 2 ? process.argv.slice(2).map((f) => join(process.cwd(), f)) : sourceFiles()
  const problems = scanHelp(files)
  for (const p of problems) console.log(p)
  console.log(`${problems.length} problem(s)`)
  process.exitCode = problems.length ? 1 : 0
}
