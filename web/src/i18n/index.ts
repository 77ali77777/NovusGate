import { az } from 'date-fns/locale'
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import { setErrorTranslator } from '@/api/errors'

// Translations live in locales/<lang>/<namespace>.json and are picked up
// automatically; every namespace exists in both languages with the same keys
// (tests/i18n.test.mjs).
const files = import.meta.glob('./locales/*/*.json', { eager: true, import: 'default' }) as Record<
  string,
  Record<string, unknown>
>

const resources: Record<string, Record<string, Record<string, unknown>>> = {}
for (const [path, data] of Object.entries(files)) {
  const m = /\.\/locales\/(\w+)\/(\w+)\.json$/.exec(path)
  if (!m) continue
  resources[m[1]] ??= {}
  resources[m[1]][m[2]] = data
}

export const LANGUAGES = [
  { code: 'az', label: 'Azərbaycanca' },
  { code: 'en', label: 'English' },
] as const

const STORAGE_KEY = 'novusgate.lang'

// The saved choice, else Azerbaijani for an Azerbaijani browser, else English.
function initialLanguage(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && LANGUAGES.some((l) => l.code === saved)) return saved
  } catch {
    // storage blocked: fall through to the browser language
  }
  return navigator.language?.toLowerCase().startsWith('az') ? 'az' : 'en'
}

i18n.use(initReactI18next).init({
  resources,
  lng: initialLanguage(),
  fallbackLng: 'en',
  defaultNS: 'common',
  interpolation: { escapeValue: false }, // React escapes
})
document.documentElement.lang = i18n.language

// Known API error codes are shown in the panel's language (apiErrors).
setErrorTranslator((code) =>
  i18n.exists(`apiErrors:${code}`) ? i18n.t(`apiErrors:${code}`) : undefined
)

export function setLanguage(code: string) {
  i18n.changeLanguage(code)
  document.documentElement.lang = code
  try {
    localStorage.setItem(STORAGE_KEY, code)
  } catch {
    // the choice lasts for this page only
  }
}

// dateFnsLocale is the date-fns locale for the panel's language (undefined: English).
export function dateFnsLocale() {
  return i18n.language === 'az' ? az : undefined
}

// locale is the BCP 47 tag dates and numbers are formatted with.
export function locale(): string {
  return i18n.language === 'az' ? 'az-AZ' : 'en-GB'
}

// formatDateTime renders an ISO time in the panel's language.
export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(locale())
}

export default i18n
