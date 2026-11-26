// Translations: one catalog file per area (src/areas/<area>/messages.ts)
// plus the shared core (src/i18n/core.ts). German is the source: its keys
// type every t() call, English must have the same keys (the type of each en
// catalog enforces it). `npm run i18n` lists keys no code uses.
import { getPrefs, usePrefs, type Locale } from '../lib/prefs'
import { catalogs, type MessageKey } from './catalog'

export type { MessageKey }
export type Vars = Record<string, string | number>

let serverLocale: Locale = typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('de') ? 'de' : 'en'

/** The server's choice (cookie or Accept-Language) from /api/v1/me, used until the user picks one. */
export const setServerLocale = (l: Locale) => {
  serverLocale = l
}

export const currentLocale = (): Locale => getPrefs().locale ?? serverLocale

const plurals = { de: new Intl.PluralRules('de'), en: new Intl.PluralRules('en') }
const numbers = { de: new Intl.NumberFormat('de-DE'), en: new Intl.NumberFormat('en-GB') }

export function translate(locale: Locale, key: MessageKey, vars?: Vars): string {
  const m = catalogs[locale][key] ?? catalogs.de[key] ?? key
  const text = typeof m === 'string' ? m : plurals[locale].select(Number(vars?.count ?? 0)) === 'one' ? m.one : m.other
  if (!vars) return text
  return text.replace(/\{(\w+)\}/g, (all, name: string) => {
    const v = vars[name]
    if (v == null) return all
    return typeof v === 'number' ? numbers[locale].format(v) : v
  })
}

/** Translates in the current language; components use useT so they re-render on a change. */
export const t = (key: MessageKey, vars?: Vars) => translate(currentLocale(), key, vars)

export function useT() {
  usePrefs() // re-render when the language changes
  return t
}
