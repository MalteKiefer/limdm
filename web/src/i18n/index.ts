// Translations: one catalog file per area (src/areas/<area>/messages.ts)
// plus the shared core (src/i18n/core.ts). German is the source: its keys
// type every t() call, English must have the same keys (the type of each en
// catalog enforces it), and so must French, Spanish, Italian and Russian
// (messages.<locale>.ts). `npm run i18n` lists keys no code uses.
import { useSyncExternalStore } from 'react'
import { setPrefs, usePrefs, type Locale } from '../lib/prefs'
import { catalogs, catalogVersion, currentLocale, subscribeCatalogs, type MessageKey } from './catalog'

export type { MessageKey }
export type Vars = Record<string, string | number>
export { currentLocale, locales, setServerLocale } from './catalog'

/** BCP 47 tag of a console language for Intl. */
export const intlTag = (l: Locale = currentLocale()) => ({ de: 'de-DE', en: 'en-GB', fr: 'fr-FR', es: 'es-ES', it: 'it-IT', ru: 'ru-RU' })[l]

const plurals = new Map<Locale, Intl.PluralRules>()
const numbers = new Map<Locale, Intl.NumberFormat>()
const memo = <T,>(m: Map<Locale, T>, l: Locale, make: () => T) => m.get(l) ?? (m.set(l, make()), m.get(l)!)

/**
 * A message in language locale: missing there, the English text, then the
 * German one; a key no catalog has shows its last part (the raw value of a
 * dynamic key such as devices.type.<type>), never the key itself.
 */
export function translate(locale: Locale, key: MessageKey, vars?: Vars): string {
  const m = catalogs[locale][key] ?? catalogs.en[key] ?? catalogs.de[key]
  if (m == null) return key.slice(key.lastIndexOf('.') + 1)
  let text: string
  if (typeof m === 'string') text = m
  else {
    const cat = memo(plurals, locale, () => new Intl.PluralRules(intlTag(locale))).select(Number(vars?.count ?? 0)) as keyof typeof m
    text = m[cat] ?? m.other
  }
  if (!vars) return text
  return text.replace(/\{(\w+)\}/g, (all, name: string) => {
    const v = vars[name]
    if (v == null) return all
    return typeof v === 'number' ? memo(numbers, locale, () => new Intl.NumberFormat(intlTag(locale))).format(v) : v
  })
}

/** Translates in the current language; components use useT so they re-render on a change. */
export const t = (key: MessageKey, vars?: Vars) => translate(currentLocale(), key, vars)

export function useT() {
  usePrefs() // re-render when the language changes
  useSyncExternalStore(subscribeCatalogs, catalogVersion) // and when its catalogs arrive
  return t
}

/**
 * Picks the console language: stored in this browser and sent to the server
 * (the language cookie of GET /lang/{lang}), so texts the server writes
 * (labels, problem details, sign in page) follow it.
 */
export function setLocale(l: Locale) {
  setPrefs({ locale: l })
  return syncServerLocale(l)
}

/** Sets the server's language cookie to l; the caller refetches what the server labelled. */
export async function syncServerLocale(l: Locale) {
  try {
    await fetch(`/lang/${l}`, { credentials: 'same-origin', redirect: 'manual' })
  } catch {
    // offline: the server keeps its language until the next choice
  }
}
