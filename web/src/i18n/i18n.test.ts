import { describe, expect, it } from 'vitest'
import { setPrefs, type Locale } from '../lib/prefs'
import { browserLocale, catalogs, loadEveryLanguage, type MessageKey } from './catalog'
import { ago, dateTime } from './format'
import { translate } from '.'

await loadEveryLanguage()
const others: Locale[] = ['en', 'fr', 'es', 'it', 'ru']
const placeholders = (m: unknown) => [...JSON.stringify(m).matchAll(/\{(\w+)\}/g)].map((x) => x[1]).sort()
const forms = (m: unknown) => (typeof m === 'string' ? [m] : Object.values(m as object))

describe('i18n', () => {
  it.each(others)('has every German key in %s and no other', (l) => {
    expect(Object.keys(catalogs[l]).sort()).toEqual(Object.keys(catalogs.de).sort())
  })
  it.each(others)('keeps the placeholders and the text kind in %s', (l) => {
    const bad: string[] = []
    for (const [k, de] of Object.entries(catalogs.de)) {
      const m = catalogs[l][k as MessageKey]
      if (typeof m !== typeof de || [...new Set(placeholders(m))].join() !== [...new Set(placeholders(de))].join() || forms(m).some((x) => !x)) bad.push(k)
    }
    expect(bad).toEqual([])
  })
  it('has the Russian plural forms one, few and many', () => {
    const bad = Object.entries(catalogs.ru).filter(([, m]) => typeof m !== 'string' && !(m.one && m.few && m.many && m.other))
    expect(bad.map(([k]) => k)).toEqual([])
    expect(translate('ru', 'time.days', { count: 2 })).not.toBe(translate('ru', 'time.days', { count: 5 }))
  })
  it('fills placeholders and picks plural forms', () => {
    expect(translate('de', 'bulk.selected', { count: 1200 })).toBe('1.200 ausgewählt')
    expect(translate('en', 'time.days', { count: 1 })).toBe('yesterday')
    expect(translate('en', 'time.days', { count: 3 })).toBe('3 days ago')
    expect(translate('de', 'palette.switchTenant', { name: 'Acme' })).toBe('Mandant wechseln: Acme')
  })
  it('shows the raw value of an unknown dynamic key, never the key', () => {
    expect(translate('de', 'devices.type.frobnicate' as MessageKey)).toBe('frobnicate')
  })
  it('picks the first browser language it speaks, else English', () => {
    expect(browserLocale(['pt-BR', 'fr-CA', 'de'])).toBe('fr')
    expect(browserLocale(['ja'])).toBe('en')
  })
  it('formats relative times in the chosen language', () => {
    setPrefs({ locale: 'de' })
    expect(ago(Date.now() - 3 * 3600_000)).toBe('vor 3 Std.')
    setPrefs({ locale: 'en' })
    expect(ago(Date.now() - 10_000)).toBe('just now')
  })
})

describe('dateTime notations', () => {
  it('formats every profile choice', () => {
    const d = new Date(2026, 0, 5, 14, 7)
    expect(dateTime(d, 'iso')).toBe('2026-01-05 14:07')
    expect(dateTime(d, 'de')).toBe('05.01.2026 14:07')
    expect(dateTime(d, 'uk')).toBe('05/01/2026 14:07')
    expect(dateTime(d, 'us')).toBe('01/05/2026 2:07 PM')
    expect(dateTime(new Date(2026, 0, 5, 0, 7), 'us')).toBe('01/05/2026 12:07 AM')
  })
})
