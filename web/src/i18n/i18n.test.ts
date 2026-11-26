import { describe, expect, it } from 'vitest'
import { setPrefs } from '../lib/prefs'
import { catalogs } from './catalog'
import { ago } from './format'
import { translate } from '.'

describe('i18n', () => {
  it('has the same keys in German and English', () => {
    expect(Object.keys(catalogs.en).sort()).toEqual(Object.keys(catalogs.de).sort())
  })
  it('fills placeholders and picks plural forms', () => {
    expect(translate('de', 'bulk.selected', { count: 1200 })).toBe('1.200 ausgewählt')
    expect(translate('en', 'time.days', { count: 1 })).toBe('yesterday')
    expect(translate('en', 'time.days', { count: 3 })).toBe('3 days ago')
    expect(translate('de', 'palette.switchTenant', { name: 'Acme' })).toBe('Mandant wechseln: Acme')
  })
  it('formats relative times in the chosen language', () => {
    setPrefs({ locale: 'de' })
    expect(ago(Date.now() - 3 * 3600_000)).toBe('vor 3 Std.')
    setPrefs({ locale: 'en' })
    expect(ago(Date.now() - 10_000)).toBe('just now')
  })
})
