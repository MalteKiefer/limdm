import { describe, expect, it } from 'vitest'
import { apiQuery, exportHref, hasFilter, parseSearch } from './filter'

describe('activity filter', () => {
  it('drops unknown categories and bad dates', () => {
    expect(parseSearch({ cat: 'secret', from: '1.1.2026', to: '2026-02-01', q: '  ssh ' })).toEqual({ q: 'ssh', to: '2026-02-01', cat: undefined, actor: undefined, action: undefined, target: undefined, from: undefined })
  })

  it('maps the category for the API but not for exports', () => {
    const s = parseSearch({ cat: 'commands', actor: 'anna', target: 'd1' })
    expect(apiQuery(s)).toEqual({ actor: 'anna', target: 'd1', category: 'commands' })
    expect(exportHref('audit.csv', s)).toBe('/api/v1/exports/audit.csv?actor=anna&target=d1')
    expect(exportHref('audit.jsonl', {})).toBe('/api/v1/exports/audit.jsonl')
    expect(hasFilter({})).toBe(false)
    expect(hasFilter(s)).toBe(true)
  })
})
