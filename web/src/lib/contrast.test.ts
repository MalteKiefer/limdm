import { describe, expect, it } from 'vitest'
import { accentTokens, contrast, guard, onColor } from './contrast'

describe('contrast guard', () => {
  it('computes WCAG ratios', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 1)
    expect(contrast('#777777', '#777777')).toBeCloseTo(1, 5)
  })
  it('darkens a pale accent on a light surface until text reads', () => {
    const c = guard('#ffe066', '#ffffff')!
    expect(contrast(c, '#ffffff')).toBeGreaterThanOrEqual(4.5)
  })
  it('lightens a dark accent on a dark surface', () => {
    const c = guard('#1a1a6e', '#131619')!
    expect(contrast(c, '#131619')).toBeGreaterThanOrEqual(4.5)
  })
  it('keeps a good accent as it is', () => {
    expect(guard('#0f6e6e', '#ffffff')).toBe('#0f6e6e')
  })
  it('refuses invalid colors', () => {
    expect(guard('red', '#ffffff')).toBeNull()
    expect(accentTokens('javascript:x', '#ffffff', false)).toBeNull()
  })
  it('picks readable text on the accent', () => {
    expect(onColor('#0f6e6e')).toBe('#ffffff')
    expect(onColor('#3fbfb3')).toBe('#000000')
    const t = accentTokens('#ffe066', '#ffffff', false)!
    expect(contrast(t['--c-on-accent'], t['--c-accent'])).toBeGreaterThanOrEqual(4.5)
    expect(contrast(t['--c-on-accent-soft'], t['--c-accent-soft'])).toBeGreaterThanOrEqual(4.5)
  })
})
