import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { contrast } from './contrast'

const css = readFileSync('src/styles.css', 'utf8')

/** The color tokens of one theme block of styles.css. */
function tokens(selector: string) {
  const start = css.indexOf(selector + ' {')
  const block = css.slice(start, css.indexOf('}', start))
  return Object.fromEntries([...block.matchAll(/--c-([a-z0-9-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1], m[2]]))
}

describe('status pill contrast (WCAG AA 4.5:1 for 12.5px text)', () => {
  for (const [theme, selector] of [
    ['light', ':root'],
    ['dark', ":root[data-theme='dark']"],
  ]) {
    const c = tokens(selector)
    for (const tone of ['ok', 'warn', 'bad', 'off', 'info']) {
      it(`${theme} ${tone}`, () => {
        expect(contrast(c[tone], c[`${tone}-soft`])).toBeGreaterThanOrEqual(4.5)
      })
    }
  }
})
