// WCAG 2.2 contrast helpers for the tenant accent: a tenant may pick any
// color, the console moves it towards black or white until text and focus
// rings on it stay readable.

type RGB = [number, number, number]

export function parseHex(hex: string): RGB | null {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim())
  if (!m) return null
  const n = parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

export const toHex = (c: RGB) => '#' + c.map((v) => Math.round(Math.min(255, Math.max(0, v))).toString(16).padStart(2, '0')).join('')

/** Relative luminance (WCAG 2.2). */
export function luminance([r, g, b]: RGB) {
  const ch = (v: number) => {
    const s = v / 255
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  }
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
}

/** Contrast ratio of two colors, 1 to 21. */
export function contrast(a: string, b: string) {
  const ca = parseHex(a)
  const cb = parseHex(b)
  if (!ca || !cb) return 1
  const [hi, lo] = [luminance(ca), luminance(cb)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

export function mix(a: string, b: string, t: number) {
  const ca = parseHex(a)
  const cb = parseHex(b)
  if (!ca || !cb) return a
  return toHex([0, 1, 2].map((i) => ca[i] + (cb[i] - ca[i]) * t) as RGB)
}

/**
 * Moves color towards black (on a light surface) or white (on a dark one)
 * in small steps until it reaches min contrast against surface. Text in
 * the accent color needs 4.5:1.
 */
export function guard(color: string, surface: string, min = 4.5) {
  if (!parseHex(color)) return null
  const towards = luminance(parseHex(surface)!) > 0.5 ? '#000000' : '#ffffff'
  for (let t = 0; t <= 1.0001; t += 0.05) {
    const c = mix(color, towards, t)
    if (contrast(c, surface) >= min) return c
  }
  return towards
}

/** Black or white, whichever reads better on color. */
export const onColor = (color: string) => (contrast(color, '#ffffff') >= contrast(color, '#000000') ? '#ffffff' : '#000000')

/**
 * The accent tokens for a tenant color on the given surface, or null for an
 * invalid color (the brand teal stays).
 */
export function accentTokens(color: string, surface: string, dark: boolean) {
  const accent = guard(color, surface)
  if (!accent) return null
  const soft = mix(accent, surface, dark ? 0.8 : 0.86)
  return {
    '--c-accent': accent,
    '--c-accent-hover': mix(accent, dark ? '#ffffff' : '#000000', 0.15),
    '--c-on-accent': onColor(accent),
    '--c-accent-soft': soft,
    '--c-on-accent-soft': guard(accent, soft) ?? accent,
  }
}
