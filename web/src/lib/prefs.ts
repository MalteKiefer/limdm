// Per browser preferences (theme, density, language, navigation). They live
// in localStorage; everything that matters to other people lives on the server.
import { useSyncExternalStore } from 'react'

export type Theme = 'system' | 'light' | 'dark'
export type Density = 'comfortable' | 'compact'
export type Locale = 'de' | 'en'
export type Prefs = { theme: Theme; density: Density; locale: Locale | null; navCollapsed: boolean }

const KEY = 'limdm.prefs'
const defaults: Prefs = { theme: 'system', density: 'comfortable', locale: null, navCollapsed: false }

function load(): Prefs {
  try {
    return { ...defaults, ...(JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<Prefs>) }
  } catch {
    return defaults
  }
}

let prefs = load()
const listeners = new Set<() => void>()
const dark = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null

/** The theme actually shown: system resolves to the operating system's choice. */
export const resolvedTheme = (p: Prefs = prefs): 'light' | 'dark' => (p.theme === 'system' ? (dark?.matches ? 'dark' : 'light') : p.theme)

function apply() {
  const root = document.documentElement
  root.dataset.theme = resolvedTheme()
  root.dataset.density = prefs.density
}

export function setPrefs(p: Partial<Prefs>) {
  prefs = { ...prefs, ...p }
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs))
  } catch {
    // private mode: the choice lasts for this tab
  }
  apply()
  listeners.forEach((l) => l())
}

dark?.addEventListener('change', () => {
  apply()
  prefs = { ...prefs } // new identity: subscribers re-render with the new resolved theme
  listeners.forEach((l) => l())
})
if (typeof document !== 'undefined') apply()

export const getPrefs = () => prefs
export function subscribePrefs(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}
export function usePrefs() {
  return useSyncExternalStore(subscribePrefs, getPrefs)
}
