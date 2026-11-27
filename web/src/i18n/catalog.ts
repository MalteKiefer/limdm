// The catalogs: the core (shell, navigation, shared components) loads up
// front, every area's catalog with the area's routes (router.tsx), so the
// first load stays small. German and English sit in messages.ts; the other
// languages in messages.<locale>.ts (core.<locale>.ts), loaded only for the
// language in use. A new area adds one loader, one type line and its
// dependencies (catalogs of other areas whose components or keys it uses).
import { getPrefs, subscribePrefs, type Locale } from '../lib/prefs'
import * as core from './core'
import type { Catalog, Msg } from './types'
import type * as activity from '../areas/activity/messages'
import type * as compliance from '../areas/compliance/messages'
import type * as config from '../areas/config/messages'
import type * as devices from '../areas/devices/messages'
import type * as home from '../areas/home/messages'
import type * as inbox from '../areas/inbox/messages'
import type * as logs from '../areas/logs/messages'
import type * as reports from '../areas/reports/messages'
import type * as settings from '../areas/settings/messages'
import type * as updates from '../areas/updates/messages'
import type * as vulns from '../areas/vulnerabilities/messages'
import type * as workloads from '../areas/workloads/messages'

type DE = typeof core.de &
  typeof home.de &
  typeof inbox.de &
  typeof devices.de &
  typeof compliance.de &
  typeof config.de &
  typeof activity.de &
  typeof reports.de &
  typeof settings.de &
  typeof updates.de &
  typeof vulns.de &
  typeof workloads.de &
  typeof logs.de

export type MessageKey = keyof DE & string

type Module = { de: Catalog; en: Catalog }

const loaders = {
  activity: () => import('../areas/activity/messages'),
  compliance: () => import('../areas/compliance/messages'),
  config: () => import('../areas/config/messages'),
  devices: () => import('../areas/devices/messages'),
  home: () => import('../areas/home/messages'),
  inbox: () => import('../areas/inbox/messages'),
  logs: () => import('../areas/logs/messages'),
  reports: () => import('../areas/reports/messages'),
  settings: () => import('../areas/settings/messages'),
  updates: () => import('../areas/updates/messages'),
  vulnerabilities: () => import('../areas/vulnerabilities/messages'),
  workloads: () => import('../areas/workloads/messages'),
} satisfies Record<string, () => Promise<Module>>

export type CatalogId = keyof typeof loaders

/** Catalogs of other areas an area needs (shared tabs, settings forms, blueprint picker). */
const deps: Partial<Record<CatalogId, CatalogId[]>> = {
  home: ['inbox'],
  devices: ['updates', 'workloads', 'logs', 'settings', 'config'],
  workloads: ['devices', 'updates'],
  logs: ['settings'],
  settings: ['updates', 'logs'],
  updates: ['settings', 'config'],
  vulnerabilities: ['settings'],
}

export const catalogs = { de: { ...core.de }, en: { ...core.en }, fr: {}, es: {}, it: {}, ru: {} } as Record<Locale, Record<MessageKey, Msg>>

/** Catalogs of the other languages: path -> loader of a module whose default export is the catalog. */
const extras = import.meta.glob<{ default: Catalog }>(['../areas/*/messages.*.ts', './core.*.ts'])
const extraPath = (id: CatalogId | 'core', l: Locale) => (id === 'core' ? `./core.${l}.ts` : `../areas/${id}/messages.${l}.ts`)

const loading = new Map<string, Promise<void>>()
const loaded = new Set<CatalogId>()

// Components re-render when a catalog arrives (useT subscribes).
let version = 0
const listeners = new Set<() => void>()
export const catalogVersion = () => version
export function subscribeCatalogs(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

function once(key: string, load: () => Promise<void>): Promise<void> {
  let p = loading.get(key)
  if (!p) {
    p = load().then(() => {
      version++
      listeners.forEach((l) => l())
    })
    p.catch(() => loading.delete(key)) // a failed chunk load is tried again next time
    loading.set(key, p)
  }
  return p
}

function loadExtra(id: CatalogId | 'core', l: Locale): Promise<void> {
  if (l === 'de' || l === 'en') return Promise.resolve()
  const load = extras[extraPath(id, l)]
  if (!load) return Promise.resolve()
  return once(`${id}.${l}`, () => load().then((m) => void Object.assign(catalogs[l], m.default)))
}

function loadOne(id: CatalogId, l: Locale = currentLocale()): Promise<void> {
  loaded.add(id)
  return Promise.all([once(id, () => loaders[id]().then((m: Module) => void (Object.assign(catalogs.de, m.de), Object.assign(catalogs.en, m.en)))), loadExtra(id, l)]).then(() => undefined)
}

/** The languages of the console with their own names. */
export const locales: { id: Locale; name: string }[] = [
  { id: 'de', name: 'Deutsch' },
  { id: 'en', name: 'English' },
  { id: 'fr', name: 'Français' },
  { id: 'es', name: 'Español' },
  { id: 'it', name: 'Italiano' },
  { id: 'ru', name: 'Русский' },
]
export const isLocale = (v: unknown): v is Locale => locales.some((l) => l.id === v)

/** The first browser language the console speaks, else English. */
export function browserLocale(langs: readonly string[] = typeof navigator === 'undefined' ? [] : (navigator.languages ?? [navigator.language])): Locale {
  for (const tag of langs) {
    const l = tag?.toLowerCase().slice(0, 2)
    if (isLocale(l)) return l
  }
  return 'en'
}

// The server's choice (cookie or Accept-Language), used until the user picks one.
let serverLocale: Locale = browserLocale()

/** The language in use: the user's choice, else the server's. */
export const currentLocale = (): Locale => getPrefs().locale ?? serverLocale

/** Loads the catalogs of language l: the core and every area loaded so far. */
export function loadLocale(l: Locale): Promise<void> {
  return Promise.all([loadExtra('core', l), ...[...loaded].map((id) => loadExtra(id, l))]).then(() => undefined)
}

/** The server's language from /api/v1/me (cookie or Accept-Language). */
export function setServerLocale(l: string) {
  if (isLocale(l)) serverLocale = l
  void loadLocale(currentLocale())
}
subscribePrefs(() => void loadLocale(currentLocale()))
void loadLocale(currentLocale())

const isCatalog = (id: string): id is CatalogId => id in loaders

/** Loads the catalog of an area (an unknown ID: every catalog) with its dependencies. */
export function loadCatalogs(id: string): Promise<void> {
  if (!isCatalog(id)) return loadAllCatalogs()
  const ids = new Set<CatalogId>([id])
  for (const x of ids) for (const d of deps[x] ?? []) ids.add(d)
  return Promise.all([...ids].map((x) => loadOne(x))).then(() => undefined)
}

/** Every catalog: the command palette, the component gallery, tests. */
export const loadAllCatalogs = (l: Locale = currentLocale()) => Promise.all((Object.keys(loaders) as CatalogId[]).map((id) => loadOne(id, l))).then(() => undefined)

/** Every catalog in every language (tests). */
export const loadEveryLanguage = () =>
  Promise.all([loadAllCatalogs(), ...(['fr', 'es', 'it', 'ru'] as Locale[]).flatMap((l) => [loadExtra('core', l), ...(Object.keys(loaders) as CatalogId[]).map((id) => loadExtra(id, l))])]).then(() => undefined)
