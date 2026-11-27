// The catalogs: the core (shell, navigation, shared components) loads up
// front, every area's catalog with the area's routes (router.tsx), so the
// first load stays small. A new area adds one loader, one type line and its
// dependencies (catalogs of other areas whose components or keys it uses).
import * as core from './core'
import type { Catalog } from './types'
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

export const catalogs = { de: { ...core.de }, en: { ...core.en } } as Record<'de' | 'en', Record<MessageKey, Catalog[string]>>

const loading = new Map<CatalogId, Promise<void>>()

function loadOne(id: CatalogId): Promise<void> {
  let p = loading.get(id)
  if (!p) {
    p = loaders[id]().then((m: Module) => {
      Object.assign(catalogs.de, m.de)
      Object.assign(catalogs.en, m.en)
    })
    p.catch(() => loading.delete(id)) // a failed chunk load is tried again next time
    loading.set(id, p)
  }
  return p
}

const isCatalog = (id: string): id is CatalogId => id in loaders

/** Loads the catalog of an area (an unknown ID: every catalog) with its dependencies. */
export function loadCatalogs(id: string): Promise<void> {
  if (!isCatalog(id)) return loadAllCatalogs()
  const ids = new Set<CatalogId>([id])
  for (const x of ids) for (const d of deps[x] ?? []) ids.add(d)
  return Promise.all([...ids].map(loadOne)).then(() => undefined)
}

/** Every catalog: the command palette, the component gallery, tests. */
export const loadAllCatalogs = () => Promise.all((Object.keys(loaders) as CatalogId[]).map(loadOne)).then(() => undefined)
