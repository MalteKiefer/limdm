// Merges the catalogs. A new area adds one import and one entry per line
// below; every area owns its keys under its own prefix (devices.*, ...).
import * as activity from '../areas/activity/messages'
import * as compliance from '../areas/compliance/messages'
import * as config from '../areas/config/messages'
import * as devices from '../areas/devices/messages'
import * as home from '../areas/home/messages'
import * as inbox from '../areas/inbox/messages'
import * as reports from '../areas/reports/messages'
import * as settings from '../areas/settings/messages'
import * as updates from '../areas/updates/messages'
import * as workloads from '../areas/workloads/messages'
import * as core from './core'
import type { Catalog } from './types'

const parts = [core, home, inbox, devices, compliance, config, activity, reports, settings, updates, workloads]

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
  typeof workloads.de

export type MessageKey = keyof DE & string

export const catalogs: Record<'de' | 'en', Record<MessageKey, Catalog[string]>> = {
  de: Object.assign({}, ...parts.map((p) => p.de)),
  en: Object.assign({}, ...parts.map((p) => p.en)),
}
