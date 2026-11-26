// Inbox logic: the risk of an approval request, the order of the inbox and
// muted warnings (a per browser convenience, 7 days).
import type { Schemas } from '../../api/client'
import type { MessageKey } from '../../i18n'
import { catalogs } from '../../i18n/catalog'

export type Approval = Schemas['Approval']
/** 3 destroys data or opens the device, 2 widens access, 1 changes configuration. */
export type Risk = 1 | 2 | 3

/** The command type of a command request ("wipe", "script", ...), else "". */
export function commandType(a: Pick<Approval, 'action' | 'payload'>): string {
  const p = a.payload as { type?: unknown } | null
  return a.action === 'command' && typeof p?.type === 'string' ? p.type : ''
}

export function risk(a: Pick<Approval, 'action' | 'payload'>): Risk {
  switch (a.action) {
    case 'remote_shell':
      return 3
    case 'command':
      return commandType(a) === 'wipe' ? 3 : 2
    case 'recovery.view':
    case 'user.add':
    case 'user.update':
    case 'user.reset':
    case 'token.add':
      return 2
    default:
      return 1
  }
}

export type InboxItem = { id: string; risk: Risk; at: string; expires?: string }

/** Highest risk first; among equals the one expiring first, then the newest. */
export function byRisk(a: InboxItem, b: InboxItem) {
  return b.risk - a.risk || (a.expires ?? '￿').localeCompare(b.expires ?? '￿') || b.at.localeCompare(a.at)
}

/** The item after id in list, else the one before, else none: where the selection goes after a decision. */
export function nextAfter<T extends { id: string }>(list: T[], id: string): string | undefined {
  const i = list.findIndex((x) => x.id === id)
  if (i < 0) return list[0]?.id
  return (list[i + 1] ?? list[i - 1])?.id
}

const MUTE_KEY = 'limdm.inbox.muted'
export const MUTE_DAYS = 7

type Muted = Record<string, number>

function readMuted(): Muted {
  try {
    return JSON.parse(localStorage.getItem(MUTE_KEY) ?? '{}') as Muted
  } catch {
    return {}
  }
}

/** Warnings muted in this browser until a time; expired entries count as not muted. */
export function isMuted(id: string, now = Date.now()) {
  return (readMuted()[id] ?? 0) > now
}

export function mute(id: string, on: boolean, now = Date.now()) {
  const m: Muted = Object.fromEntries(Object.entries(readMuted()).filter(([k, until]) => until > now && k !== id))
  if (on) m[id] = now + MUTE_DAYS * 86_400_000
  try {
    localStorage.setItem(MUTE_KEY, JSON.stringify(m))
  } catch {
    // private mode: muting lasts for this page only
  }
}

/** A translated label of a dynamic key, or the fallback when the catalog has none. */
function known(key: string, fallback: string, t: (k: MessageKey) => string) {
  return key in catalogs.de ? t(key as MessageKey) : fallback
}

export function actionLabel(a: Pick<Approval, 'action' | 'payload'>, t: (k: MessageKey) => string) {
  const cmd = commandType(a)
  if (cmd) return `${t('inbox.action.command')}: ${known(`inbox.cmd.${cmd}`, cmd, t)}`
  return known(`inbox.action.${a.action}`, a.action, t)
}

