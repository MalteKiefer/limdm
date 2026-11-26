// Pure helpers of the settings area: list fields, network lists, role
// group lines, backup schedules and colors. Tested in logic.test.ts.
import { contrast } from '../../lib/contrast'

/** Splits a text area into entries: one per line or separated by spaces or commas. */
export const lines = (text: string) => text.split(/[\s,]+/).filter(Boolean)
export const unlines = (list: readonly string[] | null | undefined) => (list ?? []).join('\n')

const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const v6 = /^[0-9a-f:]+(:\d+\.\d+\.\d+\.\d+)?$/i

/** Whether s is an IPv4 or IPv6 address or CIDR range (the server checks again). */
export function isNet(s: string) {
  const [addr, bits, extra] = s.split('/')
  if (extra !== undefined) return false
  const isV4 = v4.test(addr)
  const isV6 = !isV4 && addr.includes(':') && v6.test(addr) && (addr.match(/::/g)?.length ?? 0) <= 1
  if (!isV4 && !isV6) return false
  if (bits === undefined) return true
  if (!/^\d{1,3}$/.test(bits)) return false
  return Number(bits) <= (isV4 ? 32 : 128)
}

/** The first entry of a network list that is no address or range, or undefined. */
export const badNet = (text: string) => lines(text).find((x) => !isNet(x))

export type RoleGroup = { group: string; role: 'admin' | 'helpdesk' | 'auditor'; tags?: string[] }

/** Reads "group; role; tag,tag" lines, as the classic console does. */
export function parseRoleGroups(text: string): { groups: RoleGroup[]; error?: string } {
  const groups: RoleGroup[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const f = line.split(';').map((x) => x.trim())
    if (f.length < 2 || f.length > 3 || !f[0] || !['admin', 'helpdesk', 'auditor'].includes(f[1])) return { groups, error: line }
    const tags = f[2] ? f[2].split(',').map((x) => x.trim()).filter(Boolean) : []
    groups.push({ group: f[0], role: f[1] as RoleGroup['role'], ...(tags.length ? { tags } : {}) })
  }
  return { groups }
}

export const roleGroupsText = (list: readonly RoleGroup[] | null | undefined) =>
  (list ?? []).map((g) => [g.group, g.role, ...(g.tags?.length ? [g.tags.join(',')] : [])].join('; ')).join('\n')

/** Whether text holds a PEM certificate block. */
export const isPEM = (text: string) => !text.trim() || /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(text)

/** A syslog target udp://, tcp:// or tcp+tls://host:port, or empty. */
export const isSyslog = (s: string) => !s || /^(udp|tcp|tcp\+tls):\/\/[^/:\s]+:\d{1,5}$/.test(s.trim())

/** Contrast of a brand color against white and the dark surface; AA needs 4.5 for text and 3 for large marks. */
export function colorCheck(hex: string) {
  if (!/^#[0-9a-f]{6}$/i.test(hex)) return null
  const light = contrast(hex, '#ffffff')
  const dark = contrast(hex, '#16181d')
  return { light, dark, ok: light >= 3 && dark >= 3, text: light >= 4.5 }
}

/** A backup schedule as the API sends and takes it. */
export type Schedule = {
  name: string
  paused?: boolean
  kind: 'interval' | 'weekly' | 'monthly' | 'cron'
  every?: number
  offset?: number
  days?: number[]
  times?: string[]
  day?: number
  cron?: string
  targets: string[]
  keep: Keep
}
export type Keep = { last?: number; days?: number; daily?: number; weekly?: number; monthly?: number; yearly?: number }

export const keepEmpty = (k: Keep) => !Object.values(k).some((v) => (v ?? 0) > 0)

/** Times of a weekly or monthly schedule: HH:MM separated by spaces or commas. */
export const parseTimes = (s: string) => lines(s)
export const badTime = (s: string) => parseTimes(s).find((t) => !/^([01]\d|2[0-3]):[0-5]\d$/.test(t))

/** Weekday indexes (0 Sunday) in Monday first order. */
export const weekOrder = [1, 2, 3, 4, 5, 6, 0]

/** Keeps a schedule's fields that its kind uses, so a preview and a save send what applies. */
export function cleanSchedule(s: Schedule): Schedule {
  const base = { name: s.name, paused: s.paused, kind: s.kind, targets: s.targets, keep: s.keep }
  switch (s.kind) {
    case 'interval':
      return { ...base, every: s.every, offset: s.offset }
    case 'weekly':
      return { ...base, days: s.days, times: s.times }
    case 'monthly':
      return { ...base, day: s.day, times: s.times }
    case 'cron':
      return { ...base, cron: s.cron }
  }
}

/** Base64 of a file's bytes (logo uploads go as JSON). */
export async function fileBase64(f: Blob) {
  const b = new Uint8Array(await f.arrayBuffer())
  let s = ''
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(s)
}
