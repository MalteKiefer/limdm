// Pure logic of the Logs area: URL state to API query, time ranges,
// priorities, histogram zoom and the live tail backoff.

export type LogSearch = {
  q?: string
  range?: string
  from?: string
  to?: string
  source?: string
  prio?: string
  device?: string
  tab?: string
  sel?: string
  live?: string
}

export const priorities = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'] as const
export const sources = ['journald', 'container', 'file'] as const
export const ranges = ['15m', '1h', '6h', '24h', '7d'] as const
export type Range = (typeof ranges)[number]

const rangeMs: Record<Range, number> = { '15m': 15 * 60_000, '1h': 3_600_000, '6h': 6 * 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000 }

/** Priority groups of the histogram and the badges: most severe first. */
export const prioGroups = [
  { id: 'crit', levels: [0, 1, 2] },
  { id: 'err', levels: [3] },
  { id: 'warning', levels: [4] },
  { id: 'info', levels: [5, 6] },
  { id: 'debug', levels: [7] },
] as const
export type PrioGroup = (typeof prioGroups)[number]['id']

export const prioGroup = (p: number): PrioGroup => prioGroups.find((g) => (g.levels as readonly number[]).includes(p))?.id ?? 'info'

export const prioName = (p: number) => priorities[Math.min(Math.max(p, 0), 7)]

/** The badge tone of a priority. */
export function prioTone(p: number): 'bad' | 'warn' | 'info' | 'neutral' {
  if (p <= 3) return 'bad'
  if (p === 4) return 'warn'
  if (p <= 6) return 'info'
  return 'neutral'
}

/**
 * The time range of the search. Quick ranges end at the next full minute,
 * so the query (and its cache key) stays the same within a minute.
 */
export function timeRange(s: LogSearch, now = Date.now()): { from: string; to: string } {
  if (s.range === 'custom' && s.from) {
    const from = new Date(s.from)
    const to = s.to ? new Date(s.to) : new Date(Math.ceil(now / 60_000) * 60_000)
    if (!isNaN(from.getTime()) && !isNaN(to.getTime()) && from < to) return { from: from.toISOString(), to: to.toISOString() }
  }
  const r = (ranges as readonly string[]).includes(s.range ?? '') ? (s.range as Range) : '1h'
  const to = Math.ceil(now / 60_000) * 60_000
  return { from: new Date(to - rangeMs[r]).toISOString(), to: new Date(to).toISOString() }
}

const quote = (v: string) => (/[\s"]/.test(v) ? `"${v.replaceAll('"', '')}"` : v)

/** The query the server gets: the typed query plus the filter fields. */
export function buildQuery(s: LogSearch): string {
  const parts: string[] = []
  if (s.q?.trim()) parts.push(s.q.trim())
  if (s.source && (sources as readonly string[]).includes(s.source)) parts.push(`source:${s.source}`)
  if (s.prio && (priorities as readonly string[]).includes(s.prio)) parts.push(`prio<=${s.prio}`)
  if (s.device?.trim()) parts.push(`device:${quote(s.device.trim())}`)
  return parts.join(' ')
}

/** API parameters of a search; deviceId fixes one device (device tab). */
export function apiParams(s: LogSearch, deviceId?: string, now = Date.now()) {
  const { from, to } = timeRange(s, now)
  return { q: buildQuery(deviceId ? { ...s, device: undefined } : s) || undefined, from, to, ...(deviceId ? { device: deviceId } : {}) }
}

/** The custom range of one histogram bucket (zoom on click). */
export function zoomTo(at: string, bucketSeconds: number): Partial<LogSearch> {
  const from = new Date(at)
  const to = new Date(from.getTime() + bucketSeconds * 1000)
  return { range: 'custom', from: toLocalInput(from), to: toLocalInput(to) }
}

/** A Date as the value of an input type=datetime-local (local time, minutes). */
export function toLocalInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

/** Wait of the live tail: 5 s, doubling per failure up to a minute. */
export const tailDelay = (failures: number) => Math.min(5000 * 2 ** Math.max(failures, 0), 60_000)

/** Counts of a histogram bucket per priority group. */
export function groupCounts(counts: number[]): Record<PrioGroup, number> {
  const out = { crit: 0, err: 0, warning: 0, info: 0, debug: 0 } as Record<PrioGroup, number>
  counts.forEach((n, p) => (out[prioGroup(p)] += n))
  return out
}

/** Whether any filter narrows the search (for the empty state). */
export const hasFilter = (s: LogSearch) => !!(s.q || s.source || s.prio || s.device)
