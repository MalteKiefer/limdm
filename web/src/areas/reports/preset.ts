// Report presets: an export kind and its parameters, stored as a saved view
// of the list "reports" (query = URL parameters). "days" is relative: the
// export runs from that many days before today, so a preset stays current.

export const kinds = ['compliance.csv', 'compliance-history.csv', 'inventory.csv', 'packages.csv', 'exceptions.csv', 'audit.csv', 'audit.jsonl'] as const
export type Kind = (typeof kinds)[number]

export type Preset = { kind: Kind; at?: string; device?: string; days?: number; q?: string; actor?: string; action?: string; target?: string }

/** Which parameters a kind takes. */
export const paramsOf = (k: Kind): (keyof Preset)[] =>
  k === 'compliance-history.csv' ? ['at', 'device'] : k === 'audit.csv' || k === 'audit.jsonl' ? ['days', 'q', 'actor', 'action', 'target'] : []

export function encodePreset(p: Preset): string {
  const q = new URLSearchParams({ kind: p.kind })
  for (const k of paramsOf(p.kind)) {
    const v = p[k]
    if (v !== undefined && v !== '') q.set(k, String(v))
  }
  return q.toString()
}

/** Reads a stored preset; null when it names no known kind. */
export function decodePreset(s: string): Preset | null {
  const q = new URLSearchParams(s)
  const kind = q.get('kind') as Kind
  if (!kinds.includes(kind)) return null
  const p: Preset = { kind }
  for (const k of paramsOf(kind)) {
    const v = q.get(k)
    if (!v) continue
    if (k === 'days') {
      const n = Number(v)
      if (Number.isInteger(n) && n > 0 && n <= 3650) p.days = n
    } else (p as Record<string, unknown>)[k] = v
  }
  return p
}

const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

/** The download link of a preset, relative days resolved against now. */
export function presetHref(p: Preset, now = new Date()): string {
  const q = new URLSearchParams()
  for (const k of paramsOf(p.kind)) {
    const v = p[k]
    if (v === undefined || v === '') continue
    if (k === 'days') q.set('from', iso(new Date(now.getFullYear(), now.getMonth(), now.getDate() - Number(v))))
    else q.set(k, String(v))
  }
  const qs = q.toString()
  return `/api/v1/exports/${p.kind}${qs ? `?${qs}` : ''}`
}

/** E-mail addresses from free text: split on commas, semicolons and spaces, empty parts dropped. */
export const parseEmails = (s: string) => s.split(/[\s,;]+/).filter(Boolean)
