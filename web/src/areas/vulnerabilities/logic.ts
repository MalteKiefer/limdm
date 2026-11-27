// Pure logic of the vulnerabilities page: URL search to API query,
// severity levels and colors, remediation share, the acceptance check.

export const severities = ['critical', 'high', 'medium', 'low', 'unknown'] as const
export type Severity = (typeof severities)[number]
export const statuses = ['active', 'accepted', 'remediated'] as const
export type Status = (typeof statuses)[number]

/** Filled segments of the severity bar (4 of 4 for critical). */
export const sevLevel = (s: string | undefined) => ({ critical: 4, high: 3, medium: 2, low: 1 })[s as 'low'] ?? 0

/** Color tokens: severity and status are also named in text, never by color alone. */
export const sevColor: Record<Severity, string> = {
  critical: 'var(--c-bad)',
  high: 'var(--c-s3)',
  medium: 'var(--c-warn-mark)',
  low: 'var(--c-info)',
  unknown: 'var(--c-off)',
}
export const statusColor: Record<Status, string> = {
  active: 'var(--c-bad)',
  accepted: 'var(--c-info)',
  remediated: 'var(--c-ok)',
}

/** The URL state of the page. */
export type Search = {
  q?: string
  sev?: string
  status?: string
  device?: string
  os?: string
  pkg?: string
  from?: string
  to?: string
  kev?: string
  sort?: string
  sel?: string
  full?: string
}

/** The API query of the list for a URL state; status is active by default. */
export function toQuery(s: Search) {
  return {
    q: s.q?.trim() || undefined,
    severity: s.sev || undefined,
    status: s.status || 'active',
    device: s.device || undefined,
    os: s.os || undefined,
    package: s.pkg || undefined,
    from: s.from || undefined,
    to: s.to || undefined,
    kev: s.kev === 'on' ? ('true' as const) : undefined,
    sort: s.sort || '-severity',
  }
}

/** Whether any filter differs from the default view. */
export const filtered = (s: Search) => !!(s.q || s.sev || (s.status && s.status !== 'active') || s.device || s.os || s.pkg || s.from || s.to || s.kev)

/** The URL state without filters (sort, selection and full screen stay). */
export const cleared = (s: Search): Search => ({
  sort: s.sort,
  sel: s.sel,
  full: s.full,
})

/** Share of remediated findings in percent, 0 when there are none. */
export function remediatedPct(f: Partial<Record<Status, number>>) {
  const total = (f.active ?? 0) + (f.accepted ?? 0) + (f.remediated ?? 0)
  return total ? ((f.remediated ?? 0) / total) * 100 : 0
}

/** YYYY-MM-DD of a local date. */
export const isoDay = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

export type AcceptDraft = {
  reason: string
  expires: string
  device_id: string
  package: string
}

/** Errors of an acceptance draft, as the server checks it: reason 1 to 1000, expiry within a year. */
export function checkAccept(d: AcceptDraft, now = new Date()) {
  const errs: Partial<Record<'reason' | 'expires', true>> = {}
  if (!d.reason.trim() || d.reason.trim().length > 1000) errs.reason = true
  const max = new Date(now.getFullYear() + 1, now.getMonth(), now.getDate())
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d.expires) || d.expires < isoDay(now) || d.expires > isoDay(max)) errs.expires = true
  return errs
}

/** The server stores the first day after the expiry; this is the last valid day. */
export const lastDay = (v: string) => new Date(new Date(v).getTime() - 1)
