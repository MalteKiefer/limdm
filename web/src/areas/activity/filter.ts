// The activity filter: URL search parameters to API query parameters and
// export links. Pure, so the rules are tested without a browser.

export const categories = ['commands', 'changes', 'approvals', 'access', 'devices', 'audit', 'events'] as const
export type Category = (typeof categories)[number]

export type ActivitySearch = { q?: string; cat?: Category; actor?: string; action?: string; target?: string; from?: string; to?: string }

const day = /^\d{4}-\d{2}-\d{2}$/

/** Cleans untrusted URL values: unknown categories and malformed dates are dropped. */
export function parseSearch(s: Record<string, unknown>): ActivitySearch {
  const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 200) : undefined)
  const date = (v: unknown) => (typeof v === 'string' && day.test(v) ? v : undefined)
  return {
    q: str(s.q),
    cat: categories.includes(s.cat as Category) ? (s.cat as Category) : undefined,
    actor: str(s.actor),
    action: str(s.action),
    target: str(s.target),
    from: date(s.from),
    to: date(s.to),
  }
}

/** Query parameters of /api/v1/activity and its histogram. */
export function apiQuery(s: ActivitySearch): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of ['q', 'actor', 'action', 'target', 'from', 'to'] as const) if (s[k]) out[k] = s[k]
  if (s.cat) out.category = s.cat
  return out
}

/** Link of an audit export with the filters the export understands (the category is not one). */
export function exportHref(kind: 'audit.csv' | 'audit.jsonl', s: ActivitySearch) {
  const q = apiQuery(s)
  delete q.category
  const qs = new URLSearchParams(q).toString()
  return `/api/v1/exports/${kind}${qs ? `?${qs}` : ''}`
}

export const hasFilter = (s: ActivitySearch) => Object.values(s).some(Boolean)
