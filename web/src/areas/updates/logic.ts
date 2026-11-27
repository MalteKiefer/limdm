// Pure helpers of the updates area.
import type { Pending, Ring } from './api'

/** The ring before r in its tenant's order, if any. */
export function previous(rings: Ring[], r: Ring): Ring | undefined {
  const same = rings.filter((x) => x.tenant_id === r.tenant_id)
  const i = same.findIndex((x) => x.id === r.id)
  return i > 0 ? same[i - 1] : undefined
}

/** Whether approving r lets a newer wave through. */
export function approvable(rings: Ring[], r: Ring): boolean {
  const p = previous(rings, r)
  return !!r.require_approval && !!p && (p.wave ?? 0) > (r.approved_wave ?? 0)
}

/** Security updates first (highest severity first), then by name. */
export function sortPending(list: Pending[]): Pending[] {
  return [...list].sort((a, b) => Number(!!b.security) - Number(!!a.security) || severityRank(b.severity) - severityRank(a.severity) || (a.name ?? '').localeCompare(b.name ?? ''))
}

export function severityRank(s?: string): number {
  return { low: 1, moderate: 2, medium: 2, important: 3, high: 3, critical: 4 }[(s ?? '').toLowerCase()] ?? 0
}

/** Badge tone of an advisory severity. */
export function severityTone(s?: string): 'bad' | 'warn' | 'neutral' {
  const r = severityRank(s)
  return r >= 3 ? 'bad' : r === 2 ? 'warn' : 'neutral'
}

/** Comma separated text as a clean list. */
export function splitList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ]
}
