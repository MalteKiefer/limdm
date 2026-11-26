// Pure logic of the compliance area: filtering and sorting the checks,
// framework references, the heatmap matrix and the risk exception rules
// (the same rules the server checks in addException).
import type { Schemas } from '../../api/client'

export type Check = Schemas['ComplianceCheck']
export type Control = Schemas['ComplianceControl']
export type Exception = Schemas['Exception']
export type Framework = 'bsi' | 'cis' | 'iso'
export const frameworks: Framework[] = ['bsi', 'cis', 'iso']

/** Target pass rate drawn in bullets, as on the home page. */
export const TARGET = 95

export type CheckFilter = { q?: string; state?: string; level?: string; fw?: string }

/** Pass rate of the evaluated results in percent; null without any. */
export function passRate(c: { pass: number; fail: number }): number | null {
  const n = c.pass + c.fail
  return n ? (c.pass / n) * 100 : null
}

export const refsOf = (c: Pick<Check, 'refs'>, fw: Framework): string[] => c.refs?.[fw] ?? []

export function filterChecks(checks: Check[], f: CheckFilter): Check[] {
  const q = f.q?.trim().toLowerCase()
  return checks.filter(
    (c) =>
      !(f.state === 'failing' && c.fail === 0) &&
      !(f.state === 'passing' && (c.fail > 0 || c.pass === 0)) &&
      !(f.level && String(c.level) !== f.level) &&
      !(f.fw && frameworks.includes(f.fw as Framework) && refsOf(c, f.fw as Framework).length === 0) &&
      !(q && !`${c.id} ${c.title}`.toLowerCase().includes(q)),
  )
}

const sorters: Record<string, (a: Check, b: Check) => number> = {
  fail: (a, b) => a.fail - b.fail,
  title: (a, b) => a.title.localeCompare(b.title),
  id: (a, b) => a.id.localeCompare(b.id),
  level: (a, b) => a.level - b.level,
  rate: (a, b) => (passRate(a) ?? 101) - (passRate(b) ?? 101),
}

/** Sorts by `field` or `-field`; the default puts the most failing first. */
export function sortChecks(checks: Check[], sort = '-fail'): Check[] {
  const desc = sort.startsWith('-')
  const fn = sorters[sort.replace(/^-/, '')] ?? sorters.fail
  return [...checks].sort((a, b) => (desc ? -fn(a, b) : fn(a, b)) || a.id.localeCompare(b.id))
}

/** The area of a check: its ID up to the first dot (ssh, kernel, custom ...). */
export const areaOf = (id: string) => id.split('.')[0]

export type HeatCell = { column: string; area: string; pass: number; fail: number }

/** Rows (areas), columns and the pass rate per cell (null: no result). */
export function heatMatrix(cells: HeatCell[]) {
  const areas = [...new Set(cells.map((c) => c.area))].sort()
  const columns = [...new Set(cells.map((c) => c.column))].sort()
  const at = new Map(cells.map((c) => [`${c.area}\u0000${c.column}`, c]))
  const rate = areas.map((a) => columns.map((col) => {
    const c = at.get(`${a}\u0000${col}`)
    return c ? passRate(c) : null
  }))
  return { areas, columns, rate, cell: (a: string, col: string) => at.get(`${a}\u0000${col}`) }
}

export type ExceptionState = 'active' | 'expired' | 'revoked'

export function countStates(list: Exception[]): Record<ExceptionState | 'all', number> {
  const out = { active: 0, expired: 0, revoked: 0, all: list.length }
  for (const e of list) out[e.state as ExceptionState]++
  return out
}

/** Active exceptions that cover a check. */
export const activeFor = (list: Exception[], check: string) => list.filter((e) => e.state === 'active' && e.check_id === check)

const ident = /^[A-Za-z0-9._-]{1,64}$/
const tagRe = /^[A-Za-z0-9._-]{1,32}$/

export type ExceptionDraft = { check_id: string; mode: string; tag: string; reason: string; owner: string; approver: string; expires: string }

export type ExceptionError = 'check' | 'mode' | 'tag' | 'reason' | 'owner' | 'approver' | 'self' | 'expires'

/** Whether the user adds exceptions directly (admin, four eyes off) or asks for them (helpdesk, or four eyes on). */
export const exceptionPath = (me: { role: string; four_eyes: boolean; permissions: string[] }): 'direct' | 'request' | null =>
  me.role === 'admin' && me.permissions.includes('admin') && !me.four_eyes ? 'direct' : me.permissions.includes('commands') || me.permissions.includes('admin') ? 'request' : null

/** Validates a new exception like the server; returns the first error per field. A request has no approver. */
export function checkException(d: ExceptionDraft, opts: { fourEyes: boolean; login: string; today?: Date; request?: boolean }): Partial<Record<keyof ExceptionDraft, ExceptionError>> {
  const err: Partial<Record<keyof ExceptionDraft, ExceptionError>> = {}
  if (!ident.test(d.check_id.trim())) err.check_id = 'check'
  if (d.mode !== 'exclude' && d.mode !== 'advisory') err.mode = 'mode'
  if (d.tag.trim() && !tagRe.test(d.tag.trim())) err.tag = 'tag'
  if (!d.reason.trim() || d.reason.trim().length > 1000) err.reason = 'reason'
  if (!d.owner.trim() || d.owner.trim().length > 200) err.owner = 'owner'
  const who = opts.login.replace(/^local:/, '').toLowerCase()
  // a request names no approver: the admin who approves it is recorded
  if (!opts.request && (!d.approver.trim() || d.approver.trim().length > 200)) err.approver = 'approver'
  else if (!opts.request && opts.fourEyes && d.approver.trim().toLowerCase() === who) err.approver = 'self'
  const today = opts.today ?? new Date()
  const day = /^\d{4}-\d{2}-\d{2}$/.test(d.expires) ? new Date(`${d.expires}T00:00:00`) : null
  const min = new Date(today.getFullYear(), today.getMonth(), today.getDate())
  const max = new Date(today.getFullYear() + 3, today.getMonth(), today.getDate())
  if (!day || isNaN(day.getTime()) || day < min || day > max) err.expires = 'expires'
  return err
}

/** YYYY-MM-DD of a local date. */
export const isoDay = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
