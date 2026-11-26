// Pure helpers of the home page: chart annotations per day and the share
// of current agents.
import type { Schemas } from '../../api/client'

export type Mark = Schemas['StatsAnnotation']

/** Annotations per day of the history, labels joined ("Blueprint saved (2), Keys rotated"). */
export function marksByDay(marks: Mark[], days: string[]) {
  const out = new Map<string, string>()
  for (const m of marks) {
    if (!days.includes(m.day)) continue
    const text = m.count > 1 ? `${m.label} (${m.count})` : m.label
    out.set(m.day, out.has(m.day) ? `${out.get(m.day)}, ${text}` : text)
  }
  return out
}

/** Share of devices on the newest approved agent release (or the newest reported), percent. */
export const agentShare = (current: number, total: number) => (total ? (current * 100) / total : undefined)

