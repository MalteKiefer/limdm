// Pure helpers of the blueprint assignment map (api.Node): the tree editor
// edits it immutably, the overview counts and lists its items.
import type { Node } from './api'

export type Rule = { field: string; op: string; value: string }
export type Branch = { match: 'all' | 'any'; rules: Rule[]; nodes: Node[] }

/** Library item IDs of a map, each once, in the order they appear. */
export function treeItems(nodes: Node[] | undefined, out: number[] = []): number[] {
  for (const n of nodes ?? []) {
    for (const id of n.items ?? []) if (!out.includes(id)) out.push(id)
    for (const b of (n.branches ?? []) as Branch[]) treeItems(b.nodes, out)
    treeItems(n.else, out)
  }
  return out
}

/** Moves entry i of a list by delta (up -1, down +1); out of range is a no op. */
export function move<T>(list: T[], i: number, delta: number): T[] {
  const j = i + delta
  if (j < 0 || j >= list.length) return list
  const next = list.slice()
  ;[next[i], next[j]] = [next[j], next[i]]
  return next
}

export const replaceAt = <T>(list: T[], i: number, v: T) => list.map((x, j) => (j === i ? v : x))
export const removeAt = <T>(list: T[], i: number) => list.filter((_, j) => j !== i)

/** Operators without a value. */
export const noValue = (op: string) => op === 'present' || op === 'absent'

/** A new rule for field with its first operator. */
export function newRule(fields: Record<string, string[]>, field = Object.keys(fields).sort()[0] ?? 'tag'): Rule {
  return { field, op: fields[field]?.[0] ?? 'eq', value: '' }
}

export const newAssign = (): Node => ({ kind: 'assign', items: [] })
export const newIf = (fields: Record<string, string[]>): Node => ({ kind: 'if', branches: [{ match: 'all', rules: [newRule(fields)], nodes: [newAssign()] }], else: [] })

/** Problems the server would refuse, by path, so the editor marks them before a save. */
export function treeProblems(nodes: Node[], fields: Record<string, string[]>, path = 'tree'): Record<string, string> {
  const out: Record<string, string> = {}
  nodes.forEach((n, i) => {
    const p = `${path}.${i}`
    if (n.kind === 'if') {
      const bs = (n.branches ?? []) as Branch[]
      if (!bs.length) out[p] = 'noBranch'
      bs.forEach((b, j) => {
        b.rules.forEach((r, k) => {
          if (!fields[r.field]?.includes(r.op)) out[`${p}.b${j}.r${k}`] = 'badRule'
          else if (!noValue(r.op) && !r.value.trim()) out[`${p}.b${j}.r${k}`] = 'noValue'
        })
        if (!b.rules.length) out[`${p}.b${j}`] = 'noRules'
        Object.assign(out, treeProblems(b.nodes ?? [], fields, `${p}.b${j}`))
      })
      Object.assign(out, treeProblems(n.else ?? [], fields, `${p}.else`))
    }
  })
  return out
}
