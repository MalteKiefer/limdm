// Pure helpers of the containers and VMs tab.
import type { Schemas } from '../../api/client'

export type Workload = Schemas['Workload']

/** Badge tone of a workload state; the state text is always shown too. */
export function stateTone(state = ''): 'ok' | 'warn' | 'bad' | 'neutral' {
  if (state === 'running') return 'ok'
  if (['paused', 'frozen', 'restarting', 'created'].includes(state)) return 'warn'
  if (state === 'dead') return 'bad'
  return 'neutral'
}

/** Whether a workload counts as running (offers stop and restart, not start). */
export const isRunning = (state = '') => ['running', 'paused', 'frozen', 'restarting'].includes(state)

/** Groups the workloads by kind in the order the tools were reported. */
export function byKind(items: Workload[], kinds: string[]): [string, Workload[]][] {
  const order = [...kinds, ...items.map((w) => w.kind!).filter((k) => !kinds.includes(k))]
  return [...new Set(order)].map((k) => [k, items.filter((w) => w.kind === k)])
}

/** "nginx:1.27" from a long image reference, keeping the tag or digest. */
export function shortImage(image = ''): string {
  const slash = image.lastIndexOf('/')
  return slash >= 0 && !image.slice(slash).includes(':') ? image : image.slice(slash + 1)
}
