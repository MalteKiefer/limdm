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

/** How long the tab follows a sent command before it gives up. */
export const WAIT_LIMIT = 180_000

/** Delay of the next poll while a command waits: 2 s, then 3, 5 and 10 s, nothing after WAIT_LIMIT. */
export function pollDelay(elapsed: number): number | false {
  if (elapsed >= WAIT_LIMIT) return false
  if (elapsed < 10_000) return 2000
  if (elapsed < 30_000) return 3000
  return elapsed < 60_000 ? 5000 : 10_000
}

/** What became of a sent command: still waiting, done, failed or given up. */
export function outcome(status: string | undefined, elapsed: number): 'wait' | 'ok' | 'failed' | 'timeout' {
  if (status === 'ok') return 'ok'
  if (status === 'failed' || status === 'expired') return 'failed'
  return elapsed >= WAIT_LIMIT ? 'timeout' : 'wait'
}

/** The end state the agent appends to a workload result ("state: exited"), on its own line or as the
 * last " | " part of a one line result ("start docker web | <id> | state: running"). */
export const resultState = (output = '') => /(?:^|\s\|\s)state: ([^|\n]+?)\s*$/m.exec(output)?.[1] ?? ''

/** The agent's error: the last line of a failed result. */
export const resultError = (output = '') => output.trim().split('\n').pop() ?? ''

/** "nginx:1.27" from a long image reference, keeping the tag or digest. */
export function shortImage(image = ''): string {
  const slash = image.lastIndexOf('/')
  return slash >= 0 && !image.slice(slash).includes(':') ? image : image.slice(slash + 1)
}
