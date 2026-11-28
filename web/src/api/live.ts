// Live updates from /api/v1/events/stream (server sent events). Events are
// hints: they invalidate the queries that show the data, the recent
// activity is kept for the home feed. Query keys feature streams use:
//   ['devices', ...]  ['stats', ...]  ['activity', ...]  ['approvals', ...]
import { QueryClient } from '@tanstack/react-query'
import { useSyncExternalStore } from 'react'
import { ApiError } from './client'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      // a refused or missing resource does not get better by asking again
      retry: (n, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && n < 2,
    },
  },
})

export type ActivityEvent = { id: number; at: string; actor: string; action: string; target: string }
export type LiveState = 'connecting' | 'live' | 'offline'

let state: LiveState = 'connecting'
let recent: ActivityEvent[] = []
let pending: number | null = null
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())
const subscribe = (l: () => void) => {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

export const useLiveState = () => useSyncExternalStore(subscribe, () => state)
/** The latest audit entries received live, newest first (admin and auditor). */
export const useLiveActivity = () => useSyncExternalStore(subscribe, () => recent)
/** Pending approvals and open software requests as the stream last reported them, null before the first event. */
export const useInboxCount = () => useSyncExternalStore(subscribe, () => pending)

function parse<T>(e: Event): T | null {
  try {
    return JSON.parse((e as MessageEvent<string>).data) as T
  } catch {
    return null
  }
}

/** Opens the stream; the returned function closes it. EventSource reconnects by itself. */
export function startLive(qc: QueryClient = queryClient) {
  if (typeof EventSource === 'undefined') return () => {}
  const es = new EventSource('/api/v1/events/stream')
  let timer: ReturnType<typeof setTimeout> | undefined
  // check ins arrive in bursts: refetch at most every two seconds
  const devicesChanged = () => {
    timer ??= setTimeout(() => {
      timer = undefined
      void qc.invalidateQueries({ queryKey: ['devices'] })
      void qc.invalidateQueries({ queryKey: ['stats'] })
    }, 2000)
  }
  es.onopen = () => {
    state = 'live'
    emit()
  }
  es.onerror = () => {
    state = es.readyState === EventSource.CLOSED ? 'offline' : 'connecting'
    emit()
  }
  es.addEventListener('device', devicesChanged)
  es.addEventListener('activity', (e) => {
    const a = parse<ActivityEvent>(e)
    if (!a) return
    recent = [a, ...recent].slice(0, 30)
    emit()
    void qc.invalidateQueries({ queryKey: ['activity'] })
  })
  es.addEventListener('inbox', (e) => {
    const v = parse<{ pending: number; requests?: number }>(e)
    if (!v) return
    pending = v.pending + (v.requests ?? 0)
    emit()
    void qc.invalidateQueries({ queryKey: ['approvals'] })
    void qc.invalidateQueries({ queryKey: ['stats', 'attention'] })
    void qc.invalidateQueries({ queryKey: ['config', 'software'] })
  })
  return () => {
    clearTimeout(timer)
    es.close()
  }
}
