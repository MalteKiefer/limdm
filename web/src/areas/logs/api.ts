// TanStack Query hooks of the Logs area; keys start with 'logs'.
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import { saveBlob } from '../../components/download'
import { tailDelay, type apiParams } from './logic'

export type LogLine = Schemas['LogLine']
export type LogAlert = Schemas['LogAlert']
export type LogAlertInput = Schemas['LogAlertInput']
type Params = ReturnType<typeof apiParams>

export const keys = {
  all: ['logs'] as const,
  list: (p: Params) => ['logs', 'list', p] as const,
  hist: (p: Params) => ['logs', 'hist', p] as const,
  facets: (p: Params) => ['logs', 'facets', p] as const,
  context: (id: string) => ['logs', 'context', id] as const,
  alerts: ['logs', 'alerts'] as const,
  status: ['logs', 'status'] as const,
}

/** The lines, newest first; live polls the first pages with backoff. */
export function useLogs(p: Params, live: boolean) {
  return useInfiniteQuery({
    queryKey: keys.list(p),
    initialPageParam: '',
    queryFn: ({ pageParam }) => unwrap(api.GET('/api/v1/logs', { params: { query: { ...p, limit: 200, cursor: pageParam || undefined } } })),
    getNextPageParam: (pg) => pg.next_cursor || undefined,
    refetchInterval: (q) => (live ? tailDelay(q.state.fetchFailureCount) : false),
    retry: live ? 0 : 1,
  })
}

export const useHistogram = (p: Params, live: boolean) =>
  useQuery({ queryKey: keys.hist(p), queryFn: () => unwrap(api.GET('/api/v1/logs/histogram', { params: { query: p } })), refetchInterval: (q) => (live ? tailDelay(q.state.fetchFailureCount) * 2 : false) })

export const useFacets = (p: Params) => useQuery({ queryKey: keys.facets(p), queryFn: () => unwrap(api.GET('/api/v1/logs/facets', { params: { query: p } })), staleTime: 60_000 })

export const useLogContext = (id: string) =>
  useQuery({ queryKey: keys.context(id), enabled: !!id, queryFn: () => unwrap(api.GET('/api/v1/logs/context', { params: { query: { id, n: 15 } } })) })

/** Downloads the current filter as NDJSON or CSV (the server audits it). */
export async function exportLogs(p: Params, format: 'ndjson' | 'csv') {
  const blob = (await unwrap(api.GET('/api/v1/logs/export', { params: { query: { ...p, format } }, parseAs: 'blob' }))) as unknown as Blob
  saveBlob(blob, `limdm-logs.${format}`)
}

export const useAlerts = () => useQuery({ queryKey: keys.alerts, queryFn: () => unwrap(api.GET('/api/v1/logs/alerts')) })

export function useSaveAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: LogAlertInput & { id?: number }) =>
      unwrap(id ? api.PUT('/api/v1/logs/alerts/{id}', { params: { path: { id } }, body }) : api.POST('/api/v1/logs/alerts', { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.alerts }),
  })
}

export function useDeleteAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/logs/alerts/{id}', { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.alerts }),
  })
}

export const useTestAlert = () => useMutation({ mutationFn: (id: number) => unwrap(api.POST('/api/v1/logs/alerts/{id}/test', { params: { path: { id } } })) })

export const useLogStatus = (on = true) => useQuery({ queryKey: keys.status, enabled: on, queryFn: () => unwrap(api.GET('/api/v1/logs/status')) })

export function useLogAction<T>(fn: (v: T) => Promise<unknown>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => qc.invalidateQueries({ queryKey: keys.status }) })
}

export const rotateKeys = () => unwrap(api.POST('/api/v1/logs/keys/rotate'))
export const runArchive = () => unwrap(api.POST('/api/v1/logs/archive/run'))
export const restoreDay = (day: string) => unwrap(api.POST('/api/v1/logs/archive/restore', { body: { day } }))
