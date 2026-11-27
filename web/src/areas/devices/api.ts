// TanStack Query hooks of the devices area. Every key starts with
// 'devices', so the live stream refreshes lists and pages on check ins.
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import type { Inventory } from './types'

export type Device = Schemas['Device']
export type DeviceDetail = Omit<Schemas['DeviceDetail'], 'inventory'> & { inventory: Inventory }
export type TimelineEntry = Schemas['TimelineEntry']
export type ShellSession = Schemas['ShellSession']
export type Params = Record<string, string | number | boolean>

export const keys = {
  list: (q: string, sort: string) => ['devices', 'list', q, sort] as const,
  facets: (q: string) => ['devices', 'facets', q] as const,
  detail: (id: string) => ['devices', 'detail', id] as const,
  packages: (id: string) => ['devices', 'packages', id] as const,
  timeline: (id: string, kind: string) => ['devices', 'timeline', id, kind] as const,
  shells: (id: string) => ['devices', 'shells', id] as const,
  shell: (sid: string) => ['devices', 'shell', sid] as const,
  tokens: ['devices', 'enrollment-tokens'] as const,
}

const PAGE = 200

export function useDeviceList(q: string, sort: string) {
  return useInfiniteQuery({
    queryKey: keys.list(q, sort),
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      unwrap(api.GET('/api/v1/devices', { params: { query: { filter: q || undefined, sort: (sort || undefined) as never, limit: PAGE, cursor: pageParam || undefined } } })),
    getNextPageParam: (p) => p.next_cursor || undefined,
  })
}

export const useFacets = (q: string) => useQuery({ queryKey: keys.facets(q), queryFn: () => unwrap(api.GET('/api/v1/devices/facets', { params: { query: { filter: q || undefined } } })) })

export const useDetail = (id: string) =>
  useQuery({ queryKey: keys.detail(id), queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/detail', { params: { path: { id } } })) as Promise<DeviceDetail> })

export const usePackages = (id: string, enabled = true) =>
  useQuery({ queryKey: keys.packages(id), enabled, queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/packages', { params: { path: { id } } })).then((p) => p.items) })

export function useTimeline(id: string, kind = '', limit = 50) {
  return useInfiniteQuery({
    queryKey: [...keys.timeline(id, kind), limit],
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      unwrap(api.GET('/api/v1/devices/{id}/timeline', { params: { path: { id }, query: { limit, cursor: pageParam || undefined, kind: (kind || undefined) as never } } })),
    getNextPageParam: (p) => p.next_cursor || undefined,
  })
}

export const useShellSessions = (id: string) =>
  useQuery({ queryKey: keys.shells(id), queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/shell-sessions', { params: { path: { id } } })).then((p) => p.items) })

export const useShellSession = (sid: string) =>
  useQuery({ queryKey: keys.shell(sid), refetchInterval: 5000, queryFn: () => unwrap(api.GET('/api/v1/shell-sessions/{sid}', { params: { path: { sid } } })) })

export const useCatalogApps = (enabled: boolean) =>
  useQuery({ queryKey: ['devices', 'catalog-apps'], enabled, staleTime: 300_000, queryFn: () => unwrap(api.GET('/api/v1/devices/catalog-apps')).then((p) => p.items) })

export const useBlueprintList = (enabled: boolean) =>
  useQuery({ queryKey: ['devices', 'blueprints'], enabled, staleTime: 300_000, queryFn: () => unwrap(api.GET('/api/v1/blueprints', { params: { query: { limit: 500 } } })).then((p) => p.items ?? []) })

export const usePeople = (q: string, enabled: boolean) =>
  useQuery({ queryKey: ['devices', 'people', q], enabled, queryFn: () => unwrap(api.GET('/api/v1/devices/primary-users', { params: { query: { q } } })).then((p) => p.items) })

export const useEnrollment = () => useQuery({ queryKey: keys.tokens, queryFn: () => unwrap(api.GET('/api/v1/enrollment-tokens')) })

/** Invalidates everything about devices after an action. */
function useDone() {
  const qc = useQueryClient()
  return () => void qc.invalidateQueries({ queryKey: ['devices'] })
}

/** id is the queued command (absent when it waits for an approval). */
export type CommandResult = { approval: boolean; id?: number }

export function useCommand(id: string) {
  const done = useDone()
  return useMutation({
    mutationFn: async ({ type, params }: { type: string; params?: Params }): Promise<CommandResult> => {
      const r = await unwrap(api.POST('/api/v1/devices/{id}/commands', { params: { path: { id } }, body: { type, params } }))
      const approval = (r as { status?: string }).status === 'pending' && 'approval_id' in (r as object)
      return { approval, id: approval ? undefined : (r as { id?: number }).id }
    },
    onSuccess: done,
  })
}

export function useBulk() {
  const done = useDone()
  return useMutation({
    mutationFn: (b: { ids: string[]; action: string; params?: Params }) => unwrap(api.POST('/api/v1/devices/bulk', { body: b })),
    onSuccess: done,
  })
}

export function usePatch() {
  const done = useDone()
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Schemas['DevicePatch'] }) => unwrap(api.PATCH('/api/v1/devices/{id}', { params: { path: { id } }, body })),
    onSuccess: done,
  })
}

export function useRetire(id: string) {
  const done = useDone()
  return useMutation({ mutationFn: () => unwrap(api.POST('/api/v1/devices/{id}/retire', { params: { path: { id } } })), onSuccess: done })
}

export function useDelete(id: string) {
  const done = useDone()
  return useMutation({ mutationFn: (confirm: string) => unwrap(api.DELETE('/api/v1/devices/{id}', { params: { path: { id }, query: { confirm } } })), onSuccess: done })
}

export function useAgentUpdate(id: string) {
  const done = useDone()
  return useMutation({ mutationFn: (version: string) => unwrap(api.POST('/api/v1/devices/{id}/agent-update', { params: { path: { id } }, body: { version } })), onSuccess: done })
}

export function useRecoveryView(id: string) {
  const done = useDone()
  return useMutation({
    mutationFn: ({ uuid, reason }: { uuid: string; reason: string }) => unwrap(api.POST('/api/v1/devices/{id}/recovery-keys/{uuid}/view', { params: { path: { id, uuid } }, body: { reason } })),
    onSuccess: done,
  })
}

export function useShellStart(id: string) {
  const done = useDone()
  return useMutation({ mutationFn: (user: string) => unwrap(api.POST('/api/v1/devices/{id}/shell', { params: { path: { id } }, body: { user } })) as Promise<{ id?: string; status: string }>, onSuccess: done })
}

export function useShellEnd() {
  const done = useDone()
  return useMutation({ mutationFn: (sid: string) => unwrap(api.POST('/api/v1/shell-sessions/{sid}/end', { params: { path: { sid } } })), onSuccess: done })
}

export function useTokenCreate() {
  const done = useDone()
  return useMutation({ mutationFn: (b: { note: string; blueprint_id: number; uses: number; days: number }) => unwrap(api.POST('/api/v1/enrollment-tokens', { body: b })), onSuccess: done })
}

export function useTokenRevoke() {
  const done = useDone()
  return useMutation({ mutationFn: (id: string) => unwrap(api.DELETE('/api/v1/enrollment-tokens/{id}', { params: { path: { id } } })), onSuccess: done })
}
