// TanStack Query hooks of the updates area. Ring and fleet keys start with
// 'updates'; the device view starts with 'devices', so check ins refresh it.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'

export type Ring = Schemas['UpdateRing']
export type RingInput = Schemas['UpdateRingInput']
export type DeviceUpdates = Schemas['DeviceUpdates']
export type Pending = Schemas['PendingUpdate']
export type Fleet = Schemas['UpdatesFleet']

export const keys = {
  rings: ['updates', 'rings'] as const,
  fleet: ['updates', 'fleet'] as const,
  cve: (id: string) => ['updates', 'fleet', 'cve', id] as const,
  versions: (name: string) => ['updates', 'versions', name] as const,
  device: (id: string) => ['devices', 'updates', id] as const,
}

export const useRings = () =>
  useQuery({
    queryKey: keys.rings,
    queryFn: () => unwrap(api.GET('/api/v1/update-rings')),
  })

export const useFleet = () =>
  useQuery({
    queryKey: keys.fleet,
    queryFn: () => unwrap(api.GET('/api/v1/updates/fleet')) as Promise<Fleet>,
  })

export const useCVEDevices = (cve: string) =>
  useQuery({
    queryKey: keys.cve(cve),
    enabled: !!cve,
    queryFn: () =>
      unwrap(api.GET('/api/v1/updates/fleet', { params: { query: { cve } } })) as Promise<{
        items: { id: string; hostname: string; packages: string[] }[]
      }>,
  })

export const useVersions = (name: string) =>
  useQuery({
    queryKey: keys.versions(name),
    enabled: !!name,
    queryFn: () =>
      unwrap(
        api.GET('/api/v1/updates/package-versions', {
          params: { query: { name } },
        }),
      ),
  })

export const useDeviceUpdates = (id: string) =>
  useQuery({
    queryKey: keys.device(id),
    queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/updates', { params: { path: { id } } })),
  })

function useDone() {
  const qc = useQueryClient()
  return () => void qc.invalidateQueries({ queryKey: ['updates'] })
}

export function useRingSave() {
  const done = useDone()
  return useMutation({
    mutationFn: ({ id, body }: { id?: number; body: RingInput }) =>
      id
        ? unwrap(
            api.PUT('/api/v1/update-rings/{id}', {
              params: { path: { id } },
              body,
            }),
          )
        : unwrap(api.POST('/api/v1/update-rings', { body })),
    onSuccess: done,
  })
}

export function useRingDelete() {
  const done = useDone()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/update-rings/{id}', { params: { path: { id } } })),
    onSuccess: done,
  })
}

export function useRingAction() {
  const done = useDone()
  return useMutation({
    mutationFn: ({ id, action }: { id: number; action: 'pause' | 'resume' | 'approve' }) =>
      unwrap(
        api.POST('/api/v1/update-rings/{id}/{action}', {
          params: { path: { id, action } },
        }),
      ),
    onSuccess: done,
  })
}

export function useWaveStart() {
  const done = useDone()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/api/v1/update-waves')),
    onSuccess: done,
  })
}

/** State of the Debian and Ubuntu security data imports; polled while one runs. */
export const useFeeds = () => useQuery({ queryKey: ['updates', 'feeds'], queryFn: () => unwrap(api.GET('/api/v1/updates/cve-feeds')), refetchInterval: (q) => (q.state.data?.running ? 5000 : false) })

export function useFeedsRefresh() {
  const done = useDone()
  return useMutation({ mutationFn: () => unwrap(api.POST('/api/v1/updates/cve-feeds/refresh')), onSuccess: done })
}
