// Query hooks of the containers and VMs tab; the keys start with 'devices',
// so check ins refresh them. A refetch interval is set only while a sent
// command waits (WorkloadsTab); hidden tabs do not poll (TanStack default).
import { useQueries, useQuery } from '@tanstack/react-query'
import { api, unwrap } from '../../api/client'

export const useDeviceWorkloads = (id: string, refetchInterval: () => number | false = () => false) =>
  useQuery({
    queryKey: ['devices', 'workloads', id],
    queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/workloads', { params: { path: { id } } })),
    refetchInterval,
  })

/** Polls sent commands, each with its own interval, and hands every answer to onStatus. */
export const useCommands = (list: { cmd: number; interval: () => number | false; onStatus: (status?: string, output?: string) => void }[]) =>
  useQueries({
    queries: list.map((p) => ({
      queryKey: ['devices', 'command', p.cmd],
      queryFn: async () => {
        const c = await unwrap(api.GET('/api/v1/commands/{id}', { params: { path: { id: p.cmd } } }))
        p.onStatus(c.status, c.output)
        return c
      },
      refetchInterval: p.interval,
    })),
  })
