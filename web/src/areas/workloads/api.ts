// Query hook of the containers and VMs tab; the key starts with 'devices',
// so check ins refresh it.
import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from '../../api/client'

export const useDeviceWorkloads = (id: string) =>
  useQuery({
    queryKey: ['devices', 'workloads', id],
    queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/workloads', { params: { path: { id } } })),
  })
