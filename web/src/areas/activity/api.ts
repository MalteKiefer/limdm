// Queries of the activity area. Keys start with 'activity': the live
// stream refreshes them on every new audit entry.
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '../../api/client'

export function useActivity(query: Record<string, string>) {
  return useInfiniteQuery({
    queryKey: ['activity', 'stream', query],
    initialPageParam: '',
    queryFn: ({ pageParam }) => unwrap(api.GET('/api/v1/activity', { params: { query: { ...query, limit: 100, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    getNextPageParam: (last) => last.next_cursor || undefined,
  })
}

export const useHistogram = (query: Record<string, string>) =>
  useQuery({ queryKey: ['activity', 'histogram', query], queryFn: () => unwrap(api.GET('/api/v1/activity/histogram', { params: { query } })) })

export const useAuditStatus = (enabled: boolean) => useQuery({ queryKey: ['activity', 'audit-status'], enabled, queryFn: () => unwrap(api.GET('/api/v1/audit/status')) })

export function useVerify() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.POST('/api/v1/audit/verify')),
    onSuccess: (st) => qc.setQueryData(['activity', 'audit-status'], st),
  })
}
