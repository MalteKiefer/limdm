// Queries of the inbox. Keys start with 'approvals' (the live stream
// refreshes them on every change of pending requests) or 'stats'.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '../../api/client'

export const useApprovals = (history: boolean) =>
  useQuery({
    queryKey: ['approvals', history ? 'all' : 'pending'],
    queryFn: () => unwrap(api.GET('/api/v1/approvals', { params: { query: history ? { limit: 200 } : { status: 'pending', limit: 500 } } })).then((p) => p.items ?? []),
  })

export const useFailedCommands = () =>
  useQuery({
    queryKey: ['stats', 'commands', 'failed'],
    queryFn: () => unwrap(api.GET('/api/v1/commands', { params: { query: { status: 'failed', days: 7, limit: 200 } } })).then((p) => p.items),
  })

export const useAttention = () => useQuery({ queryKey: ['stats', 'attention'], queryFn: () => unwrap(api.GET('/api/v1/stats/attention')) })

/** The audit chain state; only for admins and auditors (enabled). */
export const useAuditStatus = (enabled: boolean) => useQuery({ queryKey: ['activity', 'audit-status'], enabled, queryFn: () => unwrap(api.GET('/api/v1/audit/status')) })

export const useLibraryItem = (id: number | undefined) =>
  useQuery({
    queryKey: ['config', 'library-item', id],
    enabled: !!id,
    queryFn: () => unwrap(api.GET('/api/v1/library-items/{id}', { params: { path: { id: id! } } })),
  })

export function useDecide() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, op, reason }: { id: number; op: 'approve' | 'reject'; reason: string }) =>
      op === 'approve'
        ? unwrap(api.POST('/api/v1/approvals/{id}/approve', { params: { path: { id } }, body: reason ? { reason } : {} }))
        : unwrap(api.POST('/api/v1/approvals/{id}/reject', { params: { path: { id } }, body: { reason } })),
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['approvals'] })
      void qc.invalidateQueries({ queryKey: ['stats', 'attention'] })
    },
  })
}
