// TanStack Query hooks of the compliance area. Query keys start with
// 'compliance'; the overview score reuses ['stats', 'compliance', days] of the
// home page, which live device events refresh.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'

export const useComplianceStats = (days: number) =>
  useQuery({ queryKey: ['stats', 'compliance', String(days)], queryFn: () => unwrap(api.GET('/api/v1/stats/compliance', { params: { query: { days } } })) })

export const useCompliance = () => useQuery({ queryKey: ['compliance', 'overview'], queryFn: () => unwrap(api.GET('/api/v1/compliance')) })

export const useCheck = (id?: string) =>
  useQuery({
    queryKey: ['compliance', 'check', id],
    enabled: !!id,
    queryFn: () => unwrap(api.GET('/api/v1/compliance/checks/{id}', { params: { path: { id: id! } } })),
  })

export const useHeatmap = (group: 'blueprint' | 'tenant') =>
  useQuery({ queryKey: ['compliance', 'heatmap', group], queryFn: () => unwrap(api.GET('/api/v1/compliance/heatmap', { params: { query: { group } } })) })

export const useHistory = (at: string, device?: string) =>
  useQuery({
    queryKey: ['compliance', 'history', at, device ?? ''],
    placeholderData: keepPreviousData,
    queryFn: () => unwrap(api.GET('/api/v1/compliance/history', { params: { query: { at, device } } })),
  })

export const usePolicies = () => useQuery({ queryKey: ['compliance', 'policies'], queryFn: () => unwrap(api.GET('/api/v1/compliance/policies')) })

export const useExceptions = () =>
  useQuery({ queryKey: ['compliance', 'exceptions'], queryFn: () => unwrap(api.GET('/api/v1/exceptions')).then((p) => (p.items ?? []) as Schemas['Exception'][]) })

export function useAddException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Schemas['ExceptionInput']) => unwrap(api.POST('/api/v1/exceptions', { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance'] }),
  })
}

export function useRevokeException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/exceptions/{id}', { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance'] }),
  })
}

export type ExportKind = 'compliance.csv' | 'compliance-history.csv' | 'exceptions.csv' | 'inventory.csv' | 'audit.csv'

/** Downloads an export through the API and returns its bytes for the checksum. */
export const fetchExport = (kind: ExportKind, query: { at?: string; device?: string } = {}) =>
  unwrap(api.GET('/api/v1/exports/{kind}', { params: { path: { kind }, query }, parseAs: 'blob' })) as Promise<unknown> as Promise<Blob>

/** The latest export.done audit entries (row count and SHA-256 of each file). */
export const useExportAudit = (enabled: boolean) =>
  useQuery({
    queryKey: ['compliance', 'exports'],
    enabled,
    queryFn: () => unwrap(api.GET('/api/v1/audit', { params: { query: { action: 'export.done', limit: 10 } } })),
  })
