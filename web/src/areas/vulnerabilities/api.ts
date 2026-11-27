// TanStack Query hooks of the vulnerabilities area; keys start with 'vulns'.
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import { saveBlob } from '../../components/download'
import type { toQuery } from './logic'

export type Vuln = Schemas['Vulnerability']
export type VulnDetail = Schemas['VulnerabilityDetail']
export type VulnSummary = Schemas['VulnerabilitySummary']
export type Acceptance = Schemas['CVEAcceptance']
type Query = ReturnType<typeof toQuery>

export const keys = {
  all: ['vulns'] as const,
  list: (q: Query) => ['vulns', 'list', q] as const,
  summary: ['vulns', 'summary'] as const,
  detail: (cve: string) => ['vulns', 'detail', cve] as const,
}

const PAGE = 100

export function useVulns(q: Query) {
  return useInfiniteQuery({
    queryKey: keys.list(q),
    initialPageParam: '',
    // JSON here; the same path answers CSV with format=csv
    queryFn: ({ pageParam }) =>
      unwrap(api.GET('/api/v1/vulnerabilities', { params: { query: { ...q, sort: q.sort as never, limit: PAGE, cursor: pageParam || undefined } } })) as Promise<Schemas['VulnerabilityList']>,
    getNextPageParam: (p) => p.next_cursor || undefined,
  })
}

export const useVulnSummary = () =>
  useQuery({
    queryKey: keys.summary,
    queryFn: () => unwrap(api.GET('/api/v1/vulnerabilities/summary')),
  })

export const useVuln = (cve: string) =>
  useQuery({
    queryKey: keys.detail(cve),
    enabled: !!cve,
    queryFn: () => unwrap(api.GET('/api/v1/vulnerabilities/{cve}', { params: { path: { cve } } })),
  })

export function useAccept() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ cve, ...body }: Schemas['CVEAcceptanceInput'] & { cve: string }) =>
      unwrap(
        api.POST('/api/v1/vulnerabilities/{cve}/accept', {
          params: { path: { cve } },
          body,
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.all }),
  })
}

export function useReopen() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ cve, id }: { cve: string; id?: number }) =>
      unwrap(
        api.POST('/api/v1/vulnerabilities/{cve}/reopen', {
          params: { path: { cve } },
          body: id ? { acceptance_id: id } : undefined,
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.all }),
  })
}

/** Downloads the filtered list as CSV (up to 10000 rows). */
export async function exportCSV(q: Query) {
  const blob = (await unwrap(
    api.GET('/api/v1/vulnerabilities', {
      params: { query: { ...q, sort: q.sort as never, format: 'csv' } },
      parseAs: 'blob',
    }),
  )) as unknown as Blob
  saveBlob(blob, 'limdm-vulnerabilities.csv')
}
