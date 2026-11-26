// Saved views (/api/v1/views): a named query, sort and column set of a list.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from './client'

export type SavedView = Schemas['SavedView']
export type SavedViewInput = Schemas['SavedViewInput']

export const viewsKey = (list: string) => ['views', list]

export function useSavedViews(list: string) {
  return useQuery({
    queryKey: viewsKey(list),
    queryFn: () => unwrap(api.GET('/api/v1/views', { params: { query: { list } } })).then((p) => p.items),
  })
}

export function useSaveView(list: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: SavedViewInput & { id?: number }) =>
      id ? unwrap(api.PUT('/api/v1/views/{id}', { params: { path: { id } }, body })) : unwrap(api.POST('/api/v1/views', { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: viewsKey(list) }),
  })
}

export function useDeleteView(list: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/views/{id}', { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: viewsKey(list) }),
  })
}
