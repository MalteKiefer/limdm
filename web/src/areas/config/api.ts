// Queries and mutations of the config area. Keys start with "config" (and
// "approvals" where a save may file a four eyes request, so the inbox
// refreshes).
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, getCsrfToken, unwrap, type Schemas } from '../../api/client'
import type { JSONSchema } from '../../components/schemaform'
import { currentLocale } from '../../i18n'

export type BlueprintRow = Schemas['ConfigBlueprint']
export type LibraryRow = Schemas['ConfigLibraryItem']
export type Preview = Schemas['ConfigPreview']
export type Node = Schemas['Node']
export type CatalogApp = Schemas['CatalogApp']
export type CatalogAppInput = Schemas['CatalogAppInput']
export type Remote = Schemas['Remote']
export type AppRequest = Schemas['AppRequest']
export type Package = Schemas['Package']
export type PackageConfig = Schemas['PackageConfig']
export type TypeInfo = { type: string; title: string; description: string; doc: string; four_eyes: boolean }
export type Kind = 'blueprints' | 'library'

/** Answer of a save: saved, or filed for four eyes approval (202). */
export type SaveResult = { pending: boolean; id?: number | string }

export const useBlueprints = () => useQuery({ queryKey: ['config', 'blueprints'], queryFn: () => unwrap(api.GET('/api/v1/config/blueprints')) })
/** The start of a new library item: example payload of a type or a device's source or remote. */
export const useTemplate = (enabled: boolean, query: { type?: string; device?: string; file?: string; remote?: string; inst?: string; mode?: string }) =>
  useQuery({ queryKey: ['config', 'template', query], enabled, staleTime: Infinity, queryFn: () => unwrap(api.GET('/api/v1/config/library/template', { params: { query: query as never } })) })
export const useLibrary = () => useQuery({ queryKey: ['config', 'library'], queryFn: () => unwrap(api.GET('/api/v1/config/library')) })

export function useTypes() {
  const lang = currentLocale()
  return useQuery({
    queryKey: ['config', 'types', lang],
    queryFn: () => unwrap(api.GET('/api/v1/schemas', { params: { query: { lang } } })).then((p) => p.items as TypeInfo[]),
    staleTime: 300_000,
  })
}

export function useSchema(type: string | undefined) {
  const lang = currentLocale()
  return useQuery({
    queryKey: ['config', 'schema', type, lang],
    enabled: !!type,
    queryFn: () => unwrap(api.GET('/api/v1/schemas/{type}', { params: { path: { type: type! }, query: { lang } } })) as Promise<JSONSchema>,
    staleTime: 300_000,
  })
}

export const useVersions = (kind: Kind, id: number | undefined) =>
  useQuery({
    queryKey: ['config', kind, id, 'versions'],
    enabled: !!id,
    queryFn: () => unwrap(api.GET('/api/v1/config/{kind}/{id}/versions', { params: { path: { kind, id: id! } } })),
  })

/** Invalidates the config area (and the inbox, a save may file an approval). */
export function useRefresh() {
  const qc = useQueryClient()
  return () => Promise.all([qc.invalidateQueries({ queryKey: ['config'] }), qc.invalidateQueries({ queryKey: ['approvals'] })])
}

const saved = (r: { response: Response; data?: unknown }): SaveResult => ({ pending: r.response.status === 202, id: (r.data as { id?: number })?.id })

async function check<T extends { response: Response; data?: unknown; error?: unknown }>(p: Promise<T>): Promise<SaveResult> {
  const r = await p
  await unwrap(Promise.resolve(r))
  return saved(r)
}

export type ItemInput = Schemas['LibraryItem']

export function useSaveItem() {
  const refresh = useRefresh()
  return useMutation({
    mutationFn: (it: ItemInput) =>
      it.id ? check(api.PUT('/api/v1/library-items/{id}', { params: { path: { id: it.id } }, body: it })) : check(api.POST('/api/v1/library-items', { body: it })),
    onSuccess: refresh,
  })
}

export function useDeleteItem() {
  const refresh = useRefresh()
  return useMutation({ mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/library-items/{id}', { params: { path: { id } } })), onSuccess: refresh })
}

export type BlueprintInput = Schemas['BlueprintInput']

export function useSaveBlueprint() {
  const refresh = useRefresh()
  return useMutation({
    mutationFn: ({ id, ...b }: BlueprintInput & { id?: number }) =>
      id ? check(api.PUT('/api/v1/blueprints/{id}', { params: { path: { id } }, body: b })) : check(api.POST('/api/v1/blueprints', { body: b })),
    onSuccess: refresh,
  })
}

export function useDeleteBlueprint() {
  const refresh = useRefresh()
  return useMutation({ mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/blueprints/{id}', { params: { path: { id } } })), onSuccess: refresh })
}

export function useRollback(kind: Kind) {
  const refresh = useRefresh()
  return useMutation({
    mutationFn: ({ id, version }: { id: number; version: number }) => check(api.POST('/api/v1/config/{kind}/{id}/rollback', { params: { path: { kind, id } }, body: { version } })),
    onSuccess: refresh,
  })
}

export const previewItem = (it: ItemInput) => unwrap(api.POST('/api/v1/config/library/preview', { body: it }))
export const previewBlueprint = (b: Schemas['BlueprintInput'] & { id?: number; tree: Node[] }) => unwrap(api.POST('/api/v1/config/blueprints/preview', { body: b }))

export function usePilot() {
  const refresh = useRefresh()
  return {
    start: useMutation({
      mutationFn: ({ id, tree, devices }: { id: number; tree: Node[]; devices: string[] }) => unwrap(api.POST('/api/v1/config/blueprints/{id}/pilot', { params: { path: { id } }, body: { tree, devices } })),
      onSuccess: refresh,
    }),
    end: useMutation({
      mutationFn: ({ id, op }: { id: number; op: 'promote' | 'abort' }) => unwrap(api.POST('/api/v1/config/blueprints/{id}/pilot/{op}', { params: { path: { id, op } } })),
      onSuccess: refresh,
    }),
  }
}

// ---- software ----

export const useCatalog = () => useQuery({ queryKey: ['config', 'software', 'catalog'], queryFn: () => unwrap(api.GET('/api/v1/software/catalog')) })
export const useRequests = () => useQuery({ queryKey: ['config', 'software', 'requests'], queryFn: () => unwrap(api.GET('/api/v1/software/requests')).then((p) => p.items) })
export const useRemotes = () => useQuery({ queryKey: ['config', 'software', 'remotes'], queryFn: () => unwrap(api.GET('/api/v1/software/remotes')).then((p) => p.items) })
export const useStoreSettings = () => useQuery({ queryKey: ['config', 'software', 'settings'], queryFn: () => unwrap(api.GET('/api/v1/software/settings')) })

export function useSoftware() {
  const refresh = useRefresh()
  const m = <A, R>(fn: (a: A) => Promise<R>) => useMutation<R, Error, A>({ mutationFn: fn, onSuccess: refresh }) // eslint-disable-line react-hooks/rules-of-hooks
  return {
    saveApp: m(({ isNew, app }: { isNew: boolean; app: CatalogAppInput }) =>
      isNew ? check(api.POST('/api/v1/software/apps', { body: app })) : check(api.PUT('/api/v1/software/apps/{id}', { params: { path: { id: app.id! } }, body: app })),
    ),
    deleteApp: m((id: string) => unwrap(api.DELETE('/api/v1/software/apps/{id}', { params: { path: { id } } }))),
    importFleet: m((flatpaks: string[]) => unwrap(api.POST('/api/v1/software/import', { body: { flatpaks } }))),
    addFlathub: m(({ id, mode }: { id: string; mode: 'available' | 'request' | 'required' }) => check(api.POST('/api/v1/software/flathub', { body: { id, mode } }))),
    decide: m(({ id, op }: { id: number; op: 'approve' | 'approve-all' | 'deny' }) => unwrap(api.POST('/api/v1/software/requests/{id}/{op}', { params: { path: { id, op } } }))),
    saveRemote: m((r: Remote) => unwrap(api.PUT('/api/v1/software/remotes/{name}', { params: { path: { name: r.name } }, body: r }))),
    remoteOp: m(({ name, op }: { name: string; op: 'allow' | 'block' | 'filter' | 'unmanage' }) => unwrap(api.POST('/api/v1/software/remotes/{name}/{op}', { params: { path: { name, op } } }))),
    saveSettings: m((s: Schemas['SoftwareSettings']) => unwrap(api.PUT('/api/v1/software/settings', { body: s }))),
  }
}

export const searchFlathub = (q: string) => unwrap(api.GET('/api/v1/software/flathub/search', { params: { query: { q } } }))

// ---- packages ----

export const usePackages = (enabled = true) => useQuery({ queryKey: ['config', 'packages'], enabled, queryFn: () => unwrap(api.GET('/api/v1/packages')) })

export function usePackageActions() {
  const refresh = useRefresh()
  return {
    remove: useMutation({ mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/packages/{id}', { params: { path: { id } } })), onSuccess: refresh }),
    settings: useMutation({ mutationFn: (c: PackageConfig) => unwrap(api.PUT('/api/v1/packages/settings', { body: c })), onSuccess: refresh }),
  }
}

/**
 * Uploads a package with progress. XMLHttpRequest, because fetch reports no
 * upload progress; same origin, session cookie and CSRF header as the client.
 */
export function uploadPackage(form: FormData, onProgress: (p: number) => void, signal?: AbortSignal): Promise<{ status: string }> {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest()
    x.open('POST', '/api/v1/packages')
    x.withCredentials = true
    x.setRequestHeader('X-CSRF-Token', getCsrfToken())
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total)
    x.onerror = () => reject(new ApiError(0, { detail: 'network' }, null))
    x.onabort = () => reject(new DOMException('aborted', 'AbortError'))
    x.onload = () => {
      let body: unknown = {}
      try {
        body = JSON.parse(x.responseText)
      } catch {
        // no JSON body
      }
      if (x.status >= 200 && x.status < 300) resolve(body as { status: string })
      else reject(new ApiError(x.status, (body as object) ?? {}, x.getResponseHeader('X-Request-ID')))
    }
    signal?.addEventListener('abort', () => x.abort())
    x.send(form)
  })
}
