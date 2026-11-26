// Queries and mutations of the settings area. Query keys start with
// "settings"; a successful change invalidates its own key.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import { toast } from '../../components/toast'
import { errorText } from '../../components/states'

export type Settings = Schemas['Settings']
export type SettingsInput = Schemas['SettingsInput']
export type Section = 'general' | 'network' | 'security' | 'remote_shell' | 'sso' | 'monitoring' | 'branding' | 'operations' | 'retention'

export const useSettings = () => useQuery({ queryKey: ['settings', 'server'], queryFn: () => unwrap(api.GET('/api/v1/settings')) })

export function useSaveSection(section: Section) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: SettingsInput) => unwrap(api.PATCH('/api/v1/settings/{section}', { params: { path: { section } }, body })),
    onSuccess: (data) => {
      qc.setQueryData(['settings', 'server'], data)
      void qc.invalidateQueries({ queryKey: ['me'] })
    },
  })
}

/** A mutation that refreshes the given query key and toasts the result. */
export function useAction<V, R>(key: unknown[], fn: (v: V) => Promise<R>, okText?: string | ((r: R) => string)) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: key })
      const text = typeof okText === 'function' ? okText(r) : okText
      if (text) toast(text)
    },
    onError: (e) => toast(errorText(e), 'error'),
  })
}

export const useUsers = () => useQuery({ queryKey: ['settings', 'users'], queryFn: () => unwrap(api.GET('/api/v1/users')) })
export const useTokens = () => useQuery({ queryKey: ['settings', 'tokens'], queryFn: () => unwrap(api.GET('/api/v1/tokens')) })
export const useTenantList = () => useQuery({ queryKey: ['settings', 'tenants'], queryFn: () => unwrap(api.GET('/api/v1/tenants')) })
export const useTenant = (id: number) => useQuery({ queryKey: ['settings', 'tenants', id], queryFn: () => unwrap(api.GET('/api/v1/tenants/{id}', { params: { path: { id } } })) })
export const useShared = (on: boolean) => useQuery({ queryKey: ['settings', 'shared'], enabled: on, queryFn: () => unwrap(api.GET('/api/v1/tenants/shared')) })
export const useKeys = () => useQuery({ queryKey: ['settings', 'keys'], queryFn: () => unwrap(api.GET('/api/v1/keys')) })
export const useBackup = () => useQuery({ queryKey: ['settings', 'backup'], queryFn: () => unwrap(api.GET('/api/v1/backup')) })
export const useChannels = () => useQuery({ queryKey: ['settings', 'channels'], queryFn: () => unwrap(api.GET('/api/v1/notification-channels')) })
export const useDirectory = () => useQuery({ queryKey: ['settings', 'directory'], queryFn: () => unwrap(api.GET('/api/v1/directory')) })
export const useDirectoryUsers = (q: string) =>
  useQuery({ queryKey: ['settings', 'directory', 'users', q], queryFn: () => unwrap(api.GET('/api/v1/directory/users', { params: { query: { q } } })) })
export const useNetwork = () => useQuery({ queryKey: ['settings', 'network'], queryFn: () => unwrap(api.GET('/api/v1/network')) })
export const useAgents = () => useQuery({ queryKey: ['settings', 'agents'], queryFn: () => unwrap(api.GET('/api/v1/agents')) })
export const useProfile = () => useQuery({ queryKey: ['settings', 'profile'], queryFn: () => unwrap(api.GET('/api/v1/profile')) })
export const useBlueprintNames = () =>
  useQuery({ queryKey: ['settings', 'blueprints'], queryFn: () => unwrap(api.GET('/api/v1/blueprints', { params: { query: { limit: 500 } } })) })
