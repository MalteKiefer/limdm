// Tenant view: super admins switch between tenants and the global view.
// The switch is the classic console's form endpoint; it changes the session.
import { useQuery } from '@tanstack/react-query'
import { api, postForm, unwrap } from '../api/client'
import { useMe } from '../api/me'

export function useTenants() {
  const me = useMe()
  return useQuery({
    queryKey: ['tenants'],
    enabled: me.multi_tenant && me.permissions.includes('tenants'),
    queryFn: () =>
      unwrap(api.GET('/api/v1/tenants')).then((p) => (p.items ?? []).flatMap((x) => (x.id != null && x.name && !x.disabled ? [{ id: x.id, name: x.name, devices: x.devices ?? 0 }] : []))),
  })
}

/** Switches the session to tenant id (0: all tenants) and reloads the app in that view. */
export async function switchTenant(id: number) {
  await postForm('/tenants/switch', { tenant: String(id) })
  location.reload()
}

export async function signOut() {
  await postForm('/logout')
  location.assign('/login')
}
