// The signed in user. Loaded once before the shell renders; everything that
// depends on role, tenant or locale reads it from here.
import { useSuspenseQuery } from '@tanstack/react-query'
import { setServerLocale } from '../i18n'
import { api, setCsrfToken, unwrap, type Schemas } from './client'

export type Me = Schemas['Me']
export type Permission = Me['permissions'][number]

export const meQuery = {
  queryKey: ['me'],
  queryFn: async () => {
    const me = await unwrap(api.GET('/api/v1/me'))
    setCsrfToken(me.csrf_token ?? '')
    setServerLocale(me.locale)
    return me
  },
  staleTime: 5 * 60_000,
}

export const useMe = () => useSuspenseQuery(meQuery).data

/** Whether the user may do what a permission names (the server checks again). */
export function useCan(p: Permission) {
  return useMe().permissions.includes(p)
}
