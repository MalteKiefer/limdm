// The signed in user. Loaded once before the shell renders; everything that
// depends on role, tenant or locale reads it from here.
import { useSuspenseQuery } from '@tanstack/react-query'
import { setLocale, setServerLocale, syncServerLocale } from '../i18n'
import { getPrefs, type Locale } from '../lib/prefs'
import { queryClient } from './live'
import { api, setCsrfToken, unwrap, type Schemas } from './client'

export type Me = Schemas['Me']
export type Permission = Me['permissions'][number]

export const meQuery = {
  queryKey: ['me'],
  queryFn: async () => {
    const me = await unwrap(api.GET('/api/v1/me'))
    setCsrfToken(me.csrf_token ?? '')
    setServerLocale(me.locale)
    // a language picked in this browser before the server knew it: tell the server
    const l = getPrefs().locale
    if (l && l !== me.locale) void syncServerLocale(l).then(() => queryClient.invalidateQueries({ predicate: (q) => q.queryKey[0] !== 'me' }))
    return me
  },
  staleTime: 5 * 60_000,
}

export const useMe = () => useSuspenseQuery(meQuery).data

/** Whether the user may do what a permission names (the server checks again). */
export function useCan(p: Permission) {
  return useMe().permissions.includes(p)
}

/** Switches the console language and reloads what the server labelled in the old one. */
export function chooseLocale(l: Locale) {
  void setLocale(l).then(() => queryClient.invalidateQueries())
}
