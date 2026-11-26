// The settings area: settings with their sections, the own profile and
// help. Navigation entry and palette commands for every section.
import { createRoute, lazyRouteComponent, redirect } from '@tanstack/react-router'
import { CircleHelp, Settings, UserRound } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t, type MessageKey } from '../../i18n'
import { sections } from './sections'

/** Other names of sections used by deep links. */
const aliases: Record<string, string> = { branding: 'general', sso: 'signin', login: 'signin', mfa: 'signin', scim: 'directory', api: 'tokens', roles: 'users', 'four-eyes': 'approvals', security: 'password' }

export const settingsArea: Area = {
  id: 'settings',
  nav: { to: '/settings', icon: Settings, label: 'nav.settings', order: 90, bottom: true, permission: 'audit' },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/settings',
      component: lazyRouteComponent(() => import('./pages'), 'SettingsPage'),
      validateSearch: (s: Record<string, unknown>) => ({ s: str(s.s), sel: str(s.sel) }),
    }),
    // deep links by name (/settings/branding, /settings/sso, ...) open the section
    createRoute({
      getParentRoute: () => shell,
      path: '/settings/$section',
      beforeLoad: ({ params }) => {
        throw redirect({ to: '/settings', search: { s: aliases[params.section] ?? params.section, sel: undefined } })
      },
    }),
    createRoute({ getParentRoute: () => shell, path: '/profile', component: lazyRouteComponent(() => import('./profile'), 'ProfilePage') }),
    createRoute({ getParentRoute: () => shell, path: '/help', component: lazyRouteComponent(() => import('./profile'), 'HelpPage') }),
  ],
  commands: () => [
    ...sections.map((x) => ({
      id: `settings.${x.id}`,
      label: `${t('settings.title')}: ${t(`settings.nav.${x.id}` as MessageKey)}`,
      icon: x.icon,
      keywords: x.id,
      run: (go: (to: string, search?: Record<string, string>) => void) => go('/settings', { s: x.id }),
    })),
    { id: 'settings.profile', label: t('settings.profile.title'), icon: UserRound, keywords: 'profile password totp', run: (go) => go('/profile') },
    { id: 'settings.help', label: t('settings.help.title'), icon: CircleHelp, keywords: 'help glossary', run: (go) => go('/help') },
  ],
}
