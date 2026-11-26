// The settings area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Settings } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const settingsArea: Area = {
  id: 'settings',
  nav: { to: '/settings', icon: Settings, label: 'nav.settings', order: 90, bottom: true },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/settings',
      component: lazyRouteComponent(() => import('./pages'), 'SettingsPage'),
      validateSearch: (s: Record<string, unknown>) => ({ s: str(s.s) }),
    }),
  ],
}
