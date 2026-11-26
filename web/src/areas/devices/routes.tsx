// The devices area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Monitor } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const devicesArea: Area = {
  id: 'devices',
  nav: { to: '/devices', icon: Monitor, label: 'nav.devices', order: 30, views: 'devices' },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/devices',
      component: lazyRouteComponent(() => import('./pages'), 'DevicesPage'),
      validateSearch: (s: Record<string, unknown>) => ({ q: str(s.q), sort: str(s.sort), sel: str(s.sel) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/devices/$id',
      component: lazyRouteComponent(() => import('./pages'), 'DevicePage'),
      validateSearch: (s: Record<string, unknown>) => ({ tab: str(s.tab) }),
    }),
  ],
}
