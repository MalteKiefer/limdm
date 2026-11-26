// The config area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Layers } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const configArea: Area = {
  id: 'config',
  nav: { to: '/config', icon: Layers, label: 'nav.config', order: 50 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/config',
      component: lazyRouteComponent(() => import('./pages'), 'ConfigPage'),
      validateSearch: (s: Record<string, unknown>) => ({ tab: str(s.tab) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/config/library/$id',
      component: lazyRouteComponent(() => import('./pages'), 'LibraryItemPage'),
    }),
  ],
}
