// The reports area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { FileBarChart2 } from 'lucide-react'
import type { Area } from '../../app/area'

export const reportsArea: Area = {
  id: 'reports',
  nav: { to: '/reports', icon: FileBarChart2, label: 'nav.reports', order: 70 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/reports',
      component: lazyRouteComponent(() => import('./pages'), 'ReportsPage'),
    }),
  ],
}
