// The activity area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Activity } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const activityArea: Area = {
  id: 'activity',
  nav: { to: '/activity', icon: Activity, label: 'nav.activity', order: 60 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/activity',
      component: lazyRouteComponent(() => import('./pages'), 'ActivityPage'),
      validateSearch: (s: Record<string, unknown>) => ({ q: str(s.q) }),
    }),
  ],
}
