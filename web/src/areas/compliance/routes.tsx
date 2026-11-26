// The compliance area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { ShieldCheck } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const complianceArea: Area = {
  id: 'compliance',
  nav: { to: '/compliance', icon: ShieldCheck, label: 'nav.compliance', order: 40 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/compliance',
      component: lazyRouteComponent(() => import('./pages'), 'CompliancePage'),
      validateSearch: (s: Record<string, unknown>) => ({ fw: str(s.fw), control: str(s.control) }),
    }),
  ],
}
