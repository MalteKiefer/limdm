// The inbox area: routes and navigation entry.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Inbox } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'

export const inboxArea: Area = {
  id: 'inbox',
  nav: { to: '/inbox', icon: Inbox, label: 'nav.inbox', order: 20 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/inbox',
      component: lazyRouteComponent(() => import('./pages'), 'InboxPage'),
      validateSearch: (s: Record<string, unknown>) => ({ item: str(s.item) }),
    }),
  ],
}
