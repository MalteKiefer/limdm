// The activity area: routes, navigation entry and palette commands.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Activity, ScrollText, TerminalSquare } from 'lucide-react'
import type { Area } from '../../app/area'
import { t } from '../../i18n'
import { parseSearch } from './filter'

export const activityArea: Area = {
  id: 'activity',
  nav: { to: '/activity', icon: Activity, label: 'nav.activity', order: 60 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/activity',
      component: lazyRouteComponent(() => import('./pages'), 'ActivityPage'),
      validateSearch: parseSearch,
    }),
  ],
  commands: () => [
    { id: 'activity.audit', label: t('activity.palette.audit'), icon: ScrollText, keywords: 'audit log protokoll', run: (go) => go('/activity') },
    { id: 'activity.commands', label: t('activity.cat.commands'), icon: TerminalSquare, keywords: 'aktivität activity befehle commands', run: (go) => go('/activity', { cat: 'commands' }) },
  ],
}
