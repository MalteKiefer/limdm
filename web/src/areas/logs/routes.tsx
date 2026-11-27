// The Logs area: search across devices, alert rules.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { BellRing, ScrollText } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

export const logsArea: Area = {
  id: 'logs',
  nav: { to: '/logs', icon: ScrollText, label: 'logs.nav', order: 47, permission: 'audit', views: 'logs' },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/logs',
      component: lazyRouteComponent(() => import('./pages'), 'LogsPage'),
      validateSearch: (s: Record<string, unknown>) => ({
        q: str(s.q),
        range: str(s.range),
        from: str(s.from),
        to: str(s.to),
        source: str(s.source),
        prio: str(s.prio),
        device: str(s.device),
        tab: str(s.tab),
        sel: str(s.sel),
        live: str(s.live),
      }),
    }),
  ],
  commands: () => [
    { id: 'logs.open', label: t('logs.palette.open'), icon: ScrollText, keywords: 'logs journal protokoll syslog', run: (go) => go('/logs') },
    { id: 'logs.errors', label: t('logs.palette.errors'), icon: ScrollText, keywords: 'logs error fehler', run: (go) => go('/logs', { prio: 'err' }) },
    { id: 'logs.alerts', label: t('logs.palette.alerts'), icon: BellRing, keywords: 'logs alert alarm', run: (go) => go('/logs', { tab: 'alerts' }) },
  ],
}
