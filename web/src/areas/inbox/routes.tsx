// The inbox area: routes, navigation entry and palette commands.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Inbox, ShieldAlert, TriangleAlert } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

const groups = ['approvals', 'warnings', 'commands'] as const
type Group = (typeof groups)[number]

export const inboxArea: Area = {
  id: 'inbox',
  nav: { to: '/inbox', icon: Inbox, label: 'nav.inbox', order: 20 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/inbox',
      component: lazyRouteComponent(() => import('./pages'), 'InboxPage'),
      validateSearch: (s: Record<string, unknown>) => ({
        item: str(s.item),
        group: groups.includes(s.group as Group) ? (s.group as Group) : undefined,
        hist: s.hist === '1' || s.hist === 1 ? '1' : undefined,
        muted: s.muted === '1' || s.muted === 1 ? '1' : undefined,
      }),
    }),
  ],
  commands: () => [
    { id: 'inbox.approvals', label: t('inbox.palette.approvals'), icon: ShieldAlert, keywords: 'freigabe approval vier augen four eyes', run: (go) => go('/inbox', { group: 'approvals' }) },
    { id: 'inbox.failed', label: t('inbox.palette.failed'), icon: TriangleAlert, keywords: 'befehl command failed fehler', run: (go) => go('/inbox', { group: 'commands' }) },
  ],
}
