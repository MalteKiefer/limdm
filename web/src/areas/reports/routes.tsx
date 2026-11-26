// The reports area: routes, navigation entry and palette commands.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { FileBarChart2, FileDown, History } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

const day = (v: unknown) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : undefined)

export const reportsArea: Area = {
  id: 'reports',
  nav: { to: '/reports', icon: FileBarChart2, label: 'nav.reports', order: 70 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/reports',
      component: lazyRouteComponent(() => import('./pages'), 'ReportsPage'),
      validateSearch: (s: Record<string, unknown>) => ({ at: day(s.at), device: str(s.device) }),
    }),
  ],
  commands: () => [
    { id: 'reports.history', label: t('reports.palette.history'), icon: History, keywords: 'compliance verlauf history stichtag', run: (go) => go('/reports') },
    {
      id: 'reports.evidence',
      label: t('reports.palette.evidence'),
      icon: FileDown,
      keywords: 'nachweis evidence csv export',
      // a download, not a page: the browser keeps the current page
      run: () => location.assign('/api/v1/exports/compliance.csv'),
    },
  ],
}
