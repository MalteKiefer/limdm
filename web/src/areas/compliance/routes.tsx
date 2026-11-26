// The compliance area: overview with check and control drill down, risk
// exceptions, history at a date and the compliance policies.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Download, FileClock, ShieldCheck, ShieldOff } from 'lucide-react'
import type { Area } from '../../app/area'
import { t } from '../../i18n'

/** A search parameter as text; the router parses 1 or true in a URL as JSON values. */
const str = (v: unknown) => (v == null || v === '' ? undefined : String(v))

export const complianceArea: Area = {
  id: 'compliance',
  nav: { to: '/compliance', icon: ShieldCheck, label: 'nav.compliance', order: 40 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/compliance',
      component: lazyRouteComponent(() => import('./pages'), 'CompliancePage'),
      validateSearch: (s: Record<string, unknown>) => ({
        fw: str(s.fw),
        view: str(s.view),
        q: str(s.q),
        state: str(s.state),
        level: str(s.level),
        sort: str(s.sort),
        sel: str(s.sel),
        control: str(s.control),
        group: str(s.group),
        export: str(s.export),
      }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/compliance/exceptions',
      component: lazyRouteComponent(() => import('./exceptions'), 'ExceptionsPage'),
      validateSearch: (s: Record<string, unknown>) => ({ state: str(s.state), new: str(s.new) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/compliance/history',
      component: lazyRouteComponent(() => import('./history'), 'HistoryPage'),
      validateSearch: (s: Record<string, unknown>) => ({ at: str(s.at), device: str(s.device) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/compliance/policies',
      component: lazyRouteComponent(() => import('./policies'), 'PoliciesPage'),
    }),
  ],
  commands: () => [
    { id: 'compliance.exceptions', label: t('compliance.cmd.exceptions'), icon: ShieldOff, keywords: 'exception risk ausnahme', run: (go) => go('/compliance/exceptions') },
    { id: 'compliance.history', label: t('compliance.cmd.history'), icon: FileClock, keywords: 'history verlauf stichtag', run: (go) => go('/compliance/history') },
    { id: 'compliance.export', label: t('compliance.cmd.export'), icon: Download, keywords: 'evidence nachweis csv export', run: (go) => go('/compliance', { export: '1' }) },
  ],
}
