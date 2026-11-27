// The vulnerabilities area: known CVEs of the fleet with severity, CVSS,
// CISA KEV, remediation and risk acceptance.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Bug, ShieldAlert } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

export const vulnerabilitiesArea: Area = {
  id: 'vulnerabilities',
  nav: { to: '/vulnerabilities', icon: Bug, label: 'vulns.nav', order: 45 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/vulnerabilities',
      component: lazyRouteComponent(() => import('./pages'), 'VulnerabilitiesPage'),
      validateSearch: (s: Record<string, unknown>) => ({
        q: str(s.q),
        sev: str(s.sev),
        status: str(s.status),
        device: str(s.device),
        os: str(s.os),
        pkg: str(s.pkg),
        from: str(s.from),
        to: str(s.to),
        kev: str(s.kev),
        sort: str(s.sort),
        sel: str(s.sel),
        full: str(s.full),
      }),
    }),
  ],
  commands: () => [
    {
      id: 'vulns.open',
      label: t('vulns.palette.open'),
      icon: Bug,
      keywords: 'cve vulnerability schwachstelle sicherheit security',
      run: (go) => go('/vulnerabilities'),
    },
    {
      id: 'vulns.critical',
      label: t('vulns.palette.critical'),
      icon: ShieldAlert,
      keywords: 'cve critical kritisch',
      run: (go) => go('/vulnerabilities', { sev: 'critical' }),
    },
    {
      id: 'vulns.kev',
      label: t('vulns.palette.kev'),
      icon: ShieldAlert,
      keywords: 'cve kev exploited ausgenutzt cisa',
      run: (go) => go('/vulnerabilities', { kev: 'on' }),
    },
  ],
}
