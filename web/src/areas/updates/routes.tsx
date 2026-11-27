// The updates area (patch management): update rings, open security
// updates and CVEs of the fleet, installed package versions.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { PackageCheck, ShieldAlert } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

export const updatesArea: Area = {
  id: 'updates',
  nav: { to: '/updates', icon: PackageCheck, label: 'updates.nav', order: 55 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/updates',
      component: lazyRouteComponent(() => import('./pages'), 'UpdatesPage'),
      validateSearch: (s: Record<string, unknown>) => ({
        tab: str(s.tab),
        cve: str(s.cve),
        pkg: str(s.pkg),
      }),
    }),
  ],
  commands: () => [
    {
      id: 'updates.rings',
      label: t('updates.palette.rings'),
      icon: PackageCheck,
      keywords: 'patch ring welle wave update',
      run: (go) => go('/updates'),
    },
    {
      id: 'updates.cves',
      label: t('updates.palette.cves'),
      icon: ShieldAlert,
      keywords: 'cve security sicherheit schwachstelle',
      run: (go) => go('/updates', { tab: 'security' }),
    },
  ],
}
