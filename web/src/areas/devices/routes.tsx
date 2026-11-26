// The devices area: routes, navigation entry and palette commands.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { Monitor, Plus } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

const page = (name: 'DevicesPage' | 'DevicePage' | 'EnrollPage' | 'ShellPage') => lazyRouteComponent(() => import('./pages'), name)

export const devicesArea: Area = {
  id: 'devices',
  nav: { to: '/devices', icon: Monitor, label: 'nav.devices', order: 30, views: 'devices' },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/devices',
      component: page('DevicesPage'),
      validateSearch: (s: Record<string, unknown>) => ({ q: str(s.q), sort: str(s.sort), sel: str(s.sel) }),
    }),
    createRoute({ getParentRoute: () => shell, path: '/devices/enroll', component: page('EnrollPage') }),
    createRoute({
      getParentRoute: () => shell,
      path: '/devices/$id',
      component: page('DevicePage'),
      validateSearch: (s: Record<string, unknown>) => ({ tab: str(s.tab), sub: str(s.sub) }),
    }),
    createRoute({ getParentRoute: () => shell, path: '/devices/$id/shell/$sid', component: page('ShellPage') }),
  ],
  commands: () => [{ id: 'devices.enroll', label: t('devices.add'), icon: Plus, keywords: 'enroll token agent install registrieren', run: (go) => go('/devices/enroll') }],
}
