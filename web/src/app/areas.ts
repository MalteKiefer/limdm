// Every area of the console, one line each. The navigation is ordered by
// nav.order, not by this list.
import { activityArea } from '../areas/activity/routes'
import { complianceArea } from '../areas/compliance/routes'
import { configArea } from '../areas/config/routes'
import { devicesArea } from '../areas/devices/routes'
import { homeArea } from '../areas/home/routes'
import { inboxArea } from '../areas/inbox/routes'
import { reportsArea } from '../areas/reports/routes'
import { settingsArea } from '../areas/settings/routes'
import { updatesArea } from '../areas/updates/routes'
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import type { Area } from './area'

/** Developer pages without navigation: the component gallery (English only, not for operators). */
const devArea: Area = {
  id: 'dev',
  routes: (shell) => [createRoute({ getParentRoute: () => shell, path: '/dev/components', component: lazyRouteComponent(() => import('./gallery'), 'Gallery') })],
}

export const areas: Area[] = [homeArea, inboxArea, devicesArea, complianceArea, configArea, updatesArea, activityArea, reportsArea, settingsArea, devArea]
