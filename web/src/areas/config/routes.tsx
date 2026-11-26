// The config area: routes, navigation entry and palette commands.
import { createRoute, lazyRouteComponent } from '@tanstack/react-router'
import { FilePlus2, Layers, Package, PackagePlus, Plus } from 'lucide-react'
import type { Area } from '../../app/area'
import { str } from '../../app/Stub'
import { t } from '../../i18n'

export const configArea: Area = {
  id: 'config',
  nav: { to: '/config', icon: Layers, label: 'nav.config', order: 50 },
  routes: (shell) => [
    createRoute({
      getParentRoute: () => shell,
      path: '/config',
      component: lazyRouteComponent(() => import('./pages'), 'ConfigPage'),
      validateSearch: (s: Record<string, unknown>) => ({ tab: str(s.tab), q: str(s.q), type: str(s.type), sub: str(s.sub) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/config/blueprints/$id',
      component: lazyRouteComponent(() => import('./blueprint'), 'BlueprintPage'),
      validateSearch: (s: Record<string, unknown>) => ({ view: str(s.view) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/config/library/$id',
      component: lazyRouteComponent(() => import('./item'), 'LibraryItemPage'),
      validateSearch: (s: Record<string, unknown>) => ({ view: str(s.view), type: str(s.type), from: str(s.from) }),
    }),
    createRoute({
      getParentRoute: () => shell,
      path: '/config/software/$id',
      component: lazyRouteComponent(() => import('./software'), 'AppPage'),
    }),
  ],
  commands: () => [
    { id: 'config.newBlueprint', label: t('config.newBlueprint'), icon: Plus, keywords: 'blueprint', run: (go) => go('/config/blueprints/new') },
    { id: 'config.newItem', label: t('config.newItem'), icon: FilePlus2, keywords: 'library bibliothek', run: (go) => go('/config', { tab: 'library', sub: 'new' }) },
    { id: 'config.software', label: t('config.tabSoftware'), icon: PackagePlus, keywords: 'flathub catalog katalog', run: (go) => go('/config', { tab: 'software' }) },
    { id: 'config.packages', label: t('config.tabPackages'), icon: Package, keywords: 'upload repository', run: (go) => go('/config', { tab: 'packages' }) },
  ],
}
