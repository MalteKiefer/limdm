// The router: browser history under /app/ (the Go server answers every
// /app/ path with the app), the shell as root, each area's routes below it.
import { createRootRoute, createRouter, Link } from '@tanstack/react-router'
import { Compass } from 'lucide-react'
import { Suspense } from 'react'
import { EmptyState, ErrorState } from '../components/states'
import { t, useT } from '../i18n'
import { loadCatalogs } from '../i18n/catalog'
import { areas } from './areas'
import { Shell } from './shell'

function Loading() {
  return (
    <div role="status" className="grid min-h-dvh place-items-center text-muted">
      {t('app.loading')}
    </div>
  )
}

function NotFound() {
  const tr = useT()
  return (
    <div className="card">
      <EmptyState
        icon={Compass}
        title={tr('state.notFoundTitle')}
        action={
          <Link to="/" className="btn">
            {tr('state.toHome')}
          </Link>
        }
      >
        {tr('state.notFoundBody')}
      </EmptyState>
    </div>
  )
}

const root = createRootRoute({
  component: () => (
    <Suspense fallback={<Loading />}>
      <Shell />
    </Suspense>
  ),
  notFoundComponent: NotFound,
  errorComponent: ({ error, reset }) => <ErrorState error={error} onRetry={reset} />,
})

// each area's catalog (and those it depends on) loads before its routes render
export const routeTree = root.addChildren(areas.flatMap((a) => a.routes(root).map((r) => r.update({ loader: () => loadCatalogs(a.id) } as never))))

export const router = createRouter({ routeTree, basepath: '/app', defaultPreload: 'intent', scrollRestoration: true })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
