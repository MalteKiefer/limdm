import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './styles.css'
import { Tooltip } from '@base-ui/react/tooltip'
import { QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { queryClient } from './api/live'
import { meQuery } from './api/me'
import { router } from './app/router'
import { ErrorBoundary } from './components/states'

void queryClient.prefetchQuery(meQuery)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <Tooltip.Provider delay={300}>
          <RouterProvider router={router} />
        </Tooltip.Provider>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
)
