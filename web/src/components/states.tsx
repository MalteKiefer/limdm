// Empty, error and loading states, and the error boundary. An empty state
// says what will appear and offers the next step; an error state names the
// request id so a report can find the server log line.
import { CircleAlert, Inbox, RotateCcw, type LucideIcon } from 'lucide-react'
import { Component, type ErrorInfo, type ReactNode } from 'react'
import { ApiError } from '../api/client'
import { t, useT } from '../i18n'
import { Skeleton } from './ui'

export function EmptyState({ icon: I = Inbox, title, children, action }: { icon?: LucideIcon; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="mb-1 grid size-10 place-items-center rounded-full bg-accent-soft text-on-accent-soft">
        <I size={20} aria-hidden />
      </div>
      <h3 className="font-semibold">{title}</h3>
      {children && <div className="max-w-sm text-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

/** The message of an error for people: problem details of the API, or a generic text. */
export function errorText(err: unknown) {
  if (err instanceof ApiError) {
    if (err.status === 401) return t('error.session')
    if (err.status === 403) return err.problem.detail || t('error.forbidden')
    return err.problem.detail || err.message
  }
  if (err instanceof TypeError) return t('error.network')
  return t('state.errorBody')
}

export function ErrorState({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: ReactNode }) {
  const tr = useT()
  const rid = error instanceof ApiError ? error.requestId : null
  return (
    <div role="alert" className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      <div className="mb-1 grid size-10 place-items-center rounded-full bg-bad-soft text-bad">
        <CircleAlert size={20} aria-hidden />
      </div>
      <h3 className="font-semibold">{title ?? tr('state.errorTitle')}</h3>
      <p className="max-w-md text-muted">{errorText(error)}</p>
      {rid && <p className="font-mono text-micro text-muted">{tr('state.requestId', { id: rid })}</p>}
      {onRetry && (
        <button type="button" className="btn mt-2" onClick={onRetry}>
          <RotateCcw size={14} aria-hidden /> {tr('state.retry')}
        </button>
      )}
    </div>
  )
}

export function LoadingState({ rows = 4 }: { rows?: number }) {
  const tr = useT()
  return (
    <div role="status" aria-label={tr('state.loading')} className="flex flex-col gap-2 py-2">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-8" />
      ))}
    </div>
  )
}

/** Catches render errors of a part of the console; the rest keeps working. */
export class ErrorBoundary extends Component<{ children: ReactNode; fallback?: (error: unknown, reset: () => void) => ReactNode }, { error: unknown }> {
  state = { error: null as unknown }
  static getDerivedStateFromError(error: unknown) {
    return { error }
  }
  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error('console crashed', error, info.componentStack)
  }
  reset = () => this.setState({ error: null })
  render() {
    if (this.state.error == null) return this.props.children
    return this.props.fallback ? this.props.fallback(this.state.error, this.reset) : <ErrorState title={t('state.crashTitle')} error={this.state.error} onRetry={this.reset} />
  }
}
