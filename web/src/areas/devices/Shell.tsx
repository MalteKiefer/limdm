// Remote shell: the live terminal for the user who started the session
// (xterm.js vendored under /static/vendor/xterm, loaded as files of our own
// origin, canvas renderer: no inline styles under the CSP), the transcript
// for admins and auditors once it ended.
import { Link, useParams } from '@tanstack/react-router'
import { ArrowLeft } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { getCsrfToken } from '../../api/client'
import { Card, PageHeader } from '../../components/ui'
import { ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { useT, type MessageKey } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { useShellEnd, useShellSession } from './api'

type Term = { open(el: HTMLElement): void; write(d: Uint8Array): void; onData(f: (d: string) => void): void; loadAddon(a: unknown): void; focus(): void; cols: number; rows: number; options: { disableStdin?: boolean } }
type XtermWindow = Window & { Terminal?: new (o: object) => Term; FitAddon?: { FitAddon: new () => { fit(): void } }; CanvasAddon?: { CanvasAddon: new () => unknown } }

const base = '/static/vendor/xterm/'
let loading: Promise<void> | null = null

/** Loads xterm.js and its addons once, as script files of our origin. */
function loadXterm() {
  const add = (src: string) =>
    new Promise<void>((ok, fail) => {
      const s = document.createElement('script')
      s.src = base + src
      s.onload = () => ok()
      s.onerror = () => fail(new Error(src))
      document.head.append(s)
    })
  if (!document.querySelector(`link[href="${base}xterm.css"]`)) {
    const l = document.createElement('link')
    l.rel = 'stylesheet'
    l.href = base + 'xterm.css'
    document.head.append(l)
  }
  return (loading ??= add('xterm.js').then(() => Promise.all([add('addon-fit.js'), add('addon-canvas.js')]).then(() => undefined)))
}

export function ShellPage() {
  const t = useT()
  const { id, sid } = useParams({ strict: false }) as { id: string; sid: string }
  const s = useShellSession(sid)
  const end = useShellEnd()
  if (s.error) return <ErrorState error={s.error} onRetry={() => void s.refetch()} />
  if (!s.data) return <LoadingState />
  const x = s.data
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Link to="/devices/$id" params={{ id }} search={{ tab: 'activity' }} className="inline-flex w-fit items-center gap-1 text-body text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {x.hostname}
      </Link>
      <PageHeader
        title={t('devices.shell.title')}
        sub={`${x.hostname} · ${x.local_user} · ${x.requested_by} · ${dateTime(x.created_at)}`}
        actions={
          x.can_end && (
            <button type="button" className="btn btn-danger" disabled={end.isPending} onClick={() => end.mutate(sid, { onSuccess: () => toast(t('devices.shell.ended')), onError: (e) => toast(errorText(e), 'error') })}>
              {t('devices.shell.end')}
            </button>
          )
        }
      />
      {x.live ? (
        <Terminal sid={sid} />
      ) : x.state !== 'ended' && x.state !== 'interrupted' ? (
        <p role="status" className="card p-4 text-body">
          {t('devices.shell.running')}
        </p>
      ) : (
        <Card title={t('devices.shell.transcript')} id="sh-tr">
          <dl className="mb-4 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-body">
            <dt className="text-muted">{t('devices.sw.state')}</dt>
            <dd>{t(`devices.shell.state.${x.state}` as MessageKey)}</dd>
            <dt className="text-muted">{t('devices.shell.connected')}</dt>
            <dd>{x.connected_at ? dateTime(x.connected_at) : '–'}</dd>
            <dt className="text-muted">{t('devices.shell.endedAt')}</dt>
            <dd>{x.ended_at ? dateTime(x.ended_at) : '–'}</dd>
            <dt className="text-muted">{t('devices.shell.reason')}</dt>
            <dd>{x.end_reason || '–'}</dd>
            <dt className="text-muted">{t('devices.shell.output')}</dt>
            <dd>
              {t('devices.shell.bytes', { n: fmt(x.bytes) })}
              {x.truncated && ` (${t('devices.shell.truncated')})`}
            </dd>
          </dl>
          {x.transcript ? <pre className="max-h-[60dvh] overflow-auto rounded-md bg-surface-2 p-3 font-mono text-meta whitespace-pre-wrap">{x.transcript}</pre> : <p className="text-body text-muted">{t('devices.shell.noOutput')}</p>}
        </Card>
      )}
    </div>
  )
}

function Terminal({ sid }: { sid: string }) {
  const t = useT()
  const el = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState(t('devices.shell.waiting'))
  useEffect(() => {
    let ws: WebSocket | undefined
    let alive = true
    const onResize: { f?: () => void } = {}
    loadXterm()
      .then(() => {
        const w = window as XtermWindow
        if (!alive || !el.current || !w.Terminal) return
        const term = new w.Terminal({ cursorBlink: true, convertEol: false, scrollback: 5000 })
        const fit = w.FitAddon ? new w.FitAddon.FitAddon() : null
        if (fit) term.loadAddon(fit)
        term.open(el.current)
        if (w.CanvasAddon) term.loadAddon(new w.CanvasAddon.CanvasAddon())
        fit?.fit()
        const proto = location.protocol === 'https:' ? 'wss://' : 'ws://'
        ws = new WebSocket(`${proto}${location.host}/shell/${encodeURIComponent(sid)}/ws?csrf=${encodeURIComponent(getCsrfToken())}`)
        ws.binaryType = 'arraybuffer'
        const send = (o: object) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify(o))
        onResize.f = () => {
          fit?.fit()
          send({ r: [term.cols, term.rows] })
        }
        ws.onmessage = (ev) => {
          if (typeof ev.data === 'string') {
            if (ev.data === 'connected') {
              setStatus(t('devices.shell.connectedNow'))
              onResize.f?.()
              term.focus()
            }
            return
          }
          term.write(new Uint8Array(ev.data as ArrayBuffer))
        }
        ws.onclose = (ev) => {
          setStatus(`${t('devices.shell.closed')} ${ev.reason}`)
          term.options.disableStdin = true
        }
        term.onData((data) => send({ i: data }))
        window.addEventListener('resize', onResize.f)
      })
      .catch(() => setStatus(t('devices.shell.missing')))
    return () => {
      alive = false
      ws?.close()
      if (onResize.f) window.removeEventListener('resize', onResize.f)
    }
  }, [sid, t])
  return (
    <section className="card flex flex-col gap-2 p-[var(--pad-card)]">
      <p role="status" aria-live="polite" className="text-body text-muted">
        {status}
      </p>
      <div ref={el} className="h-[60dvh] min-h-[320px] w-full overflow-hidden rounded-md p-1" aria-label={t('devices.shell.title')} />
    </section>
  )
}
