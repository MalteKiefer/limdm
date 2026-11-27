// Side panels of the item editor: the preview of a files or firewall
// template for one device, and the last run of a recurring script per
// device.
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Eye } from 'lucide-react'
import { useId, useState } from 'react'
import { api, unwrap } from '../../api/client'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { Badge } from '../../components/ui'
import { useT } from '../../i18n'
import { ago, dateTime } from '../../i18n/format'

type Obj = Record<string, unknown>

/** Whether a payload uses templates (files[].template or template). */
export function usesTemplate(type: string, payload: Obj) {
  if (type === 'com.limdm.firewall') return payload.template === true
  if (type === 'com.limdm.files') return Array.isArray(payload.files) && payload.files.some((f) => (f as Obj | null)?.template === true)
  return false
}

type Rendered = { payload: Obj; error?: string; vars: { hostname: string; tags: string[]; attributes: Record<string, string> } }

export function TemplatePreview({ type, payload }: { type: string; payload: Obj }) {
  const t = useT()
  const id = useId()
  const [device, setDevice] = useState('')
  const [state, setState] = useState<{ busy?: boolean; data?: Rendered; error?: unknown }>({})
  const hint = device.trim().length >= 2 ? device.trim() : ''
  const devices = useQuery({
    queryKey: ['devices', 'pick', hint],
    enabled: !!hint,
    staleTime: 30_000,
    queryFn: () => unwrap(api.GET('/api/v1/devices', { params: { query: { filter: hint, limit: 10 } } })),
  })
  const render = () => {
    if (!device.trim()) return
    setState({ busy: true })
    unwrap(api.POST('/api/v1/config/library/render', { body: { type, payload: payload as never, device: device.trim() } })).then(
      (data) => setState({ data: data as Rendered }),
      (error: unknown) => setState({ error }),
    )
  }
  const files = type === 'com.limdm.files' ? ((state.data?.payload.files as Obj[] | undefined) ?? []) : []
  return (
    <section className="card p-[var(--pad-card)]" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`} className="font-semibold">
        {t('config.tplPreview')}
      </h2>
      <p className="mb-3 text-[12.5px] text-muted">{t('config.tplPreviewHelp')}</p>
      <label htmlFor={`${id}-d`} className="mb-1 block text-[13px] font-medium">
        {t('config.tplDevice')}
      </label>
      <div className="flex gap-2">
        <input
          id={`${id}-d`}
          className="field min-w-0 flex-1"
          list={`${id}-l`}
          value={device}
          autoComplete="off"
          onChange={(e) => setDevice(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault() // the editor is a form: Enter must not save it
              render()
            }
          }}
        />
        <datalist id={`${id}-l`}>
          {devices.data?.items.map((d) => (
            <option key={d.id} value={d.hostname}>
              {d.id}
            </option>
          ))}
        </datalist>
        <button type="button" className="btn" disabled={!device.trim() || state.busy} onClick={render}>
          <Eye size={14} aria-hidden /> {t('config.tplRender')}
        </button>
      </div>
      <div aria-live="polite" className="mt-3">
        {state.busy && <LoadingState rows={2} />}
        {state.error !== undefined && (
          <p role="alert" className="rounded-lg bg-bad-soft p-3 text-[13px] text-bad">
            {errorText(state.error)}
          </p>
        )}
        {state.data && (
          <>
            {state.data.error && (
              <p role="alert" className="mb-2 rounded-lg bg-bad-soft p-3 text-[13px] text-bad">
                {t('config.tplFailed', { error: state.data.error })}
              </p>
            )}
            <dl className="mb-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[12.5px]">
              <dt className="text-muted">{t('config.tplVarHost')}</dt>
              <dd className="font-mono">{state.data.vars.hostname}</dd>
              <dt className="text-muted">{t('config.tplVarTags')}</dt>
              <dd className="font-mono">{state.data.vars.tags.join(', ') || '–'}</dd>
              <dt className="text-muted">{t('config.tplVarAttrs')}</dt>
              <dd className="font-mono break-all">
                {Object.entries(state.data.vars.attributes ?? {})
                  .map(([k, v]) => `${k}=${v}`)
                  .join(', ') || '–'}
              </dd>
            </dl>
            {type === 'com.limdm.files' ? (
              files.map((f) => (
                <div key={String(f.path)} className="mb-2">
                  <div className="flex items-center gap-2 font-mono text-[12.5px]">
                    {String(f.path)} {f.template === true && <Badge tone="bad">{t('config.tplNotRendered')}</Badge>}
                  </div>
                  <pre className="max-h-64 overflow-auto rounded-lg bg-surface-2 p-2 font-mono text-[12px] whitespace-pre-wrap">{String(f.content ?? '')}</pre>
                </div>
              ))
            ) : (
              <pre className="max-h-80 overflow-auto rounded-lg bg-surface-2 p-2 font-mono text-[12px]">{JSON.stringify(state.data.payload, null, 2)}</pre>
            )}
          </>
        )}
      </div>
    </section>
  )
}

/** Last run of each recurring script of the item, per device. */
export function ScriptRuns({ payload }: { payload: Obj }) {
  const t = useT()
  const id = useId()
  const names = Array.isArray(payload.scripts) ? payload.scripts.map((s) => String((s as Obj | null)?.name ?? '')).filter(Boolean) : []
  const [pick, setPick] = useState('')
  const name = names.includes(pick) ? pick : (names[0] ?? '')
  const q = useQuery({
    queryKey: ['config', 'scriptRuns', name],
    enabled: !!name,
    queryFn: () => unwrap(api.GET('/api/v1/config/scripts/results', { params: { query: { name } } })),
  })
  if (!names.length) return null
  return (
    <section className="card p-[var(--pad-card)]" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`} className="font-semibold">
        {t('config.runsTitle')}
      </h2>
      {names.length > 1 && (
        <select className="field mt-2" aria-label={t('config.runsScript')} value={name} onChange={(e) => setPick(e.target.value)}>
          {names.map((n) => (
            <option key={n}>{n}</option>
          ))}
        </select>
      )}
      <div className="mt-3">
        {q.error ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : !q.data ? (
          <LoadingState rows={2} />
        ) : !q.data.items.length ? (
          <EmptyState title={t('config.runsEmpty')}>{t('config.runsEmptyHelp')}</EmptyState>
        ) : (
          <ul className="flex flex-col gap-2">
            {q.data.items.map((r) => (
              <li key={r.device_id} className="text-[13px]">
                <div className="flex flex-wrap items-center gap-2">
                  <Link to="/devices/$id" params={{ id: r.device_id }} className="font-medium hover:underline">
                    {r.hostname || r.device_id}
                  </Link>
                  <Badge tone={r.exit_code === 0 ? 'ok' : 'bad'}>{t('config.runsExit', { code: r.exit_code })}</Badge>
                  <span className="text-muted" title={dateTime(r.end)}>
                    {ago(r.end)}
                  </span>
                </div>
                {r.output && (
                  <details>
                    <summary className="cursor-pointer text-[12.5px] text-muted">{t('config.runsOutput')}</summary>
                    <pre className="max-h-48 overflow-auto rounded-lg bg-surface-2 p-2 font-mono text-[12px] whitespace-pre-wrap">{r.output}</pre>
                  </details>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
