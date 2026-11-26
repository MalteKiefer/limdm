// Scheduled reports: a saved report gets a cadence and recipients; the
// server runs it as its owner and sends a link. Runs keep the last files.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, Download, Play, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { api, unwrap, type Schemas } from '../../api/client'
import { useSavedViews } from '../../api/views'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime } from '../../i18n/format'
import { parseEmails } from './preset'

const key = ['reports', 'schedules']
const cadences = ['daily', 'weekly', 'monthly'] as const
type Cadence = (typeof cadences)[number]

export function Schedules() {
  const t = useT()
  const qc = useQueryClient()
  const list = useQuery({ queryKey: key, queryFn: () => unwrap(api.GET('/api/v1/report-schedules')) })
  const views = useSavedViews('reports')
  const [viewID, setViewID] = useState('')
  const [cadence, setCadence] = useState<Cadence>('weekly')
  const [channels, setChannels] = useState<number[]>([])
  const [emails, setEmails] = useState('')
  const [error, setError] = useState<{ field?: string; text: string } | null>(null)
  const done = () => void qc.invalidateQueries({ queryKey: key })
  const save = useMutation({
    mutationFn: () => unwrap(api.POST('/api/v1/report-schedules', { body: { view_id: Number(viewID), cadence, channels, emails: parseEmails(emails) } })),
    onSuccess: () => {
      toast(t('reports.sched.saved'))
      setError(null)
      done()
    },
    onError: (e) => setError({ field: (e as { problem?: { field?: string } }).problem?.field, text: errorText(e) }),
  })
  const run = useMutation({
    mutationFn: (id: number) => unwrap(api.POST('/api/v1/report-schedules/{id}/run', { params: { path: { id } } })),
    onSuccess: (r) => {
      toast(r.error ? t('reports.sched.runFailed', { error: r.error }) : t('reports.sched.ran', { rows: r.rows }), r.error ? 'error' : 'ok')
      done()
    },
    onError: (e) => toast(errorText(e), 'error'),
  })
  const del = useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/api/v1/report-schedules/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      toast(t('reports.sched.deleted'))
      done()
    },
    onError: (e) => toast(errorText(e), 'error'),
  })
  const chans = list.data?.channels ?? []
  const name = (id: number) => chans.find((c) => c.id === id)?.name ?? `#${id}`
  const errFor = (f: string) => (error && (error.field === f || (!error.field && f === 'view_id')) ? error.text : undefined)
  return (
    <Card title={t('reports.sched.title')} sub={t('reports.sched.sub')} id="r-sched">
      {list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : !list.data ? (
        <LoadingState rows={2} />
      ) : (
        <>
          {list.data.items.length ? (
            <ul className="mb-5 divide-y divide-line" aria-label={t('reports.sched.title')}>
              {list.data.items.map((s) => (
                <li key={s.id} className="flex flex-wrap items-start gap-3 py-3">
                  <CalendarClock size={18} className="mt-0.5 shrink-0 text-muted" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <div className="font-medium">
                      {s.name} <Badge>{t(`reports.cadence.${s.cadence}` as MessageKey)}</Badge>
                    </div>
                    <div className="text-[12.5px] text-muted">
                      {t('reports.sched.to', { to: [...s.channels.map(name), ...s.emails].join(', ') })} · {t('reports.sched.next', { at: dateTime(s.next_run) })}
                      {s.last_run && ` · ${t('reports.sched.last', { at: dateTime(s.last_run) })}`} · {s.owner}
                    </div>
                    {s.last_error && <div className="text-[12.5px] font-medium text-bad">{s.last_error}</div>}
                    <Runs id={s.id} />
                  </div>
                  <div className="flex gap-2">
                    <button type="button" className="btn" disabled={run.isPending} onClick={() => run.mutate(s.id)}>
                      <Play size={14} aria-hidden /> {t('reports.sched.runNow')}
                    </button>
                    <button type="button" className="btn btn-ghost" aria-label={`${t('common.delete')}: ${s.name}`} onClick={() => del.mutate(s.id)}>
                      <Trash2 size={14} aria-hidden />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState icon={CalendarClock} title={t('reports.sched.none')}>
              {t('reports.sched.noneBody')}
            </EmptyState>
          )}
          <form
            className="grid gap-3 border-t border-line pt-4 sm:grid-cols-2 xl:grid-cols-4"
            onSubmit={(e) => {
              e.preventDefault()
              save.mutate()
            }}
          >
            <Field label={t('reports.sched.report')} required error={errFor('view_id')}>
              {({ id, describedBy, invalid }) => (
                <select id={id} className="field" required value={viewID} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setViewID(e.target.value)}>
                  <option value="">{t('reports.sched.pick')}</option>
                  {views.data?.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.name}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field label={t('reports.sched.cadence')} error={errFor('cadence')}>
              {({ id }) => (
                <select id={id} className="field" value={cadence} onChange={(e) => setCadence(e.target.value as Cadence)}>
                  {cadences.map((c) => (
                    <option key={c} value={c}>
                      {t(`reports.cadence.${c}` as MessageKey)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <fieldset className="flex flex-col gap-1" aria-describedby={errFor('channels') ? 'sched-ch-err' : undefined}>
              <legend className="text-[13px] font-medium">{t('reports.sched.channels')}</legend>
              {chans.length ? (
                chans.map((c) => (
                  <label key={c.id} className="flex items-center gap-2 text-[13px]">
                    <input type="checkbox" checked={channels.includes(c.id)} onChange={(e) => setChannels(e.target.checked ? [...channels, c.id] : channels.filter((x) => x !== c.id))} />
                    {c.name} <span className="text-muted">({c.kind})</span>
                  </label>
                ))
              ) : (
                <p className="text-[12.5px] text-muted">{t('reports.sched.noChannels')}</p>
              )}
              {errFor('channels') && (
                <p id="sched-ch-err" className="text-[12.5px] font-medium text-bad">
                  {errFor('channels')}
                </p>
              )}
            </fieldset>
            <Field label={t('reports.sched.emails')} help={t('reports.sched.emailsHelp')} error={errFor('emails')}>
              {({ id, describedBy, invalid }) => <input id={id} className="field" value={emails} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setEmails(e.target.value)} />}
            </Field>
            <div className="sm:col-span-2 xl:col-span-4">
              <button type="submit" className="btn btn-primary" disabled={save.isPending}>
                <CalendarClock size={14} aria-hidden /> {t('reports.sched.save')}
              </button>
            </div>
          </form>
        </>
      )}
    </Card>
  )
}

function Runs({ id }: { id: number }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const runs = useQuery({
    queryKey: [...key, id, 'runs'],
    enabled: open,
    queryFn: () => unwrap(api.GET('/api/v1/report-schedules/{id}/runs', { params: { path: { id } } })).then((p) => p.items),
  })
  return (
    <details className="mt-1 text-[12.5px]" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer text-accent">{t('reports.sched.runs')}</summary>
      {runs.data && !runs.data.length && <p className="text-muted">{t('reports.sched.noRuns')}</p>}
      <ul className="mt-1 flex flex-col gap-1">
        {runs.data?.map((r: Schemas['ReportRun']) => (
          <li key={r.id} className="flex flex-wrap items-center gap-2">
            <span>{dateTime(r.at)}</span>
            {r.error ? (
              <span className="text-bad">{r.error}</span>
            ) : (
              <>
                <span className="text-muted">{t('reports.sched.rows', { count: r.rows })}</span>
                <a className="inline-flex items-center gap-1 text-accent hover:underline" href={`/api/v1/report-runs/${r.id}`} download>
                  <Download size={12} aria-hidden /> {t('reports.download')}
                </a>
                <span className="font-mono text-[11px] break-all text-muted" title="SHA-256">
                  {r.sha256.slice(0, 16)}
                </span>
              </>
            )}
          </li>
        ))}
      </ul>
    </details>
  )
}
