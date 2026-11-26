// Reports ("Berichte"): the compliance state at a date (all devices or one
// with its changes), the evidence exports and report presets (saved views
// of the list "reports": an export with its parameters, relative days
// allowed). Exports are for admins and auditors, as in the console.
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Download, FileBarChart2 } from 'lucide-react'
import { useState } from 'react'
import { api, unwrap } from '../../api/client'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { SavedViewsMenu } from '../../components/savedviews'
import { ErrorState, LoadingState } from '../../components/states'
import { Badge, Card, PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { Schedules } from './schedules'
import { decodePreset, encodePreset, kinds, paramsOf, presetHref, type Kind, type Preset } from './preset'

type Search = { at?: string; device?: string }

const today = () => {
  const d = new Date()
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

export function ReportsPage() {
  const t = useT()
  const canExport = useCan('audit')
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader title={t('reports.title')} sub={t('reports.sub')} />
      <History canExport={canExport} />
      {canExport ? (
        <>
          <Exports />
          <Builder />
          <Schedules />
        </>
      ) : (
        <Card title={t('reports.exports')}>
          <p className="text-muted">{t('reports.noExports')}</p>
        </Card>
      )}
    </div>
  )
}

function History({ canExport }: { canExport: boolean }) {
  const t = useT()
  const s = useSearch({ strict: false }) as Search
  const nav = useNavigate()
  const at = s.at ?? today()
  const set = (p: Partial<Search>) => void nav({ to: '/reports', search: { ...s, ...p }, replace: true })
  const hist = useQuery({
    queryKey: ['reports', 'history', at, s.device ?? ''],
    queryFn: () => unwrap(api.GET('/api/v1/compliance/history', { params: { query: { at, ...(s.device ? { device: s.device } : {}) } } })),
  })
  const devices = useQuery({
    queryKey: ['devices', 'reports-picker'],
    queryFn: () => unwrap(api.GET('/api/v1/devices', { params: { query: { limit: 500, sort: 'hostname' } } })).then((p) => p.items ?? []),
  })
  const csv = presetHref({ kind: 'compliance-history.csv', at, device: s.device })
  return (
    <Card
      title={t('reports.history')}
      sub={t('reports.historySub')}
      id="r-hist"
      action={
        canExport && (
          <a className="btn" href={csv} download>
            <Download size={14} aria-hidden /> {t('reports.csv')}
          </a>
        )
      }
    >
      <div className="mb-4 grid gap-3 sm:grid-cols-[180px_minmax(0,320px)]">
        <Field label={t('reports.at')}>{({ id }) => <input id={id} type="date" className="field" value={at} max={today()} required onChange={(e) => e.target.value && set({ at: e.target.value })} />}</Field>
        <Field label={t('reports.device')}>
          {({ id }) => (
            <select id={id} className="field" value={s.device ?? ''} onChange={(e) => set({ device: e.target.value || undefined })}>
              <option value="">{t('reports.allDevices')}</option>
              {devices.data?.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.hostname}
                </option>
              ))}
            </select>
          )}
        </Field>
      </div>
      {hist.error ? (
        <ErrorState error={hist.error} onRetry={() => void hist.refetch()} />
      ) : !hist.data ? (
        <LoadingState />
      ) : s.device ? (
        <div className="flex flex-col gap-5">
          <Table
            caption={t('reports.statePerCheck')}
            head={[t('reports.check'), t('reports.status'), t('reports.since'), t('reports.detail'), t('reports.catalog')]}
            empty={t('reports.noState')}
            rows={hist.data.state.map((r) => [<span className="font-mono">{r.check_id}</span>, <StatusBadge status={r.status} />, dateTime(r.since), <span className="text-muted">{r.detail}</span>, <span className="font-mono text-muted">{r.catalog_version}</span>])}
          />
          <Table
            caption={t('reports.changes')}
            head={[t('reports.time'), t('reports.check'), t('reports.status'), t('reports.detail')]}
            empty={t('reports.noChanges')}
            rows={hist.data.changes.map((r) => [dateTime(r.since), <span className="font-mono">{r.check_id}</span>, <StatusBadge status={r.status} />, <span className="text-muted">{r.detail}</span>])}
          />
        </div>
      ) : (
        <Table
          caption={t('reports.devices')}
          head={[t('reports.device'), t('reports.pass'), t('reports.fail'), t('reports.other')]}
          empty={t('reports.noState')}
          rows={hist.data.devices.map((d) => [
            <Link to="/reports" search={{ at, device: d.id }} className="text-accent hover:underline">
              {d.hostname}
            </Link>,
            fmt(d.pass),
            d.fail ? <Badge tone="bad">{fmt(d.fail)}</Badge> : <span className="text-muted">0</span>,
            fmt(d.other),
          ])}
        />
      )}
    </Card>
  )
}

function StatusBadge({ status }: { status: string }) {
  const t = useT()
  const known = ['pass', 'fail', 'removed', 'na', 'error'].includes(status)
  return <Badge tone={status === 'pass' ? 'ok' : status === 'fail' ? 'bad' : 'warn'}>{known ? t(`reports.check.${status}` as MessageKey) : status}</Badge>
}

function Table({ caption, head, rows, empty }: { caption: string; head: string[]; rows: React.ReactNode[][]; empty: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-body">
        <caption className="mb-2 text-left text-meta font-semibold text-muted">{caption}</caption>
        <thead>
          <tr className="border-b border-line text-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="py-2 pr-4 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((r, i) => (
              <tr key={i} className="border-b border-line last:border-0">
                {r.map((c, j) => (
                  <td key={j} className="py-2 pr-4 align-top">
                    {c}
                  </td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={head.length} className="py-6 text-center text-muted">
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

const catalogKinds: Kind[] = ['compliance.csv', 'inventory.csv', 'packages.csv', 'exceptions.csv', 'audit.csv', 'audit.jsonl']

function Exports() {
  const t = useT()
  return (
    <Card title={t('reports.exports')} sub={t('reports.exportsSub')} id="r-exp">
      <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {catalogKinds.map((k) => (
          <li key={k} className="flex items-start gap-3 rounded-lg border border-line p-3">
            <FileBarChart2 size={18} className="mt-0.5 shrink-0 text-muted" aria-hidden />
            <div className="min-w-0 flex-1">
              <div className="font-medium">{t(`reports.kind.${k}` as MessageKey)}</div>
              <p className="text-meta text-muted">{t(`reports.kindHelp.${k}` as MessageKey)}</p>
            </div>
            <a className="btn shrink-0" href={presetHref({ kind: k })} download aria-label={`${t('reports.download')}: ${t(`reports.kind.${k}` as MessageKey)}`}>
              <Download size={14} aria-hidden />
            </a>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function Builder() {
  const t = useT()
  const [p, setP] = useState<Preset>({ kind: 'audit.csv', days: 30 })
  const params = paramsOf(p.kind)
  const text = (k: 'q' | 'actor' | 'action' | 'target' | 'at' | 'device', type = 'text') => (
    <Field key={k} label={t(`reports.param.${k}` as MessageKey)}>
      {({ id }) => <input id={id} type={type} className="field" value={p[k] ?? ''} onChange={(e) => setP({ ...p, [k]: e.target.value || undefined })} />}
    </Field>
  )
  return (
    <Card title={t('reports.builder')} sub={t('reports.builderSub')} id="r-build" action={<SavedViewsMenu list="reports" current={{ query: encodePreset(p) }} onApply={(v) => setP(decodePreset(v.query) ?? p)} />}>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Field label={t('reports.kindLabel')}>
          {({ id }) => (
            <select id={id} className="field" value={p.kind} onChange={(e) => setP({ ...p, kind: e.target.value as Kind })}>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {t(`reports.kind.${k}` as MessageKey)}
                </option>
              ))}
            </select>
          )}
        </Field>
        {params.includes('days') && (
          <Field label={t('reports.param.days')} help={t('reports.daysHelp')}>
            {({ id, describedBy }) => (
              <input id={id} type="number" min={1} max={3650} className="field" aria-describedby={describedBy} value={p.days ?? ''} onChange={(e) => setP({ ...p, days: e.target.value ? Math.max(1, Math.min(3650, Math.trunc(Number(e.target.value)))) : undefined })} />
            )}
          </Field>
        )}
        {params.includes('at') && text('at', 'date')}
        {params.includes('device') && text('device')}
        {params.includes('q') && text('q')}
        {params.includes('actor') && text('actor')}
        {params.includes('action') && text('action')}
        {params.includes('target') && text('target')}
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <a className="btn btn-primary" href={presetHref(p)} download>
          <Download size={14} aria-hidden /> {t('reports.run')}
        </a>
        <span className="font-mono text-meta break-all text-muted">{presetHref(p)}</span>
      </div>
      {!params.length && <p className="mt-3 text-meta text-muted">{t('reports.noParams')}</p>}
    </Card>
  )
}
