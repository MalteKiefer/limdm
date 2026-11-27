// The Logs page: search across the devices of the caller's scope (or one
// device, see LogsTab) with filters, the query language, a histogram per
// priority (click a bar to zoom), the virtual result list, a detail sheet
// with context lines, live tail, saved views, export and copy link; and
// the alert rules. Every view state of the page lives in the URL.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { BellRing, Check, Download, FlaskConical, Link2, Pause, Play, Plus, RefreshCw, ScrollText, Trash2, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useCan } from '../../api/me'
import { ChartFrame } from '../../components/charts'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { Field } from '../../components/form'
import { SideSheet, SplitView, TabBar, TabPanel } from '../../components/layout'
import { QueryBar, type QueryKey } from '../../components/querybar'
import { SavedViewsMenu } from '../../components/savedviews'
import { Confirm, Facts } from '../../components/settingsform'
import { EmptyState, ErrorState, errorText, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { ActionMenu, Badge, Card, Modal, PageHeader, Switch } from '../../components/ui'
import { currentLocale, useT, type MessageKey } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { exportLogs, useAlerts, useDeleteAlert, useFacets, useHistogram, useLogContext, useLogs, useSaveAlert, useTestAlert, type LogAlert, type LogLine } from './api'
import { apiParams, groupCounts, hasFilter, prioGroups, prioName, priorities, prioTone, ranges, sources, toLocalInput, zoomTo, type LogSearch, type PrioGroup } from './logic'

const tabs = ['search', 'alerts'] as const

export function LogsPage() {
  const t = useT()
  const s = useSearch({ strict: false }) as LogSearch
  const navigate = useNavigate()
  const go = useCallback((patch: Partial<LogSearch>) => void navigate({ to: '/logs', search: ((prev: LogSearch) => ({ ...prev, ...patch })) as never, replace: true }), [navigate])
  const tab = s.tab === 'alerts' ? 'alerts' : 'search'
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader title={t('logs.title')} sub={t('logs.sub')} />
      <TabBar idBase="logs" label={t('logs.tabs')} value={tab} onChange={(v) => go({ tab: v === 'search' ? undefined : v, sel: undefined })} tabs={tabs.map((v) => ({ value: v, label: t(`logs.tab.${v}`) }))} />
      <TabPanel idBase="logs" value={tab}>
        {tab === 'search' ? <LogExplorer s={s} go={go} /> : <Alerts />}
      </TabPanel>
    </div>
  )
}

const timeFmt = (at: string) =>
  new Intl.DateTimeFormat(currentLocale() === 'de' ? 'de-DE' : 'en-GB', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(at))

export function PrioBadge({ p }: { p: number }) {
  return <Badge tone={prioTone(p)}>{prioName(p)}</Badge>
}

/** Search, histogram and list; with deviceId for one device (the device tab). */
export function LogExplorer({ s, go, deviceId }: { s: LogSearch; go: (p: Partial<LogSearch>) => void; deviceId?: string }) {
  const t = useT()
  const live = s.live === 'on'
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => setNow(Date.now()), 15_000)
    return () => clearInterval(id)
  }, [live])
  const minute = Math.ceil(now / 60_000)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const params = useMemo(() => apiParams(s, deviceId, now), [s.q, s.range, s.from, s.to, s.source, s.prio, s.device, deviceId, minute])
  const list = useLogs(params, live)
  const hist = useHistogram(params, live)
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data])
  const sel = rows.find((r) => r.id === s.sel)
  const idx = sel ? rows.indexOf(sel) : -1
  const columns = useMemo<GridColumn<LogLine>[]>(
    () => [
      { id: 'at', header: t('logs.col.time'), meta: { className: 'w-40' }, cell: ({ row: { original: l } }) => <span className="num font-mono text-meta whitespace-nowrap">{timeFmt(l.at)}</span> },
      { id: 'prio', header: t('logs.col.prio'), meta: { className: 'w-24' }, cell: ({ row: { original: l } }) => <PrioBadge p={l.priority} /> },
      ...(deviceId ? [] : [{ id: 'device', header: t('logs.col.device'), cell: ({ row: { original: l } }: { row: { original: LogLine } }) => <span className="truncate">{l.hostname}</span> } as GridColumn<LogLine>]),
      { id: 'unit', header: t('logs.col.unit'), cell: ({ row: { original: l } }) => <span className="truncate font-mono text-meta">{l.unit}</span> },
      { id: 'message', header: t('logs.col.message'), meta: { className: 'w-[55%]' }, cell: ({ row: { original: l } }) => <span className="block truncate font-mono text-meta">{l.message}</span> },
    ],
    [t, deviceId],
  )
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Filters s={s} go={go} deviceId={deviceId} params={params} live={live} refresh={() => (setNow(Date.now()), void list.refetch(), void hist.refetch())} />
      <Card title={t('logs.hist.title')} sub={t('logs.hist.sub')}>
        {hist.error ? <ErrorState error={hist.error} onRetry={() => void hist.refetch()} /> : hist.data ? <Histogram data={hist.data} onZoom={(at) => go({ ...zoomTo(at, hist.data.bucket_seconds), live: undefined })} /> : <LoadingState rows={2} />}
      </Card>
      <SplitView
        list={
          list.error ? (
            <ErrorState error={list.error} onRetry={() => void list.refetch()} />
          ) : list.isLoading ? (
            <LoadingState rows={8} />
          ) : (
            <section aria-label={t('logs.results')} className="flex flex-col gap-2">
              <span className="text-meta text-muted" aria-live="polite">
                {t(list.hasNextPage ? 'logs.countMore' : 'logs.count', { count: rows.length })}
                {live && ` · ${t('logs.liveOn')}`}
              </span>
              <DataGrid
                data={rows}
                columns={columns}
                getRowId={(l) => l.id}
                label={t('logs.results')}
                activeId={s.sel}
                onRowClick={(l) => go({ sel: l.id })}
                onEndReached={() => list.hasNextPage && !list.isFetchingNextPage && void list.fetchNextPage()}
                loadingMore={list.isFetchingNextPage}
                card={(l) => (
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="flex items-center gap-2 text-meta">
                      <PrioBadge p={l.priority} />
                      <span className="num font-mono">{timeFmt(l.at)}</span>
                      <span className="truncate text-muted">{deviceId ? l.unit : l.hostname}</span>
                    </span>
                    <span className="truncate font-mono text-meta">{l.message}</span>
                  </div>
                )}
                empty={
                  <EmptyState
                    icon={ScrollText}
                    compact
                    title={t(hasFilter(s) ? 'logs.empty.noMatch' : 'logs.empty.title')}
                    action={
                      hasFilter(s) ? (
                        <button type="button" className="btn" onClick={() => go({ q: undefined, source: undefined, prio: undefined, device: undefined })}>
                          {t('logs.reset')}
                        </button>
                      ) : (
                        !deviceId && (
                          <Link to="/config" search={{ tab: 'library' } as never} className="btn">
                            {t('logs.empty.action')}
                          </Link>
                        )
                      )
                    }
                  >
                    {t(hasFilter(s) ? 'logs.empty.noMatchBody' : 'logs.empty.body')}
                  </EmptyState>
                }
              />
            </section>
          )
        }
        detail={
          sel && (
            <Detail
              line={sel}
              deviceId={deviceId}
              onClose={() => go({ sel: undefined })}
              onPrev={idx > 0 ? () => go({ sel: rows[idx - 1].id }) : undefined}
              onNext={idx >= 0 && idx < rows.length - 1 ? () => go({ sel: rows[idx + 1].id }) : undefined}
            />
          )
        }
      />
    </div>
  )
}

const queryKeys = (t: (k: MessageKey) => string): QueryKey[] =>
  ['device', 'tag', 'blueprint', 'os', 'source', 'unit', 'container', 'file', 'host', 'prio', 'field.'].map((key) => ({ key: key.replace(/\.$/, ''), help: t(`logs.key.${key.replace(/\.$/, '')}` as MessageKey) }))

function Filters({ s, go, deviceId, params, live, refresh }: { s: LogSearch; go: (p: Partial<LogSearch>) => void; deviceId?: string; params: ReturnType<typeof apiParams>; live: boolean; refresh: () => void }) {
  const t = useT()
  const facets = useFacets(params)
  const [device, setDevice] = useState(s.device ?? '')
  useEffect(() => {
    const id = setTimeout(() => {
      if ((s.device ?? '') !== device.trim()) go({ device: device.trim() || undefined })
    }, 350)
    return () => clearTimeout(id)
  }, [device, s.device, go])
  const custom = s.range === 'custom'
  const doExport = (f: 'ndjson' | 'csv') =>
    void exportLogs(params, f).then(
      () => toast(t('logs.exported')),
      (e) => toast(errorText(e), 'error'),
    )
  return (
    <section aria-label={t('logs.filters')} className="card flex flex-col gap-3 p-[var(--pad-card)]">
      <QueryBar value={s.q ?? ''} onChange={(q) => go({ q: q || undefined, sel: undefined })} keys={queryKeys(t)} label={t('logs.query')} placeholder={t('logs.queryHint')} />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Field label={t('logs.range')}>
          {({ id }) => (
            <select
              id={id}
              className="field"
              value={custom ? 'custom' : (s.range ?? '1h')}
              onChange={(e) => {
                const v = e.target.value
                if (v === 'custom') {
                  const to = new Date()
                  go({ range: 'custom', from: toLocalInput(new Date(to.getTime() - 3_600_000)), to: toLocalInput(to), live: undefined })
                } else go({ range: v === '1h' ? undefined : v, from: undefined, to: undefined })
              }}
            >
              {ranges.map((r) => (
                <option key={r} value={r}>
                  {t(`logs.range.${r}` as MessageKey)}
                </option>
              ))}
              <option value="custom">{t('logs.range.custom')}</option>
            </select>
          )}
        </Field>
        <Field label={t('logs.source')}>
          {({ id }) => (
            <select id={id} className="field" value={s.source ?? ''} onChange={(e) => go({ source: e.target.value || undefined })}>
              <option value="">{t('logs.source.all')}</option>
              {sources.map((x) => (
                <option key={x} value={x}>
                  {t(`logs.source.${x}` as MessageKey)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('logs.prio')}>
          {({ id }) => (
            <select id={id} className="field" value={s.prio ?? ''} onChange={(e) => go({ prio: e.target.value || undefined })}>
              <option value="">{t('logs.prio.all')}</option>
              {priorities.map((p) => (
                <option key={p} value={p}>
                  {t('logs.prioOption', { p })}
                </option>
              ))}
            </select>
          )}
        </Field>
        {!deviceId && (
          <Field label={t('logs.device')}>
            {({ id }) => <input id={id} className="field" value={device} placeholder={t('logs.deviceHint')} onChange={(e) => setDevice(e.target.value)} />}
          </Field>
        )}
        <Field label={t('logs.unit')}>
          {({ id }) => (
            <select
              id={id}
              className="field"
              value=""
              onChange={(e) => {
                const u = facets.data?.units.find((x) => `${x.source}|${x.unit}` === e.target.value)
                if (u) go({ q: `${s.q ? s.q + ' ' : ''}${u.source === 'journald' ? 'unit' : u.source}:${/[\s"]/.test(u.unit) ? `"${u.unit}"` : u.unit}` })
              }}
            >
              <option value="">{t('logs.unitPick')}</option>
              {(facets.data?.units ?? []).map((u) => (
                <option key={`${u.source}|${u.unit}`} value={`${u.source}|${u.unit}`}>
                  {u.unit || t(`logs.source.${u.source}` as MessageKey)} ({fmt(u.count)})
                </option>
              ))}
            </select>
          )}
        </Field>
      </div>
      {custom && (
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('logs.from')}>{({ id }) => <input id={id} type="datetime-local" className="field" value={s.from ?? ''} max={s.to} onChange={(e) => go({ from: e.target.value || undefined })} />}</Field>
          <Field label={t('logs.to')}>{({ id }) => <input id={id} type="datetime-local" className="field" value={s.to ?? ''} min={s.from} onChange={(e) => go({ to: e.target.value || undefined })} />}</Field>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={cx('btn', live && 'btn-primary')} aria-pressed={live} disabled={custom} onClick={() => go({ live: live ? undefined : 'on' })}>
          {live ? <Pause size={14} aria-hidden /> : <Play size={14} aria-hidden />} {t(live ? 'logs.pause' : 'logs.live')}
        </button>
        <button type="button" className="btn" onClick={refresh}>
          <RefreshCw size={14} aria-hidden /> {t('logs.refresh')}
        </button>
        <ActionMenu
          trigger={
            <button type="button" className="btn">
              <Download size={14} aria-hidden /> {t('logs.export')}
            </button>
          }
          items={[
            { label: t('logs.exportNdjson'), onClick: () => doExport('ndjson') },
            { label: t('logs.exportCsv'), onClick: () => doExport('csv') },
          ]}
        />
        <button
          type="button"
          className="btn"
          onClick={() =>
            void navigator.clipboard.writeText(location.href).then(
              () => toast(t('logs.linkCopied')),
              () => toast(t('logs.copyFailed'), 'error'),
            )
          }
        >
          <Link2 size={14} aria-hidden /> {t('logs.copyLink')}
        </button>
        {!deviceId && <SavedViewsMenu list="logs" current={{ query: [s.q, s.source && `source:${s.source}`, s.prio && `prio<=${s.prio}`, s.device && `device:${s.device}`].filter(Boolean).join(' ') }} onApply={(v) => go({ q: v.query || undefined, source: undefined, prio: undefined, device: undefined, sel: undefined })} />}
        {hasFilter(s) && (
          <button type="button" className="btn btn-ghost" onClick={() => (setDevice(''), go({ q: undefined, source: undefined, prio: undefined, device: undefined }))}>
            <X size={14} aria-hidden /> {t('logs.reset')}
          </button>
        )}
      </div>
    </section>
  )
}

const groupColor: Record<PrioGroup, string> = { crit: 'var(--c-bad)', err: 'var(--c-s3)', warning: 'var(--c-warn-mark)', info: 'var(--c-info)', debug: 'var(--c-off)' }

/** Stacked bars per time bucket and priority group; a click zooms into the bucket. */
function Histogram({ data, onZoom }: { data: { bucket_seconds: number; buckets: { at: string; counts: number[] }[] }; onZoom: (at: string) => void }) {
  const t = useT()
  const groups = data.buckets.map((b) => ({ at: b.at, g: groupCounts(b.counts) }))
  const totals = groups.map((b) => Object.values(b.g).reduce((a, c) => a + c, 0))
  const peak = Math.max(1, ...totals)
  const total = totals.reduce((a, c) => a + c, 0)
  const label = (k: PrioGroup) => t(`logs.group.${k}` as MessageKey)
  return (
    <ChartFrame
      caption={t('logs.hist.title')}
      table={{ head: [t('logs.col.time'), ...prioGroups.map((g) => label(g.id))], rows: groups.filter((_, i) => totals[i] > 0).map((b) => [dateTime(b.at), ...prioGroups.map((g) => fmt(b.g[g.id]))]) }}
      chart={
        <div>
          <div role="group" aria-label={t('logs.hist.label', { count: total })} className="flex h-32 items-end gap-px">
            {groups.map((b, i) => (
              <button
                key={b.at}
                type="button"
                className="flex h-full min-w-0 flex-1 flex-col-reverse rounded-sm hover:bg-surface-2 focus-visible:outline-2"
                aria-label={t('logs.hist.bar', { at: dateTime(b.at), count: totals[i] })}
                title={`${dateTime(b.at)}: ${fmt(totals[i])}`}
                onClick={() => onZoom(b.at)}
              >
                {prioGroups.map((g) => b.g[g.id] > 0 && <span key={g.id} className="block w-full" style={{ height: `${(b.g[g.id] / peak) * 100}%`, background: groupColor[g.id] }} />)}
              </button>
            ))}
          </div>
          <ul className="mt-2 flex flex-wrap gap-3 text-micro text-muted" aria-hidden>
            {prioGroups.map((g) => (
              <li key={g.id} className="flex items-center gap-1">
                <span className="size-2.5 rounded-sm" style={{ background: groupColor[g.id] }} /> {label(g.id)}
              </li>
            ))}
          </ul>
        </div>
      }
    />
  )
}

function Detail({ line, deviceId, onClose, onPrev, onNext }: { line: LogLine; deviceId?: string; onClose: () => void; onPrev?: () => void; onNext?: () => void }) {
  const t = useT()
  const ctx = useLogContext(line.id)
  return (
    <SideSheet title={<span className="font-mono text-body">{line.unit || line.source}</span>} sub={dateTime(line.at)} onClose={onClose} onPrev={onPrev} onNext={onNext}>
      <div className="flex flex-col gap-4">
        <pre className="max-h-64 overflow-auto rounded-md bg-sunken p-3 font-mono text-meta break-all whitespace-pre-wrap">{line.message}</pre>
        <Facts
          rows={[
            [t('logs.col.prio'), <PrioBadge key="p" p={line.priority} />],
            [
              t('logs.col.device'),
              deviceId ? (
                line.hostname
              ) : (
                <Link key="d" to="/devices/$id" params={{ id: line.device_id }} search={{ tab: 'logs' } as never} className="text-accent hover:underline">
                  {line.hostname}
                </Link>
              ),
            ],
            [t('logs.source'), t(`logs.source.${line.source}` as MessageKey)],
            ...(line.host ? [[t('logs.host'), line.host] as [string, string]] : []),
            ...Object.entries(line.fields ?? {}).map(([k, v]) => [<span key={k} className="font-mono">{k}</span>, <span key={k + 'v'} className="font-mono">{v}</span>] as [React.ReactNode, React.ReactNode]),
          ]}
        />
        <section aria-label={t('logs.context')}>
          <h3 className="mb-2 text-body font-semibold">{t('logs.context')}</h3>
          {ctx.error ? (
            <ErrorState error={ctx.error} />
          ) : !ctx.data ? (
            <LoadingState rows={3} />
          ) : (
            <ol className="flex flex-col gap-0.5 font-mono text-micro">
              {ctx.data.items.map((l) => (
                <li key={l.id} className={cx('flex gap-2 rounded px-1 py-0.5', l.id === line.id && 'bg-accent-soft font-semibold')} aria-current={l.id === line.id || undefined}>
                  <span className="num shrink-0 text-muted">{timeFmt(l.at)}</span>
                  <span className="shrink-0">{prioName(l.priority)}</span>
                  <span className="min-w-0 break-all">{l.message}</span>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </SideSheet>
  )
}

// ---- alert rules ----

const emptyAlert = { name: '', query: '', threshold: 10, window_minutes: 15, severity: 'warning' as 'info' | 'warning' | 'critical', enabled: true }

function Alerts() {
  const t = useT()
  const admin = useCan('admin')
  const list = useAlerts()
  const save = useSaveAlert()
  const del = useDeleteAlert()
  const test = useTestAlert()
  const [edit, setEdit] = useState<(typeof emptyAlert & { id?: number }) | null>(null)
  const [deleting, setDeleting] = useState<LogAlert | null>(null)
  const [err, setErr] = useState('')
  if (list.error) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />
  if (!list.data) return <LoadingState rows={4} />
  const items = list.data.items
  return (
    <Card
      title={t('logs.alerts.title')}
      sub={t('logs.alerts.sub')}
      action={
        admin && (
          <button type="button" className="btn btn-primary" onClick={() => (setErr(''), setEdit({ ...emptyAlert }))}>
            <Plus size={14} aria-hidden /> {t('logs.alerts.add')}
          </button>
        )
      }
    >
      {!items.length ? (
        <EmptyState icon={BellRing} title={t('logs.alerts.empty')} compact>
          {t('logs.alerts.emptyBody')}
        </EmptyState>
      ) : (
        <ul className="flex flex-col divide-y divide-line">
          {items.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{a.name}</span>
                  <Badge tone={a.severity === 'critical' ? 'bad' : a.severity === 'warning' ? 'warn' : 'info'}>{t(`logs.sev.${a.severity}` as MessageKey)}</Badge>
                  {!a.enabled && <Badge tone="off">{t('logs.alerts.off')}</Badge>}
                </div>
                <p className="truncate font-mono text-meta text-muted">{a.query}</p>
                <p className="text-micro text-muted">
                  {t('logs.alerts.rule', { threshold: a.threshold, minutes: a.window_minutes })}
                  {a.last_fired_at && ` · ${t('logs.alerts.fired', { at: dateTime(a.last_fired_at) })}`}
                </p>
              </div>
              {admin && (
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    className="btn"
                    disabled={test.isPending}
                    onClick={() =>
                      test.mutate(a.id, {
                        onSuccess: (r) => toast(t(r.matches ? 'logs.alerts.testMatch' : 'logs.alerts.testNoMatch', { count: r.count })),
                        onError: (e) => toast(errorText(e), 'error'),
                      })
                    }
                  >
                    <FlaskConical size={14} aria-hidden /> {t('logs.alerts.test')}
                  </button>
                  <button type="button" className="btn" onClick={() => (setErr(''), setEdit({ id: a.id, name: a.name, query: a.query, threshold: a.threshold, window_minutes: a.window_minutes, severity: a.severity ?? 'warning', enabled: a.enabled ?? true }))}>
                    {t('logs.alerts.edit')}
                  </button>
                  <button type="button" className="btn btn-ghost" aria-label={t('logs.alerts.delete', { name: a.name })} onClick={() => setDeleting(a)}>
                    <Trash2 size={14} aria-hidden />
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {edit && (
        <Modal
          open
          onClose={() => setEdit(null)}
          title={t(edit.id ? 'logs.alerts.editTitle' : 'logs.alerts.add')}
          description={t('logs.alerts.formSub')}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setEdit(null)}>
                {t('common.cancel')}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={save.isPending}
                onClick={() =>
                  save.mutate(edit, {
                    onSuccess: () => (toast(t('logs.alerts.saved')), setEdit(null)),
                    onError: (e) => setErr(errorText(e)),
                  })
                }
              >
                <Check size={14} aria-hidden /> {t('common.save')}
              </button>
            </>
          }
        >
          <div className="flex flex-col gap-3">
            <Field label={t('logs.alerts.name')} required>
              {({ id }) => <input id={id} className="field" maxLength={100} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} />}
            </Field>
            <Field label={t('logs.query')} help={t('logs.alerts.queryHelp')} required>
              {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} className="field font-mono" value={edit.query} onChange={(e) => setEdit({ ...edit, query: e.target.value })} />}
            </Field>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label={t('logs.alerts.threshold')}>
                {({ id }) => <input id={id} type="number" min={1} className="field" value={edit.threshold} onChange={(e) => setEdit({ ...edit, threshold: Number(e.target.value) })} />}
              </Field>
              <Field label={t('logs.alerts.window')}>
                {({ id }) => <input id={id} type="number" min={1} max={1440} className="field" value={edit.window_minutes} onChange={(e) => setEdit({ ...edit, window_minutes: Number(e.target.value) })} />}
              </Field>
              <Field label={t('logs.alerts.severity')}>
                {({ id }) => (
                  <select id={id} className="field" value={edit.severity} onChange={(e) => setEdit({ ...edit, severity: e.target.value as typeof edit.severity })}>
                    {(['info', 'warning', 'critical'] as const).map((v) => (
                      <option key={v} value={v}>
                        {t(`logs.sev.${v}`)}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            </div>
            <Switch checked={edit.enabled} onChange={(v) => setEdit({ ...edit, enabled: v })} label={t('logs.alerts.enabled')} />
            {err && (
              <p role="alert" className="rounded-md bg-bad-soft p-2 text-body text-bad">
                {err}
              </p>
            )}
          </div>
        </Modal>
      )}
      <Confirm
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title={t('logs.alerts.deleteTitle', { name: deleting?.name ?? '' })}
        confirm={t('common.delete')}
        danger
        busy={del.isPending}
        onConfirm={() =>
          deleting &&
          del.mutate(deleting.id, {
            onSuccess: () => (toast(t('logs.alerts.deleted')), setDeleting(null)),
            onError: (e) => toast(errorText(e), 'error'),
          })
        }
      />
    </Card>
  )
}
