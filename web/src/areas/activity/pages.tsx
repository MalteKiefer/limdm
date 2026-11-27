// Activity ("Aktivität"): the audit log and the device events as one
// timeline, a stacked bar per day and category above it, filters in the URL,
// paging, audit exports and the full chain verification for admins and
// auditors. New entries arrive over the live stream.
import { useNavigate, useSearch } from '@tanstack/react-router'
import { Activity, Download, ShieldCheck, ShieldX, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { useCan } from '../../api/me'
import type { Schemas } from '../../api/client'
import { axisX, axisY, baseOption, ChartFrame, EChart, type Colors } from '../../components/charts'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { Timeline } from '../../components/timeline'
import { toast } from '../../components/toast'
import { Badge, Card, PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateShort, dateTime, fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useActivity, useAuditStatus, useHistogram, useVerify } from './api'
import { apiQuery, categories, exportHref, hasFilter, type ActivitySearch, type Category } from './filter'

const catColor = (c: Colors): Record<Category, string> => ({ commands: c.s1, changes: c.s2, approvals: c.s3, access: c.s4, devices: c.s5, audit: c.fg2, events: c.off })

export function ActivityPage() {
  const t = useT()
  const canAudit = useCan('audit')
  const s = useSearch({ strict: false }) as ActivitySearch
  const nav = useNavigate()
  const set = (p: Partial<ActivitySearch>) => void nav({ to: '/activity', search: { ...s, ...p }, replace: true })
  const query = apiQuery(s)
  const stream = useActivity(query)
  const hist = useHistogram(query)
  const status = useAuditStatus(canAudit)
  const verify = useVerify()
  const items = stream.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader
        title={t('activity.title')}
        sub={t('activity.sub')}
        actions={
          canAudit && (
            <>
              <a className="btn" href={exportHref('audit.csv', s)} download>
                <Download size={14} aria-hidden /> {t('activity.csv')}
              </a>
              <a className="btn" href={exportHref('audit.jsonl', s)} download title={t('activity.jsonlHint')}>
                <Download size={14} aria-hidden /> {t('activity.jsonl')}
              </a>
              <button
                type="button"
                className="btn"
                disabled={verify.isPending}
                onClick={() =>
                  verify.mutate(undefined, {
                    onSuccess: (st) => toast(st.broken_at ? t('activity.broken', { id: st.broken_at }) : t('activity.verified'), st.broken_at ? 'error' : 'ok'),
                    onError: (e) => toast(errorText(e), 'error'),
                  })
                }
              >
                <ShieldCheck size={14} aria-hidden /> {verify.isPending ? t('activity.verifying') : t('activity.verify')}
              </button>
            </>
          )
        }
      />
      {canAudit && status.data && <ChainState st={status.data} />}
      <Filters s={s} set={set} actions={status.data?.actions ?? []} />
      <Card title={t('activity.perDay')} sub={t('activity.perDaySub')} id="act-hist">
        {hist.error ? <ErrorState error={hist.error} onRetry={() => void hist.refetch()} /> : hist.data ? <Histogram data={hist.data} /> : <LoadingState rows={2} />}
      </Card>
      <section aria-label={t('activity.stream')} className="card p-[var(--pad-card)]">
        {stream.error ? (
          <ErrorState error={stream.error} onRetry={() => void stream.refetch()} />
        ) : stream.isLoading ? (
          <LoadingState />
        ) : !items.length ? (
          <EmptyState
            icon={Activity}
            title={hasFilter(s) ? t('activity.noMatch') : t('activity.empty')}
            action={
              hasFilter(s) && (
                <button type="button" className="btn" onClick={() => void nav({ to: '/activity', search: {} })}>
                  {t('activity.reset')}
                </button>
              )
            }
          >
            {!canAudit && t('activity.onlyEvents')}
          </EmptyState>
        ) : (
          <>
            {!canAudit && <p className="mb-2 text-meta text-muted">{t('activity.onlyEvents')}</p>}
            <Timeline label={t('activity.stream')} items={items.map((it) => ({ id: it.id, at: it.at, title: <Entry it={it} onFilter={set} />, meta: <Meta it={it} onFilter={set} /> }))} />
            {stream.hasNextPage && (
              <button type="button" className="btn mt-3" disabled={stream.isFetchingNextPage} onClick={() => void stream.fetchNextPage()}>
                {stream.isFetchingNextPage ? t('state.loading') : t('activity.older')}
              </button>
            )}
          </>
        )}
      </section>
    </div>
  )
}

function ChainState({ st }: { st: Schemas['AuditStatus'] }) {
  const t = useT()
  if (st.broken_at)
    return (
      <p role="alert" className="flex items-start gap-2 rounded-lg bg-bad-soft p-3 text-body text-bad">
        <ShieldX size={16} className="mt-0.5 shrink-0" aria-hidden />
        <span>
          <strong>{t('activity.integrity')}</strong> {t('activity.brokenLong', { id: st.broken_at })}
        </span>
      </p>
    )
  return (
    <p role="status" className="flex items-start gap-2 rounded-lg bg-ok-soft p-3 text-body text-ok">
      <ShieldCheck size={16} className="mt-0.5 shrink-0" aria-hidden />
      <span>
        {t('activity.intact')}
        {st.verified_at && ` ${t('activity.lastFull', { at: dateTime(st.verified_at) })}`}
        {st.keyed_from > 0 && ` ${t('activity.keyed', { id: st.keyed_from })}`}
      </span>
    </p>
  )
}

function Filters({ s, set, actions }: { s: ActivitySearch; set: (p: Partial<ActivitySearch>) => void; actions: string[] }) {
  const t = useT()
  // text inputs apply after a short pause, so typing does not refetch per key
  const [draft, setDraft] = useState({ q: s.q ?? '', actor: s.actor ?? '', target: s.target ?? '' })
  // a change of the URL (a click in the timeline, reset) replaces the draft
  const urlKey = `${s.q}|${s.actor}|${s.target}`
  const [seen, setSeen] = useState(urlKey)
  if (seen !== urlKey) {
    setSeen(urlKey)
    setDraft({ q: s.q ?? '', actor: s.actor ?? '', target: s.target ?? '' })
  }
  useEffect(() => {
    const id = setTimeout(() => {
      if (draft.q !== (s.q ?? '') || draft.actor !== (s.actor ?? '') || draft.target !== (s.target ?? '')) set({ q: draft.q || undefined, actor: draft.actor || undefined, target: draft.target || undefined })
    }, 350)
    return () => clearTimeout(id)
  })
  return (
    <section aria-label={t('activity.filters')} className="card flex flex-col gap-3 p-[var(--pad-card)]">
      <div role="group" aria-label={t('activity.category')} className="flex flex-wrap gap-1.5">
        <button type="button" aria-pressed={!s.cat} className={cx('btn', !s.cat && 'btn-primary')} onClick={() => set({ cat: undefined })}>
          {t('activity.cat.all')}
        </button>
        {categories.map((c) => (
          <button key={c} type="button" aria-pressed={s.cat === c} className={cx('btn', s.cat === c && 'btn-primary')} onClick={() => set({ cat: s.cat === c ? undefined : c })}>
            {t(`activity.cat.${c}` as MessageKey)}
          </button>
        ))}
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <div className="xl:col-span-2">
          <Field label={t('activity.search')}>{({ id }) => <input id={id} type="search" className="field" value={draft.q} placeholder={t('activity.searchHint')} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />}</Field>
        </div>
        <Field label={t('activity.actor')}>{({ id }) => <input id={id} className="field" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} />}</Field>
        <Field label={t('activity.action')}>
          {({ id }) => (
            <select id={id} className="field" value={s.action ?? ''} onChange={(e) => set({ action: e.target.value || undefined })}>
              <option value="">{t('activity.allActions')}</option>
              {actions.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('activity.target')}>{({ id }) => <input id={id} className="field font-mono" value={draft.target} onChange={(e) => setDraft({ ...draft, target: e.target.value })} />}</Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label={t('activity.from')}>{({ id }) => <input id={id} type="date" className="field" value={s.from ?? ''} max={s.to} onChange={(e) => set({ from: e.target.value || undefined })} />}</Field>
          <Field label={t('activity.to')}>{({ id }) => <input id={id} type="date" className="field" value={s.to ?? ''} min={s.from} onChange={(e) => set({ to: e.target.value || undefined })} />}</Field>
        </div>
      </div>
      {hasFilter(s) && (
        <button type="button" className="btn btn-ghost self-start" onClick={() => set({ q: undefined, cat: undefined, actor: undefined, action: undefined, target: undefined, from: undefined, to: undefined })}>
          <X size={14} aria-hidden /> {t('activity.reset')}
        </button>
      )}
    </section>
  )
}

type Item = Schemas['ActivityItem']

function Entry({ it, onFilter }: { it: Item; onFilter: (p: Partial<ActivitySearch>) => void }) {
  const t = useT()
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <button type="button" className="font-medium hover:text-accent hover:underline" onClick={() => onFilter({ action: it.kind === 'audit' ? it.action : undefined, cat: it.kind === 'audit' ? undefined : 'events' })}>
          {it.label}
        </button>
        {it.label !== it.action && <span className="font-mono text-micro text-muted">{it.action}</span>}
        <Badge>{t(`activity.cat.${it.category}` as MessageKey)}</Badge>
      </div>
      {it.detail && (
        <details className="text-meta text-muted">
          <summary className="cursor-pointer truncate">{it.detail.slice(0, 140)}</summary>
          <pre className="mt-1 max-h-64 overflow-auto rounded bg-surface-2 p-2 font-mono text-meta whitespace-pre-wrap">{it.detail}</pre>
        </details>
      )}
    </div>
  )
}

function Meta({ it, onFilter }: { it: Item; onFilter: (p: Partial<ActivitySearch>) => void }) {
  return (
    <>
      <button type="button" className="hover:text-accent hover:underline" onClick={() => onFilter(it.kind === 'audit' ? { actor: it.actor } : { target: it.target })}>
        {it.actor}
      </button>
      {it.target && it.kind === 'audit' && (
        <>
          {' · '}
          <button type="button" className="font-mono hover:text-accent hover:underline" onClick={() => onFilter({ target: it.target })}>
            {it.target}
          </button>
        </>
      )}
    </>
  )
}

function Histogram({ data }: { data: Schemas['ActivityHistogram'] }) {
  const t = useT()
  const total = data.days.reduce((n, d) => n + Object.values(d.counts).reduce((a, b) => a + b, 0), 0)
  const build = useCallback(
    (c: Colors) => ({
      ...baseOption(c),
      legend: { bottom: 0, textStyle: { color: c.muted }, itemWidth: 10, itemHeight: 10 },
      grid: { left: 8, right: 12, top: 12, bottom: 28, containLabel: true },
      xAxis: { type: 'category', data: data.days.map((d) => dateShort(d.day)), ...axisX(c) },
      yAxis: { type: 'value', minInterval: 1, ...axisY(c) },
      series: data.categories.map((cat) => ({ name: t(`activity.cat.${cat}` as MessageKey), type: 'bar', stack: 'all', barMaxWidth: 18, itemStyle: { color: catColor(c)[cat] }, data: data.days.map((d) => d.counts[cat] ?? 0) })),
    }),
    [data, t],
  )
  return (
    <ChartFrame
      caption={t('activity.perDay')}
      chart={<EChart build={build} height={200} label={t('activity.histLabel', { count: total })} />}
      table={{
        head: [t('activity.day'), ...data.categories.map((c) => t(`activity.cat.${c}` as MessageKey))],
        rows: [...data.days].reverse().map((d) => [dateShort(d.day), ...data.categories.map((c) => fmt(d.counts[c] ?? 0))]),
      }}
    />
  )
}
