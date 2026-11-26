// The home page "Lage": one sentence, the KPI row, what needs attention, the
// fleet grid, the compliance history and frameworks, distributions, backup
// and the live feed. Every number links to the list behind it.
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from '@tanstack/react-router'
import { ArrowRight, CheckCircle2, CircleAlert, Circle, DatabaseBackup, Monitor, ShieldAlert, TriangleAlert, WifiOff, X, type LucideIcon } from 'lucide-react'
import { useCallback, useState } from 'react'
import { api, unwrap, type Schemas } from '../../api/client'
import { useLiveActivity } from '../../api/live'
import { useCan, useMe } from '../../api/me'
import { actionLabel, risk } from '../inbox/risk'
import { axisX, axisY, baseOption, Bullet, ChartFrame, EChart, FleetGrid, StackBar, type Colors } from '../../components/charts'
import { KpiCard } from '../../components/kpi'
import { EmptyState, ErrorState } from '../../components/states'
import { Avatar, Badge, Card, Delta, PageHeader, Segmented, Skeleton } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { switchTenant } from '../../app/tenants'
import { ago, bytes, dateLong, dateShort, dateTime, fmt, fmt1, pct } from '../../i18n/format'
import { cx } from '../../lib/cx'

const TARGET = 95

const useStat = <K extends 'fleet' | 'attention'>(k: K) =>
  useQuery({
    queryKey: ['stats', k],
    queryFn: () => unwrap(api.GET(k === 'fleet' ? '/api/v1/stats/fleet' : '/api/v1/stats/attention')) as Promise<K extends 'fleet' ? Schemas['StatsFleet'] : Schemas['StatsAttention']>,
  })

export function Home() {
  const t = useT()
  const me = useMe()
  const [days, setDays] = useState<'30' | '90'>('30')
  const [now] = useState(() => new Date())
  const fleet = useStat('fleet')
  const attention = useStat('attention')
  const comp = useQuery({ queryKey: ['stats', 'compliance', days], queryFn: () => unwrap(api.GET('/api/v1/stats/compliance', { params: { query: { days: Number(days) } } })) })
  const approvals = useQuery({
    queryKey: ['approvals', 'pending'],
    queryFn: () => unwrap(api.GET('/api/v1/approvals', { params: { query: { status: 'pending', limit: 7 } } })).then((p) => p.items ?? []),
  })
  const cmdDays = useQuery({
    queryKey: ['stats', 'commands', 14],
    queryFn: () => unwrap(api.GET('/api/v1/stats/commands', { params: { query: { days: 14 } } })).then((p) => p.items),
  })
  const canAudit = useCan('audit')
  const err = fleet.error ?? attention.error ?? comp.error
  if (err) return <ErrorState error={err} onRetry={() => void Promise.all([fleet.refetch(), attention.refetch(), comp.refetch()])} />
  if (!fleet.data || !attention.data || !comp.data) return <HomeSkeleton />
  const f = fleet.data
  const a = attention.data
  const c = comp.data
  const hist = c.history
  const week = hist.length > 7 ? hist[hist.length - 8].score : undefined
  const waiting = a.approvals_pending
  const hour = now.getHours()
  const name = me.login.replace(/^local:/, '').split(/[@.]/)[0]
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader
        title={`${t(hour < 11 ? 'home.morning' : hour < 18 ? 'home.afternoon' : 'home.evening')}, ${name}`}
        sub={
          <>
            {dateLong(now)}. {t('home.scoreLine', { score: pct(c.score) })}
            {week !== undefined && (
              <>
                {' '}
                <Delta value={c.score - week} label={t('home.in7')} />
              </>
            )}
            . {waiting > 0 ? <strong className="text-fg">{t('home.waiting', { count: waiting })}</strong> : t('home.nothingWaiting')}
          </>
        }
        actions={
          <Link to="/reports" className="btn">
            {t('home.report')}
          </Link>
        }
      />
      <Onboarding />
      {f.total === 0 ? (
        <div className="card">
          <EmptyState icon={Monitor} title={t('home.noDevices')} action={<a className="btn btn-primary" href="/devices">{t('home.enroll')}</a>}>
            {t('home.noDevicesBody')}
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-[var(--gap)] md:grid-cols-3 xl:grid-cols-6">
            <KpiCard to="/compliance" label={t('home.kpi.score')} value={pct(c.score)} delta={week !== undefined ? <Delta value={c.score - week} label={t('home.d7')} /> : undefined} spark={hist.map((h) => h.score)} sparkLabel={t('home.kpi.scoreSpark')} tone="accent" />
            <KpiCard to="/devices" label={t('home.kpi.online')} value={fmt(f.online)} unit={t('home.kpi.ofTotal', { total: f.total })} delta={<span className="text-[12px] text-muted">{t('home.kpi.offline', { count: f.total - f.online })}</span>} spark={hist.map((h) => h.compliant + h.noncompliant + h.in_grace)} tone="muted" />
            <KpiCard to="/devices" search={{ q: 'status:non-compliant' }} label={t('home.kpi.noncompliant')} value={fmt(a.noncompliant)} delta={week !== undefined ? <Delta value={a.noncompliant - hist[hist.length - 8].noncompliant} unit="" goodUp={false} label={t('home.d7')} /> : undefined} spark={hist.map((h) => h.noncompliant)} tone="bad" />
            <KpiCard to="/devices" search={{ q: 'status:stale' }} label={t('home.kpi.stale')} value={fmt(a.stale)} delta={<span className="text-[12px] text-muted">{t('home.kpi.staleHint', { hours: me.stale_hours })}</span>} spark={hist.map((h) => h.stale)} tone="muted" />
            <KpiCard to="/inbox" search={{ group: 'approvals' }} label={t('home.kpi.approvals')} value={fmt(a.approvals_pending)} delta={<span className={cx('text-[12px]', a.exceptions_expiring_7d ? 'font-medium text-warn' : 'text-muted')}>{t('home.kpi.exceptions', { count: a.exceptions_expiring_7d })}</span>} />
            <KpiCard to="/inbox" search={{ group: 'commands' }} label={t('home.kpi.failed')} value={fmt(a.commands_failed_24h)} unit={t('home.kpi.h24')} delta={<span className="text-[12px] text-muted">{t('home.kpi.sent', { count: a.commands_sent_24h })}</span>} spark={cmdDays.data?.map((d) => d.failed)} sparkLabel={t('home.kpi.failedSpark')} tone="bad" />
          </div>

          <div className="grid gap-[var(--gap)] xl:grid-cols-12">
            <Card className="xl:col-span-7" title={t('home.attention')} sub={t('home.attentionSub')} id="h-att" bodyClass="!pt-2" action={<Link to="/inbox" className="btn btn-ghost text-accent">{t('home.toInbox')} <ArrowRight size={14} aria-hidden /></Link>}>
              <Attention approvals={approvals.data ?? []} a={a} />
            </Card>
            <Card className="xl:col-span-5" title={t('home.grid')} sub={t('home.gridSub', { count: f.total })} id="h-grid">
              <GridCard f={f} />
              <TopFailing items={c.top_failing} />
            </Card>
          </div>

          {me.super && me.multi_tenant && !me.tenant && <Tenants />}

          <div className="grid gap-[var(--gap)] xl:grid-cols-12">
            <Card className="xl:col-span-8" title={t('home.trend')} sub={t('home.trendSub', { days: Number(days), target: TARGET })} id="h-trend" action={<Segmented label={t('home.range')} value={days} onChange={setDays} options={[{ value: '30', label: t('home.d30') }, { value: '90', label: t('home.d90') }]} />}>
              {hist.length > 1 ? <TrendChart hist={hist} /> : <p className="text-muted">{t('home.trendEmpty')}</p>}
            </Card>
            <Card className="xl:col-span-4" title={t('home.frameworks')} sub={t('home.frameworksSub')} id="h-fw" action={<Link to="/compliance" className="btn btn-ghost text-accent">{t('home.details')} <ArrowRight size={14} aria-hidden /></Link>}>
              <Frameworks list={c.frameworks} />
            </Card>
          </div>

          <div className="grid items-start gap-[var(--gap)] md:grid-cols-2 xl:grid-cols-4">
            <Card title={t('home.agents')} sub={t('home.agentsSub')} id="h-agent">
              <Distribution items={f.agent_versions} label={t('home.agents')} filterKey="agent" />
            </Card>
            <Card title={t('home.os')} sub={t('home.osSub')} id="h-os">
              <Distribution items={f.os} label={t('home.os')} />
            </Card>
            <Card title={t('home.backup')} id="h-backup">
              <Backup b={a.last_backup} />
            </Card>
            {canAudit && (
              <Card title={t('home.live')} sub={t('home.liveSub')} id="h-live" bodyClass="!pt-2" action={<Link to="/activity" className="btn btn-ghost text-accent">{t('home.all')} <ArrowRight size={14} aria-hidden /></Link>}>
                <LiveFeed />
              </Card>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function HomeSkeleton() {
  const t = useT()
  return (
    <div className="grid gap-[var(--gap)]" role="status" aria-label={t('state.loading')}>
      <Skeleton className="h-14 w-1/2" />
      <div className="grid grid-cols-2 gap-[var(--gap)] md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-[118px]" />
        ))}
      </div>
      <Skeleton className="h-[320px]" />
    </div>
  )
}

type Item = { id: string; icon: LucideIcon; risk: 0 | 1 | 2; title: string; meta: string; at?: string; to: string; search?: Record<string, string>; approval?: boolean }

function Attention({ approvals, a }: { approvals: Schemas['Approval'][]; a: Schemas['StatsAttention'] }) {
  const t = useT()
  const items: Item[] = approvals.map((x) => ({
    id: `a${x.id}`,
    icon: ShieldAlert,
    risk: risk(x) >= 3 ? 2 : risk(x) === 2 ? 1 : 0,
    title: `${actionLabel(x, t)} · ${x.target}`,
    meta: `${t('home.approval')} · ${x.requested_by} · ${x.created_at ? ago(x.created_at) : ''}`,
    at: x.created_at,
    to: '/inbox',
    search: { item: `a${x.id}` },
    approval: true,
  }))
  const b = a.last_backup
  if (b && b.status !== 'ok' && b.status !== 'running')
    items.push({ id: 'backup', icon: DatabaseBackup, risk: 2, title: t('home.warnBackup'), meta: `${t('home.warning')} · ${b.error || dateTime(b.started_at)}`, to: '/settings', search: { s: 'backup' } })
  if (a.noncompliant) items.push({ id: 'nc', icon: CircleAlert, risk: 1, title: t('home.warnNoncompliant', { count: a.noncompliant }), meta: t('home.warning'), to: '/devices', search: { q: 'status:non-compliant' } })
  if (a.commands_failed_24h) items.push({ id: 'cmd', icon: TriangleAlert, risk: 1, title: t('home.warnFailed', { count: a.commands_failed_24h }), meta: `${t('home.warning')} · ${t('home.kpi.h24')}`, to: '/inbox', search: { group: 'commands' } })
  if (a.exceptions_expiring_7d) items.push({ id: 'exc', icon: CircleAlert, risk: 1, title: t('home.kpi.exceptions', { count: a.exceptions_expiring_7d }), meta: t('home.warning'), to: '/inbox', search: { item: 'w-exc' } })
  if (a.stale) items.push({ id: 'stale', icon: WifiOff, risk: 0, title: t('home.warnStale', { count: a.stale }), meta: t('home.warning'), to: '/devices', search: { q: 'status:stale' } })
  items.sort((x, y) => y.risk - x.risk || (y.at ?? '').localeCompare(x.at ?? ''))
  if (!items.length)
    return (
      <div className="flex items-center gap-3 rounded-lg bg-ok-soft p-4 text-ok">
        <CheckCircle2 size={20} aria-hidden /> {t('home.allDone')}
      </div>
    )
  return (
    <ul className="divide-y divide-line">
      {items.slice(0, 7).map((it) => (
        <li key={it.id} className="flex items-center gap-3 py-2.5">
          <span className={cx('grid size-8 shrink-0 place-items-center rounded-lg', it.risk === 2 ? 'bg-bad-soft text-bad' : it.risk === 1 ? 'bg-warn-soft text-warn' : 'bg-surface-2 text-muted')}>
            <it.icon size={16} aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate font-medium">{it.title}</div>
            <div className="truncate text-[12.5px] text-muted">{it.meta}</div>
          </div>
          <Link to={it.to} search={it.search} className={cx('btn shrink-0', it.approval && 'btn-primary')}>
            {it.approval ? t('home.review') : t('home.show')}
          </Link>
        </li>
      ))}
    </ul>
  )
}

function GridCard({ f }: { f: Schemas['StatsFleet'] }) {
  const t = useT()
  const nav = useNavigate()
  return (
    <>
      <FleetGrid cells={f.cells} cell={f.cells.length > 600 ? 9 : f.cells.length > 150 ? 13 : 18} onPick={(c) => void nav({ to: '/devices', search: { sel: c.id } })} />
      {f.truncated && <p className="mt-2 text-[12px] text-muted">{t('home.gridTruncated', { count: f.cells.length })}</p>}
    </>
  )
}

function TopFailing({ items }: { items: Schemas['StatsCompliance']['top_failing'] }) {
  const t = useT()
  if (!items.length) return null
  const max = items[0].fail || 1
  return (
    <div className="mt-5 border-t border-line pt-4">
      <h3 className="mb-2 text-[12.5px] font-semibold text-muted">{t('home.topFailing')}</h3>
      <ul className="flex flex-col gap-1.5">
        {items.slice(0, 5).map((c) => (
          <li key={c.id}>
            <Link to="/devices" search={{ q: `check:${c.id}` }} className="grid grid-cols-[1fr_90px_36px] items-center gap-3 rounded text-[13px] hover:text-accent">
              <span className="truncate">{c.title || c.id}</span>
              <span className="h-1.5 rounded-full bg-surface-2" aria-hidden>
                <span className="block h-1.5 rounded-full bg-bad" style={{ width: `${(c.fail / max) * 100}%` }} />
              </span>
              <span className="num text-right font-medium">{fmt(c.fail)}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}

function TrendChart({ hist }: { hist: Schemas['StatsCompliance']['history'] }) {
  const t = useT()
  const build = useCallback(
    (c: Colors) => ({
      ...baseOption(c),
      xAxis: { type: 'category', data: hist.map((h) => dateShort(h.day)), boundaryGap: false, ...axisX(c) },
      yAxis: { type: 'value', min: (v: { min: number }) => Math.max(0, Math.floor(v.min - 3)), max: 100, ...axisY(c, { axisLabel: { color: c.muted, formatter: '{value} %' } }) },
      tooltip: { ...(baseOption(c).tooltip as object), valueFormatter: (v: number) => `${fmt1(v)} %` },
      series: [
        {
          name: t('home.score'),
          type: 'line',
          data: hist.map((h) => h.score),
          showSymbol: false,
          smooth: 0.3,
          lineStyle: { color: c.accent, width: 2 },
          itemStyle: { color: c.accent },
          areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: c.accent + '33' }, { offset: 1, color: c.accent + '00' }] } },
          markLine: { silent: true, symbol: 'none', lineStyle: { color: c.fg2, type: 'dashed', width: 1 }, label: { formatter: t('home.target', { target: TARGET }), color: c.fg2, position: 'insideEndTop' }, data: [{ yAxis: TARGET }] },
        },
      ],
    }),
    [hist, t],
  )
  return (
    <ChartFrame
      caption={t('home.trend')}
      chart={<EChart build={build} height={240} label={t('home.trendLabel', { score: pct(hist[hist.length - 1].score) })} />}
      table={{ head: [t('home.day'), t('home.score'), t('home.compliantCol'), t('home.noncompliantCol')], rows: [...hist].reverse().map((h) => [dateShort(h.day), pct(h.score), h.compliant, h.noncompliant]) }}
    />
  )
}

function Frameworks({ list }: { list: Schemas['StatsCompliance']['frameworks'] }) {
  const t = useT()
  const shown = list.filter((f) => f.pass + f.fail > 0)
  if (!shown.length) return <p className="text-muted">{t('home.noChecks')}</p>
  return (
    <ul className="flex flex-col gap-4">
      {shown.map((f) => (
        <li key={f.id}>
          <Link to="/compliance" search={{ fw: f.id }} className="block rounded-md hover:bg-surface-2">
            <div className="mb-1.5 flex items-baseline justify-between gap-2">
              <span className="font-medium">{f.name}</span>
              <span className="num font-semibold">{pct(f.rate)}</span>
            </div>
            <Bullet value={f.rate} target={TARGET} label={t('home.frameworkBullet', { name: f.name, value: pct(f.rate), target: TARGET })} />
          </Link>
        </li>
      ))}
    </ul>
  )
}

const series = ['var(--c-s1)', 'var(--c-s2)', 'var(--c-s3)', 'var(--c-s4)', 'var(--c-s5)']

function Distribution({ items, label, filterKey }: { items: Schemas['FacetCount'][]; label: string; filterKey?: string }) {
  const t = useT()
  const top = items.slice(0, 4)
  const rest = items.slice(4).reduce((s, x) => s + x.count, 0)
  const parts = [...top.map((x, i) => ({ label: x.value || t('home.unknown'), value: x.count, color: series[i] })), ...(rest ? [{ label: t('home.others'), value: rest, color: series[4] }] : [])]
  return (
    <>
      <StackBar parts={parts} label={label} />
      {filterKey && top[0] && (
        <Link to="/devices" search={{ q: `${filterKey}:${top[0].value}` }} className="mt-2 inline-block text-[12.5px] text-accent hover:underline">
          {top[0].value} <ArrowRight size={12} className="inline" aria-hidden />
        </Link>
      )}
    </>
  )
}

function Backup({ b }: { b: Schemas['StatsAttention']['last_backup'] }) {
  const t = useT()
  if (!b) return <p className="text-muted">{t('home.backupNone')}</p>
  const ok = b.status === 'ok'
  return (
    <div className="flex items-center gap-3">
      <span className={cx('grid size-9 shrink-0 place-items-center rounded-lg', ok ? 'bg-ok-soft text-ok' : 'bg-bad-soft text-bad')}>
        <DatabaseBackup size={18} aria-hidden />
      </span>
      <div className="min-w-0">
        <div className="font-semibold">{ok ? t('home.backupOk') : t('home.backupFailed')}</div>
        <div className="num truncate text-[12.5px] text-muted">
          {dateTime(b.started_at)}
          {b.size > 0 && ` · ${bytes(b.size)}`}
          {b.error && ` · ${b.error}`}
        </div>
      </div>
    </div>
  )
}

function LiveFeed() {
  const t = useT()
  const ev = useLiveActivity()
  if (!ev.length) return <p className="text-[12.5px] text-muted">{t('home.liveEmpty')}</p>
  return (
    <ul className="flex flex-col">
      {ev.slice(0, 6).map((e, i) => (
        <li key={e.id} className={cx('flex gap-2.5 py-1.5', i === 0 && 'fade-in')}>
          <Avatar name={e.actor} size={22} />
          <div className="min-w-0 flex-1 text-[12.5px] leading-snug">
            <div className="line-clamp-2">
              <span className="font-medium">{e.actor}</span> <Badge>{e.action}</Badge>
            </div>
            <div className="truncate text-muted">
              {e.target && <span className="font-mono">{e.target} · </span>}
              {ago(e.at)}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}

// The first steps of a new installation (admins, global view) until all are
// done; hiding them is remembered in this browser.
const ONBOARDING_KEY = 'limdm.home.onboarding'
const onboardingLinks: Record<string, { to: string; search?: Record<string, string> }> = {
  branding: { to: '/settings' },
  sso: { to: '/settings' },
  token: { to: '/devices' },
  blueprint: { to: '/config' },
  device: { to: '/devices' },
}

function Onboarding() {
  const t = useT()
  const [hidden, setHidden] = useState(() => {
    try {
      return localStorage.getItem(ONBOARDING_KEY) === 'hidden'
    } catch {
      return false
    }
  })
  const steps = useQuery({ queryKey: ['stats', 'onboarding'], enabled: !hidden, queryFn: () => unwrap(api.GET('/api/v1/onboarding')).then((p) => p.items) })
  if (hidden || !steps.data?.length) return null
  const hide = () => {
    try {
      localStorage.setItem(ONBOARDING_KEY, 'hidden')
    } catch {
      // private mode: hidden for this page only
    }
    setHidden(true)
  }
  return (
    <Card
      title={t('home.onboarding')}
      sub={t('home.onboardingSub')}
      id="h-onb"
      action={
        <button type="button" className="btn btn-ghost" onClick={hide}>
          <X size={14} aria-hidden /> {t('home.onboardingHide')}
        </button>
      }
    >
      <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        {steps.data.map((s) => (
          <li key={s.id}>
            <Link to={onboardingLinks[s.id].to} className={cx('flex h-full items-start gap-2 rounded-lg border border-line p-3 hover:border-line-strong', s.done && 'opacity-70')}>
              {s.done ? <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-ok" aria-hidden /> : <Circle size={18} className="mt-0.5 shrink-0 text-muted" aria-hidden />}
              <span>
                <span className="block font-medium">
                  {t(`home.step.${s.id}` as MessageKey)}
                  {s.done && <span className="sr-only"> ({t('home.stepDone')})</span>}
                </span>
                <span className="block text-[12.5px] text-muted">{t(`home.stepHint.${s.id}` as MessageKey)}</span>
              </span>
            </Link>
          </li>
        ))}
      </ol>
    </Card>
  )
}

// The tenants side by side (super admins in the all tenants view): score
// against the target, non compliant, silent, pending approvals. A click
// switches the view to the tenant.
function Tenants() {
  const t = useT()
  const q = useQuery({ queryKey: ['stats', 'tenants'], queryFn: () => unwrap(api.GET('/api/v1/stats/tenants')).then((p) => p.items) })
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <Skeleton className="h-[160px]" />
  return (
    <Card title={t('home.tenants')} sub={t('home.tenantsSub', { target: TARGET })} id="h-tenants">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]">
          <thead>
            <tr className="border-b border-line text-muted">
              <th scope="col" className="py-2 pr-4 font-medium">{t('home.tenant')}</th>
              <th scope="col" className="w-[30%] py-2 pr-4 font-medium">{t('home.score')}</th>
              <th scope="col" className="num py-2 pr-4 text-right font-medium">{t('home.kpi.noncompliant')}</th>
              <th scope="col" className="num py-2 pr-4 text-right font-medium">{t('home.kpi.stale')}</th>
              <th scope="col" className="num py-2 pr-4 text-right font-medium">{t('home.kpi.approvals')}</th>
              <th scope="col" className="num py-2 text-right font-medium">{t('home.devices')}</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((x) => (
              <tr key={x.id} className="border-b border-line last:border-0">
                <th scope="row" className="py-2 pr-4 font-medium">
                  <button type="button" className="text-left text-accent hover:underline" onClick={() => void switchTenant(x.id)}>
                    {x.name}
                  </button>
                </th>
                <td className="py-2 pr-4">
                  <div className="flex items-center gap-2">
                    <span className="num w-14 shrink-0">{pct(x.score)}</span>
                    <span className="min-w-[80px] flex-1">
                      <Bullet value={x.score} target={TARGET} label={t('home.frameworkBullet', { name: x.name, value: pct(x.score), target: TARGET })} />
                    </span>
                  </div>
                </td>
                <td className={cx('num py-2 pr-4 text-right', x.noncompliant > 0 && 'font-semibold text-bad')}>{fmt(x.noncompliant)}</td>
                <td className="num py-2 pr-4 text-right">{fmt(x.stale)}</td>
                <td className={cx('num py-2 pr-4 text-right', x.approvals_pending > 0 && 'font-semibold text-warn')}>{fmt(x.approvals_pending)}</td>
                <td className="num py-2 text-right">{fmt(x.devices)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
