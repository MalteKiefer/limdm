// The compliance overview: score and trend, framework cards, device states,
// the checks (most failing first) or the controls of a framework, the drill
// down into a check or control, and the heatmap of check areas.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { ArrowRight, Download, History, Search, ShieldCheck, ShieldOff } from 'lucide-react'
import { useCallback, useMemo } from 'react'
import { useMe, useCan } from '../../api/me'
import { Bullet, ChartFrame, EChart, Sparkline, baseOption, type Colors } from '../../components/charts'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { SideSheet, SplitView } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge, Card, Delta, PageHeader, Segmented, Skeleton } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, fmt, pct } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useCheck, useCompliance, useComplianceStats, useExceptions, useHeatmap } from './api'
import { ExportDialog } from './export'
import { activeFor, exceptionPath, filterChecks, frameworks, heatMatrix, passRate, refsOf, sortChecks, TARGET, type Check, type Control, type Framework } from './logic'
import { ResultBadge, SeverityBadge } from '../../components/badges'
import { SectionNav } from './parts'

type S = ReturnType<typeof useOverviewSearch>
const useOverviewSearch = () => useSearch({ strict: false }) as Record<string, string | undefined>

export function CompliancePage() {
  const t = useT()
  const s: S = useOverviewSearch()
  const navigate = useNavigate()
  const go = useCallback((patch: Record<string, string | undefined>) => void navigate({ to: '/compliance', search: { ...s, ...patch } as never, replace: true }), [navigate, s])
  const canExport = useCan('audit')
  const data = useCompliance()
  const stats = useComplianceStats(90)
  if (data.error) return <ErrorState error={data.error} onRetry={() => void data.refetch()} />
  const d = data.data
  return (
    <div className="flex flex-col">
      <PageHeader
        title={t('compliance.title')}
        sub={d ? t('compliance.sub', { devices: d.total, checks: d.checks.length }) : undefined}
        actions={
          <>
            <Link to="/compliance/history" className="btn">
              <History size={15} aria-hidden /> {t('compliance.tab.history')}
            </Link>
            {canExport && (
              <button type="button" className="btn btn-primary" onClick={() => go({ export: '1' })}>
                <Download size={15} aria-hidden /> {t('compliance.export')}
              </button>
            )}
          </>
        }
      />
      <SectionNav />
      {!d ? (
        <LoadingState rows={6} />
      ) : d.checks.length === 0 ? (
        <div className="card">
          <EmptyState icon={ShieldCheck} title={t('compliance.empty')} action={<Link to="/compliance/policies" className="btn">{t('compliance.toPolicies')}</Link>}>
            {t('compliance.emptyBody')}
          </EmptyState>
        </div>
      ) : (
        <div className="flex flex-col gap-[var(--gap)]">
          <ScoreRow stats={stats.data} fw={s.fw} onFw={(fw) => go({ fw: fw === s.fw ? undefined : fw, control: undefined })} />
          <StateRow d={d} />
          <Body d={d} s={s} go={go} />
        </div>
      )}
      {canExport && <ExportDialog open={!!s.export} onClose={() => go({ export: undefined })} />}
    </div>
  )
}

function ScoreRow({ stats, fw, onFw }: { stats?: ReturnType<typeof useComplianceStats>['data']; fw?: string; onFw: (fw: string) => void }) {
  const t = useT()
  if (!stats) return <Skeleton className="h-[132px]" />
  const hist = stats.history
  const prev = hist.length > 30 ? hist[hist.length - 31].score : undefined
  return (
    <div className="grid grid-cols-1 gap-[var(--gap)] sm:grid-cols-2 xl:grid-cols-4">
      <div className="card flex flex-col p-[var(--pad-card)]">
        <span className="text-meta font-medium text-muted" title={t('compliance.scoreHint')}>
          {t('compliance.score')}
        </span>
        <span className="num text-display leading-tight font-semibold tracking-tight">{pct(stats.score)}</span>
        {prev !== undefined && <Delta value={stats.score - prev} label={t('compliance.in30')} />}
        <p className="mt-1 text-meta text-muted">{t('compliance.scoreHint')}</p>
        {hist.length > 1 && (
          <div className="mt-2">
            <Sparkline data={hist.map((h) => h.score)} height={30} width={220} label={t('compliance.scoreSpark')} />
          </div>
        )}
      </div>
      {stats.frameworks.map((f) => (
        <button
          key={f.id}
          type="button"
          onClick={() => onFw(f.id)}
          aria-pressed={fw === f.id}
          aria-label={t('compliance.fwPick', { name: t(`compliance.fw.${f.id}` as MessageKey) })}
          className={cx('card flex flex-col p-[var(--pad-card)] text-left transition-colors', fw === f.id ? 'border-accent ring-1 ring-accent' : 'hover:border-line-strong')}
        >
          <span className="flex items-center justify-between text-meta font-medium text-muted">
            {t(`compliance.fw.${f.id}` as MessageKey)}
            {fw === f.id && <ShieldCheck size={14} className="text-accent" aria-hidden />}
          </span>
          <span className="num text-heading leading-tight font-semibold">{pct(f.rate)}</span>
          <span className="text-meta text-muted">
            {t('compliance.fwRate')}: {fmt(f.pass)} / {fmt(f.pass + f.fail)}
          </span>
          <div className="mt-3">
            <Bullet value={f.rate} target={TARGET} label={`${pct(f.rate)}, ${t('compliance.target', { target: TARGET })}`} />
          </div>
        </button>
      ))}
    </div>
  )
}

function StateRow({ d }: { d: NonNullable<ReturnType<typeof useCompliance>['data']> }) {
  const t = useT()
  const items = [
    { label: t('compliance.state.compliant'), n: d.compliant, q: 'status:compliant', dot: 'bg-ok' },
    { label: t('compliance.state.noncompliant'), n: d.noncompliant, q: 'status:non-compliant', dot: 'bg-bad' },
    { label: t('compliance.state.stale'), n: d.stale, q: 'status:stale', dot: 'bg-warn-mark', hint: t('compliance.state.staleHint', { hours: d.stale_hours }) },
    { label: t('compliance.state.pending'), n: d.pending, q: 'status:pending', dot: 'bg-off', hint: t('compliance.state.pendingHint') },
  ]
  return (
    <div className="grid grid-cols-2 gap-[var(--gap)] md:grid-cols-4">
      {items.map((i) => (
        <Link key={i.q} to="/devices" search={{ q: i.q } as never} className="card flex flex-col gap-0.5 p-3 hover:border-line-strong">
          <span className="flex items-center gap-1.5 text-meta font-medium text-muted">
            <span className={cx('size-2 rounded-full', i.dot)} aria-hidden />
            {i.label}
          </span>
          <span className="num text-heading font-semibold">{fmt(i.n)}</span>
          {i.hint && <span className="text-meta text-muted">{i.hint}</span>}
        </Link>
      ))}
    </div>
  )
}

function RateCell({ c }: { c: { pass: number; fail: number } }) {
  const r = passRate(c)
  if (r === null) return <span className="text-muted">·</span>
  return (
    <div className="flex items-center gap-2 pr-2">
      <span className="num w-12 text-right text-meta">{Math.round(r)} %</span>
      <div className="min-w-16 flex-1">
        <Bullet value={r} target={TARGET} label={`${Math.round(r)} %`} />
      </div>
    </div>
  )
}

function Body({ d, s, go }: { d: NonNullable<ReturnType<typeof useCompliance>['data']>; s: S; go: (p: Record<string, string | undefined>) => void }) {
  const t = useT()
  const fw = frameworks.includes(s.fw as Framework) ? (s.fw as Framework) : undefined
  const view = s.view === 'controls' ? 'controls' : 'checks'
  const checks = useMemo(() => sortChecks(filterChecks(d.checks, { q: s.q, state: s.state, level: s.level, fw }), s.sort), [d.checks, s.q, s.state, s.level, s.sort, fw])
  const controls = useMemo(() => d.controls.filter((c) => (!fw || c.framework === fw) && (s.state !== 'failing' || c.fail > 0)), [d.controls, fw, s.state])
  const columns = useMemo<GridColumn<Check>[]>(
    () => [
      {
        id: 'check',
        header: t('compliance.col.check'),
        meta: { sortKey: 'title' },
        cell: ({ row: { original: c } }) => (
          <span className="flex min-w-0 flex-col">
            <span className="truncate font-medium">{c.title}</span>
            <span className="truncate font-mono text-micro text-muted">{c.id}</span>
          </span>
        ),
      },
      { id: 'level', header: t('compliance.col.level'), meta: { sortKey: 'level' }, cell: ({ row: { original: c } }) => <span className="flex gap-1"><Badge>L{c.level}</Badge><SeverityBadge severity={c.severity} /></span> },
      {
        id: 'refs',
        header: t('compliance.col.refs'),
        cell: ({ row: { original: c } }) => <span className="font-mono text-micro text-muted">{(fw ? refsOf(c, fw) : [...refsOf(c, 'bsi'), ...refsOf(c, 'iso')]).slice(0, 3).join(', ')}</span>,
      },
      { id: 'rate', header: t('compliance.col.rate'), meta: { sortKey: 'rate', className: 'w-[170px]' }, cell: ({ row: { original: c } }) => <RateCell c={c} /> },
      {
        id: 'fail',
        header: t('compliance.col.fail'),
        meta: { sortKey: 'fail', className: 'text-right' },
        cell: ({ row: { original: c } }) => <span className={cx('num font-semibold', c.fail ? 'text-bad' : 'text-muted')}>{c.fail ? fmt(c.fail) : '·'}</span>,
      },
      { id: 'excepted', header: t('compliance.col.excepted'), meta: { className: 'text-right' }, cell: ({ row: { original: c } }) => <span className="num text-muted">{c.excepted || '·'}</span> },
      { id: 'na', header: t('compliance.col.na'), meta: { className: 'text-right' }, cell: ({ row: { original: c } }) => <span className="num text-muted">{c.na || '·'}</span> },
    ],
    [t, fw],
  )
  const ctlColumns = useMemo<GridColumn<Control>[]>(
    () => [
      { id: 'framework', header: t('compliance.col.framework'), cell: ({ row: { original: c } }) => t(`compliance.fw.${c.framework}` as MessageKey) },
      { id: 'control', header: t('compliance.col.control'), cell: ({ row: { original: c } }) => <span className="font-mono">{c.control}</span> },
      { id: 'checks', header: t('compliance.col.checks'), cell: ({ row: { original: c } }) => <span className="truncate font-mono text-micro text-muted">{c.checks.join(', ')}</span> },
      { id: 'rate', header: t('compliance.col.rate'), meta: { className: 'w-[170px]' }, cell: ({ row: { original: c } }) => <RateCell c={c} /> },
      { id: 'fail', header: t('compliance.col.fail'), meta: { className: 'text-right' }, cell: ({ row: { original: c } }) => <span className={cx('num font-semibold', c.fail ? 'text-bad' : 'text-muted')}>{c.fail ? fmt(c.fail) : '·'}</span> },
    ],
    [t],
  )
  const idx = checks.findIndex((c) => c.id === s.sel)
  const step = (n: number) => checks.length && go({ sel: checks[(idx + n + checks.length) % checks.length].id })
  const ctl = s.control ? d.controls.find((c) => `${c.framework}|${c.control}` === s.control) : undefined
  const filtered = !!(s.q || s.state || s.level)
  const detail = s.sel ? (
    <CheckSheet id={s.sel} total={d.total} onClose={() => go({ sel: undefined })} onPrev={idx >= 0 ? () => step(-1) : undefined} onNext={idx >= 0 ? () => step(1) : undefined} />
  ) : ctl ? (
    <ControlSheet c={ctl} checks={d.checks} onClose={() => go({ control: undefined })} onPick={(id) => go({ sel: id })} />
  ) : undefined
  return (
    <>
      <div className="flex flex-wrap items-end gap-2">
        <Segmented
          label={t('compliance.view')}
          value={view}
          onChange={(v) => go({ view: v === 'checks' ? undefined : v, sel: undefined, control: undefined })}
          options={[
            { value: 'checks', label: t('compliance.view.checks') },
            { value: 'controls', label: t('compliance.view.controls') },
          ]}
        />
        {view === 'checks' && (
          <label className="relative min-w-[200px] flex-1">
            <span className="sr-only">{t('compliance.search')}</span>
            <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" aria-hidden />
            <input type="search" className="field pl-8" placeholder={t('compliance.search')} value={s.q ?? ''} onChange={(e) => go({ q: e.target.value || undefined })} />
          </label>
        )}
        <label className="flex flex-col gap-0.5 text-meta text-muted">
          {t('compliance.filter.state')}
          <select className="field" value={s.state ?? ''} onChange={(e) => go({ state: e.target.value || undefined })}>
            <option value="">{t('compliance.filter.all')}</option>
            <option value="failing">{t('compliance.filter.failing')}</option>
            {view === 'checks' && <option value="passing">{t('compliance.filter.passing')}</option>}
          </select>
        </label>
        {view === 'checks' && (
          <label className="flex flex-col gap-0.5 text-meta text-muted">
            {t('compliance.filter.level')}
            <select className="field" value={s.level ?? ''} onChange={(e) => go({ level: e.target.value || undefined })}>
              <option value="">{t('compliance.filter.allLevels')}</option>
              <option value="1">{t('compliance.level', { n: 1 })}</option>
              <option value="2">{t('compliance.level', { n: 2 })}</option>
            </select>
          </label>
        )}
        {filtered && (
          <button type="button" className="btn btn-ghost" onClick={() => go({ q: undefined, state: undefined, level: undefined })}>
            {t('compliance.reset')}
          </button>
        )}
        <span className="ml-auto self-center text-meta text-muted" aria-live="polite">
          {view === 'checks' ? t('compliance.shown', { shown: checks.length, all: d.checks.length }) : t('compliance.shown', { shown: controls.length, all: d.controls.length })}
        </span>
      </div>
      <SplitView
        list={
          view === 'checks' ? (
            <DataGrid
              label={t('compliance.view.checks')}
              data={checks}
              columns={columns}
              getRowId={(c) => c.id}
              sort={s.sort ?? '-fail'}
              onSortChange={(v) => go({ sort: v === '-fail' ? undefined : v })}
              activeId={s.sel}
              onRowClick={(c) => go({ sel: c.id, control: undefined })}
              maxHeight="560px"
              empty={t('compliance.noMatch')}
              card={(c) => (
                <span className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate font-medium">{c.title}</span>
                    <span className="truncate font-mono text-micro text-muted">{c.id}</span>
                  </span>
                  <span className={cx('num font-semibold', c.fail ? 'text-bad' : 'text-muted')}>{c.fail || '·'}</span>
                </span>
              )}
            />
          ) : (
            <DataGrid
              label={t('compliance.view.controls')}
              data={controls}
              columns={ctlColumns}
              getRowId={(c) => `${c.framework}|${c.control}`}
              activeId={s.control}
              onRowClick={(c) => go({ control: `${c.framework}|${c.control}`, sel: undefined })}
              maxHeight="560px"
              card={(c) => (
                <span className="flex items-center justify-between gap-2">
                  <span className="font-mono">{c.control}</span>
                  <span className={cx('num font-semibold', c.fail ? 'text-bad' : 'text-muted')}>{c.fail || '·'}</span>
                </span>
              )}
            />
          )
        }
        detail={detail}
      />
      {!detail && <Heatmap group={s.group === 'tenant' ? 'tenant' : 'blueprint'} onGroup={(g) => go({ group: g === 'blueprint' ? undefined : g })} />}
    </>
  )
}

function CheckSheet({ id, total, onClose, onPrev, onNext }: { id: string; total: number; onClose: () => void; onPrev?: () => void; onNext?: () => void }) {
  const t = useT()
  const path = exceptionPath(useMe())
  const q = useCheck(id)
  const exc = useExceptions()
  const c = q.data
  const fixKey = `compliance.fix.${id}` as MessageKey
  const fix = t(fixKey)
  const byBp = useMemo(() => {
    const m = new Map<string, number>()
    for (const dv of c?.devices ?? []) if (dv.status === 'fail') m.set(dv.blueprint, (m.get(dv.blueprint) ?? 0) + 1)
    return [...m].sort((a, b) => b[1] - a[1])
  }, [c])
  const active = activeFor(exc.data ?? [], id)
  return (
    <SideSheet
      title={c?.title ?? id}
      sub={<span className="font-mono">{id}</span>}
      onClose={onClose}
      onPrev={onPrev}
      onNext={onNext}
      actions={
        <>
          <Link to="/devices" search={{ q: `check:${id}` } as never} className="btn btn-primary">
            {t('compliance.check.allInList')} <ArrowRight size={14} aria-hidden />
          </Link>
          {path && (
            <Link to="/compliance/exceptions" search={{ new: id } as never} className="btn">
              <ShieldOff size={14} aria-hidden /> {t(path === 'direct' ? 'compliance.check.addException' : 'compliance.exc.request')}
            </Link>
          )}
        </>
      }
    >
      {q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !c ? (
        <LoadingState rows={5} />
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge>{t('compliance.level', { n: c.level })}</Badge>
            <SeverityBadge severity={c.severity} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={cx('num text-display font-semibold', c.fail ? 'text-bad' : 'text-ok')}>{fmt(c.fail)}</span>
            <span className="text-muted">{t('compliance.check.ofDevices', { total })}</span>
          </div>
          <RateCell c={c} />
          <div className="rounded-lg bg-surface-2 p-3 text-body">
            <span className="font-semibold">{t('compliance.check.fix')}: </span>
            {fix !== fixKey ? fix : id.startsWith('custom.') ? t('compliance.check.fixCustom') : t('compliance.check.fixUnknown')}
          </div>
          <section>
            <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('compliance.check.refs')}</h3>
            {frameworks.every((f) => !refsOf(c, f).length) ? (
              <p className="text-muted">{t('compliance.check.noRefs')}</p>
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-body">
                {frameworks
                  .filter((f) => refsOf(c, f).length)
                  .map((f) => (
                    <div key={f} className="contents">
                      <dt className="text-muted">{t(`compliance.fw.${f}` as MessageKey)}</dt>
                      <dd className="font-mono text-meta">{refsOf(c, f).join(', ')}</dd>
                    </div>
                  ))}
              </dl>
            )}
            {c.refs.cis_benchmark && <p className="mt-1 text-meta text-muted">{t('compliance.check.benchmark', { name: c.refs.cis_benchmark })}</p>}
          </section>
          {active.length > 0 && (
            <section>
              <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('compliance.check.exceptions')}</h3>
              <ul className="flex flex-col gap-1 text-body">
                {active.map((e) => (
                  <li key={e.id}>
                    <Link to="/compliance/exceptions" className="hover:text-accent">
                      {t(`compliance.exc.mode.${e.mode}` as MessageKey)} · {e.tag || t('compliance.exc.allDevices')} · {e.reason}
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {byBp.length > 0 && (
            <section>
              <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('compliance.check.byBlueprint')}</h3>
              <ul className="flex flex-col gap-1.5">
                {byBp.map(([name, n]) => (
                  <li key={name} className="flex items-center gap-2 text-body">
                    <span className="w-36 truncate">{name}</span>
                    <span className="h-2 flex-1 rounded-full bg-surface-2" aria-hidden>
                      <span className="block h-2 rounded-full bg-bad" style={{ width: `${(n / c.fail) * 100}%` }} />
                    </span>
                    <span className="num w-8 text-right">{n}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
          <section>
            <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('compliance.check.devices')}</h3>
            {c.truncated && <p className="mb-1 text-meta text-muted">{t('compliance.check.truncated', { count: c.devices.length })}</p>}
            <ul className="max-h-[320px] divide-y divide-line overflow-y-auto rounded-lg border border-line">
              {c.devices.map((dv) => (
                <li key={dv.id}>
                  <Link to="/devices/$id" params={{ id: dv.id } as never} className="flex flex-col gap-0.5 px-3 py-1.5 hover:bg-surface-2">
                    <span className="flex items-center gap-2">
                      <span className="flex-1 truncate font-mono text-meta">{dv.hostname || dv.id}</span>
                      <ResultBadge status={dv.status} />
                    </span>
                    <span className="flex gap-2 text-meta text-muted">
                      <span className="truncate">{dv.blueprint}</span>
                      {dv.last_seen && <span>{ago(dv.last_seen)}</span>}
                      {dv.remediated && <span>{t('compliance.check.remediated')}</span>}
                    </span>
                    {dv.detail && dv.status !== 'pass' && <span className="truncate text-meta text-muted">{dv.detail}</span>}
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        </div>
      )}
    </SideSheet>
  )
}

function ControlSheet({ c, checks, onClose, onPick }: { c: Control; checks: Check[]; onClose: () => void; onPick: (id: string) => void }) {
  const t = useT()
  const list = checks.filter((x) => c.checks.includes(x.id))
  return (
    <SideSheet title={t('compliance.control.title', { framework: t(`compliance.fw.${c.framework}` as MessageKey), control: c.control })} sub={t('compliance.control.summary', { pass: c.pass, fail: c.fail })} onClose={onClose}>
      <div className="flex flex-col gap-4">
        <RateCell c={c} />
        <section>
          <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('compliance.control.checks')}</h3>
          <ul className="divide-y divide-line rounded-lg border border-line">
            {list.map((x) => (
              <li key={x.id}>
                <button type="button" onClick={() => onPick(x.id)} className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-surface-2">
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate font-medium">{x.title}</span>
                    <span className="truncate font-mono text-micro text-muted">{x.id}</span>
                  </span>
                  <span className={cx('num font-semibold', x.fail ? 'text-bad' : 'text-muted')}>{x.fail ? t('compliance.failDevices', { count: x.fail }) : t('compliance.rateOf', { rate: pct(passRate(x) ?? 100) })}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </SideSheet>
  )
}

function Heatmap({ group, onGroup }: { group: 'blueprint' | 'tenant'; onGroup: (g: 'blueprint' | 'tenant') => void }) {
  const t = useT()
  const me = useMe()
  const multi = me.multi_tenant && me.super && !me.tenant
  const q = useHeatmap(group)
  const m = useMemo(() => heatMatrix(q.data?.cells ?? []), [q.data])
  const groupLabel = t(group === 'tenant' ? 'compliance.heat.tenant' : 'compliance.heat.blueprint')
  const build = useCallback(
    (c: Colors) => {
      const data: [number, number, number | '-'][] = []
      m.areas.forEach((_, y) => m.columns.forEach((_, x) => data.push([x, y, m.rate[y][x] === null ? '-' : Math.round(m.rate[y][x]! * 10) / 10])))
      const b = baseOption(c)
      return {
        ...b,
        tooltip: {
          ...(b.tooltip as object),
          trigger: 'item',
          formatter: (p: { value: [number, number, number] }) => {
            const cell = m.cell(m.areas[p.value[1]], m.columns[p.value[0]])
            return t('compliance.heat.tip', { area: m.areas[p.value[1]], column: m.columns[p.value[0]], rate: pct(p.value[2]), fail: cell?.fail ?? 0 })
          },
        },
        grid: { left: 8, right: 8, top: 4, bottom: 4, containLabel: true },
        xAxis: { type: 'category', data: m.columns, position: 'top', axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.fg2, interval: 0, fontSize: 11 } },
        yAxis: { type: 'category', data: m.areas, inverse: true, axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.fg2 } },
        visualMap: { show: false, min: 50, max: 100, inRange: { color: [c.surface, c.accent] } },
        series: [{ type: 'heatmap', data, label: { show: true, color: c.fg, fontSize: 11, textBorderColor: c.surface, textBorderWidth: 2, formatter: (p: { value: number[] }) => `${Math.round(p.value[2])}` }, itemStyle: { borderColor: c.surface, borderWidth: 3, borderRadius: 4 } }],
      }
    },
    [m, t],
  )
  return (
    <Card
      title={t(group === 'tenant' ? 'compliance.heat.titleTenant' : 'compliance.heat.title')}
      sub={t('compliance.heat.sub')}
      id="compliance-heat"
      action={
        multi ? (
          <Segmented
            label={t('compliance.heat.group')}
            value={group}
            onChange={onGroup}
            options={[
              { value: 'blueprint', label: t('compliance.heat.blueprint') },
              { value: 'tenant', label: t('compliance.heat.tenant') },
            ]}
          />
        ) : undefined
      }
    >
      {q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !q.data ? (
        <Skeleton className="h-[240px]" />
      ) : !m.areas.length ? (
        <EmptyState compact title={t('compliance.heat.none')} />
      ) : (
        <ChartFrame
          caption={t('compliance.heat.label', { group: groupLabel })}
          chart={<EChart build={build} height={Math.max(200, m.areas.length * 30 + 40)} label={t('compliance.heat.label', { group: groupLabel })} />}
          table={{
            head: [t('compliance.heat.area'), ...m.columns],
            rows: m.areas.map((a, y) => [a, ...m.columns.map((_, x) => (m.rate[y][x] === null ? '·' : pct(m.rate[y][x]!)))]),
          }}
        />
      )}
    </Card>
  )
}
