// The vulnerabilities page: three cards (open CVEs by severity, remediation
// status, top software), the filtered CVE table with paging, a detail sheet
// with packages, devices, references and risk acceptances, and the accept
// and reopen dialogs. Every view state lives in the URL.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import type { EChartsCoreOption } from 'echarts/core'
import { Bug, CheckCircle2, CircleDot, Download, ExternalLink, Flame, Maximize2, Minimize2, MoreHorizontal, ShieldCheck, ShieldOff, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useCan, useMe } from '../../api/me'
import { baseOption, ChartFrame, EChart, type Colors } from '../../components/charts'
import { ColumnChooser, DataGrid, useColumnVisibility, type GridColumn } from '../../components/datagrid'
import { Field } from '../../components/form'
import { SideSheet, SplitView } from '../../components/layout'
import { Facts } from '../../components/settingsform'
import { EmptyState, ErrorState, errorText, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { ActionMenu, Badge, Card, Modal, PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateShort, dateTime, fmt, fmt1, pct } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { exportCSV, useAccept, useReopen, useVuln, useVulns, useVulnSummary, type Vuln, type VulnSummary } from './api'
import {
  checkAccept,
  cleared,
  filtered,
  isoDay,
  lastDay,
  remediatedPct,
  severities,
  sevColor,
  sevLevel,
  statusColor,
  statuses,
  toQuery,
  type AcceptDraft,
  type Search,
  type Severity,
  type Status,
} from './logic'

const sevKey = (s: string | undefined) => `vulns.sev.${s ?? 'unknown'}` as MessageKey
const statusKey = (s: string | undefined) => `vulns.status.${s ?? 'active'}` as MessageKey

export function VulnerabilitiesPage() {
  const t = useT()
  const s = useSearch({ strict: false }) as Search
  const navigate = useNavigate()
  const go = useCallback(
    (patch: Partial<Search>) =>
      void navigate({
        to: '/vulnerabilities',
        search: ((prev: Search) => ({ ...prev, ...patch })) as never,
        replace: true,
      }),
    [navigate],
  )
  const summary = useVulnSummary()
  const sum = summary.data
  const findings = sum ? (sum.findings?.active ?? 0) + (sum.findings?.accepted ?? 0) + (sum.findings?.remediated ?? 0) : 0
  const full = s.full === 'on'
  const body = (
    <div className={cx('flex flex-col gap-[var(--gap)]', full && 'fixed inset-0 z-30 overflow-auto bg-bg p-4')}>
      <PageHeader
        title={t('vulns.title')}
        sub={t('vulns.sub')}
        actions={
          <button type="button" className="btn" aria-pressed={full} onClick={() => go({ full: full ? undefined : 'on' })}>
            {full ? <Minimize2 size={15} aria-hidden /> : <Maximize2 size={15} aria-hidden />} {t(full ? 'vulns.exitFullscreen' : 'vulns.fullscreen')}
          </button>
        }
      />
      {summary.error ? (
        <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
      ) : !sum ? (
        <LoadingState rows={6} />
      ) : findings === 0 ? (
        <div className="card">
          {sum.feeds_enabled ? (
            <EmptyState icon={ShieldCheck} title={t('vulns.clean.title')}>
              {t('vulns.clean.body')}
            </EmptyState>
          ) : (
            <EmptyState
              icon={Bug}
              title={t('vulns.empty.title')}
              action={
                <Link to="/settings" search={{ s: 'cve' } as never} className="btn btn-primary">
                  {t('vulns.empty.action')}
                </Link>
              }
            >
              {t('vulns.empty.body')}
            </EmptyState>
          )}
        </div>
      ) : (
        <>
          <div className="grid gap-[var(--gap)] lg:grid-cols-3">
            <SeverityCard sum={sum} />
            <RemediationCard sum={sum} />
            <TopCard sum={sum} pkg={s.pkg} onPick={(pkg) => go({ pkg: s.pkg === pkg ? undefined : pkg })} />
          </div>
          <List s={s} go={go} sum={sum} />
        </>
      )}
    </div>
  )
  return body
}

/** A donut with its legend and the total (or share) in the middle. */
function Donut({
  parts,
  center,
  centerLabel,
  caption,
  head,
}: {
  parts: {
    key: string
    label: string
    value: number
    color: (c: Colors) => string
    swatch: string
  }[]
  center: string
  centerLabel: string
  caption: string
  head: [string, string]
}) {
  const build = useCallback(
    (c: Colors): EChartsCoreOption => ({
      ...baseOption(c),
      tooltip: {
        trigger: 'item',
        backgroundColor: c.surface,
        borderColor: c.line,
        textStyle: { color: c.fg, fontSize: 12 },
      },
      series: [
        {
          type: 'pie',
          radius: ['58%', '84%'],
          label: { show: false },
          labelLine: { show: false },
          itemStyle: { borderColor: c.surface, borderWidth: 2 },
          data: parts
            .filter((p) => p.value > 0)
            .map((p) => ({
              name: p.label,
              value: p.value,
              itemStyle: { color: p.color(c) },
            })),
        },
      ],
    }),
    [parts],
  )
  return (
    <ChartFrame
      caption={caption}
      table={{ head, rows: parts.map((p) => [p.label, fmt(p.value)]) }}
      chart={
        <div className="grid grid-cols-[150px_1fr] items-center gap-4">
          <div className="relative">
            <EChart build={build} height={150} label={`${caption}: ${parts.map((p) => `${p.label} ${p.value}`).join(', ')}`} />
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center" aria-hidden>
              <span className="num text-heading font-semibold">{center}</span>
              <span className="text-micro text-muted">{centerLabel}</span>
            </div>
          </div>
          <ul className="flex flex-col gap-1.5 text-meta">
            {parts.map((p) => (
              <li key={p.key} className="flex items-center gap-2">
                <span className="size-2.5 shrink-0 rounded-sm" style={{ background: p.swatch }} aria-hidden />
                <span className="truncate text-fg-2">{p.label}</span>
                <span className="num ml-auto font-semibold">{fmt(p.value)}</span>
              </li>
            ))}
          </ul>
        </div>
      }
    />
  )
}

const sevChartColor = (s: Severity) => (c: Colors) =>
  ({
    critical: c.bad,
    high: c.s3,
    medium: c.warn,
    low: c.info,
    unknown: c.off,
  })[s]
const statusChartColor = (s: Status) => (c: Colors) => ({ active: c.bad, accepted: c.info, remediated: c.ok })[s]

function SeverityCard({ sum }: { sum: VulnSummary }) {
  const t = useT()
  const parts = useMemo(
    () =>
      severities.map((s) => ({
        key: s,
        label: t(sevKey(s)),
        value: sum.severity?.[s] ?? 0,
        color: sevChartColor(s),
        swatch: sevColor[s],
      })),
    [sum, t],
  )
  const total = parts.reduce((n, p) => n + p.value, 0)
  return (
    <Card title={t('vulns.card.severity')} sub={t('vulns.card.severitySub')}>
      <Donut parts={parts} center={fmt(total)} centerLabel={t('vulns.card.total')} caption={t('vulns.card.severity')} head={[t('vulns.chart.level'), t('vulns.chart.count')]} />
    </Card>
  )
}

const remediationOrder = ['remediated', 'active', 'accepted'] as const

function RemediationCard({ sum }: { sum: VulnSummary }) {
  const t = useT()
  const parts = useMemo(
    () =>
      remediationOrder.map((s) => ({
        key: s,
        label: t(statusKey(s)),
        value: sum.findings?.[s] ?? 0,
        color: statusChartColor(s),
        swatch: statusColor[s],
      })),
    [sum, t],
  )
  return (
    <Card title={t('vulns.card.remediation')} sub={t('vulns.card.remediationSub')}>
      <Donut
        parts={parts}
        center={pct(remediatedPct(sum.findings ?? {}))}
        centerLabel={t('vulns.card.remediated')}
        caption={t('vulns.card.remediation')}
        head={[t('vulns.col.status'), t('vulns.chart.count')]}
      />
    </Card>
  )
}

function TopCard({ sum, pkg, onPick }: { sum: VulnSummary; pkg?: string; onPick: (name: string) => void }) {
  const t = useT()
  const top = sum.top_packages ?? []
  const max = Math.max(1, ...top.map((p) => p.cves ?? 0))
  return (
    <Card title={t('vulns.card.top')} sub={t('vulns.card.topSub')}>
      {top.length ? (
        <ul className="flex flex-col gap-1">
          {top.map((p) => (
            <li key={p.name}>
              <button
                type="button"
                aria-pressed={pkg === p.name}
                aria-label={t('vulns.card.topBar', {
                  name: p.name ?? '',
                  count: p.cves ?? 0,
                  devices: p.devices ?? 0,
                })}
                onClick={() => onPick(p.name ?? '')}
                className={cx('grid w-full grid-cols-[minmax(0,9rem)_1fr_auto] items-center gap-2 rounded px-1.5 py-1 text-left text-meta hover:bg-surface-2', pkg === p.name && 'bg-accent-soft')}
              >
                <span className="truncate font-mono">{p.name}</span>
                <span className="h-2 rounded-full bg-surface-2">
                  <span className="block h-2 rounded-full bg-bad" style={{ width: `${((p.cves ?? 0) / max) * 100}%` }} />
                </span>
                <span className="num font-semibold">{fmt(p.cves ?? 0)}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState compact icon={ShieldCheck} title={t('vulns.card.topNone')} />
      )}
    </Card>
  )
}

/** Severity as four segments plus its name: never by color alone. */
function SevBar({ severity }: { severity?: string }) {
  const t = useT()
  const level = sevLevel(severity)
  const color = sevColor[(severity as Severity) ?? 'unknown'] ?? sevColor.unknown
  return (
    <span className="inline-flex items-center gap-2">
      <span className="inline-flex gap-0.5" aria-hidden>
        {[1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className="h-3 w-1.5 rounded-sm"
            style={{
              background: i <= level ? color : 'var(--c-surface-2)',
              outline: i <= level ? undefined : '1px solid var(--c-line-strong)',
            }}
          />
        ))}
      </span>
      <span>{t(sevKey(severity))}</span>
    </span>
  )
}

const statusTone = {
  active: 'bad',
  accepted: 'info',
  remediated: 'ok',
} as const
const statusIcon = {
  active: CircleDot,
  accepted: ShieldOff,
  remediated: CheckCircle2,
}

function StatusBadge({ status }: { status?: string }) {
  const t = useT()
  const st = (status ?? 'active') as Status
  const I = statusIcon[st] ?? CircleDot
  return (
    <Badge tone={statusTone[st] ?? 'off'}>
      <I size={12} aria-hidden /> {t(statusKey(st))}
    </Badge>
  )
}

function KevMark({ kev }: { kev?: boolean }) {
  const t = useT()
  return kev ? (
    <Badge tone="bad">
      <Flame size={12} aria-hidden /> {t('vulns.yes')}
    </Badge>
  ) : (
    <span className="text-muted">{t('vulns.no')}</span>
  )
}

function List({ s, go, sum }: { s: Search; go: (p: Partial<Search>) => void; sum: VulnSummary }) {
  const t = useT()
  const admin = useCan('admin')
  const query = useMemo(() => toQuery(s), [s])
  const list = useVulns(query)
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items ?? []) ?? [], [list.data])
  const total = list.data?.pages[0]?.total ?? 0
  const [vis, setVis] = useColumnVisibility('vulns')
  const [accepting, setAccepting] = useState<string>()
  const [reopening, setReopening] = useState<string>()
  const [text, setText] = useState(s.q ?? '')
  useEffect(() => {
    const id = setTimeout(() => {
      if ((s.q ?? '') !== text.trim()) go({ q: text.trim() || undefined })
    }, 300)
    return () => clearTimeout(id)
  }, [text, s.q, go])
  const columns = useMemo<GridColumn<Vuln>[]>(
    () => [
      {
        id: 'cve',
        header: t('vulns.col.cve'),
        meta: { sortKey: 'cve' },
        cell: ({ row: { original: v } }) => (
          <button type="button" className="font-mono text-meta text-accent hover:underline" onClick={(e) => (e.stopPropagation(), go({ sel: v.cve }))}>
            {v.cve}
          </button>
        ),
      },
      {
        id: 'software',
        header: t('vulns.col.software'),
        cell: ({ row: { original: v } }) => (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="truncate font-mono text-meta">{v.packages?.[0]}</span>
            {(v.packages?.length ?? 0) > 1 && (
              <span className="text-micro text-muted" title={v.packages?.join(', ')}>
                {t('vulns.more', { count: (v.packages?.length ?? 1) - 1 })}
              </span>
            )}
          </span>
        ),
      },
      {
        id: 'severity',
        header: t('vulns.col.severity'),
        meta: { sortKey: 'severity' },
        cell: ({ row: { original: v } }) => <SevBar severity={v.severity} />,
      },
      {
        id: 'cvss',
        header: t('vulns.col.cvss'),
        meta: { sortKey: 'cvss', className: 'text-right' },
        cell: ({ row: { original: v } }) => <span className="num">{v.cvss != null ? fmt1(v.cvss) : <span className="text-muted">–</span>}</span>,
      },
      {
        id: 'kev',
        header: t('vulns.col.kev'),
        cell: ({ row: { original: v } }) => <KevMark kev={v.kev} />,
      },
      {
        id: 'first',
        header: t('vulns.col.first'),
        meta: { sortKey: 'first_detected' },
        cell: ({ row: { original: v } }) => (
          <span className="num" title={v.first_detected && dateTime(v.first_detected)}>
            {v.first_detected && dateShort(v.first_detected)}
          </span>
        ),
      },
      {
        id: 'devices',
        header: t('vulns.col.devices'),
        meta: { sortKey: 'devices', className: 'text-right' },
        cell: ({ row: { original: v } }) => (
          <button type="button" className="num text-accent hover:underline" onClick={(e) => (e.stopPropagation(), go({ sel: v.cve }))}>
            {fmt(v.devices ?? 0)}
          </button>
        ),
      },
      {
        id: 'status',
        header: t('vulns.col.status'),
        cell: ({ row: { original: v } }) => <StatusBadge status={v.status} />,
      },
      {
        id: 'actions',
        header: () => <span className="sr-only">{t('vulns.col.actions')}</span>,
        meta: { label: t('vulns.col.actions'), className: 'w-10' },
        cell: ({ row: { original: v } }) => (
          <ActionMenu
            trigger={
              <button type="button" className="btn btn-ghost px-1.5" aria-label={t('vulns.menu', { cve: v.cve ?? '' })} onClick={(e) => e.stopPropagation()}>
                <MoreHorizontal size={16} />
              </button>
            }
            items={[
              {
                label: t('vulns.action.details'),
                onClick: () => go({ sel: v.cve }),
              },
              {
                label: t('vulns.action.devices'),
                onClick: () => go({ sel: v.cve }),
              },
              ...(admin && v.status !== 'remediated'
                ? [
                    {
                      label: t('vulns.action.accept'),
                      icon: ShieldOff,
                      onClick: () => setAccepting(v.cve),
                    },
                  ]
                : []),
              ...(admin && (v.accepted_devices ?? 0) > 0
                ? [
                    {
                      label: t('vulns.action.reopen'),
                      icon: CircleDot,
                      onClick: () => setReopening(v.cve),
                    },
                  ]
                : []),
            ]}
          />
        ),
      },
    ],
    [t, go, admin],
  )
  const idx = rows.findIndex((r) => r.cve === s.sel)
  return (
    <>
      <Filters s={s} go={go} sum={sum} text={text} setText={setText} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-meta text-muted" aria-live="polite">
          {list.data ? t('vulns.count', { count: total }) : ''}
        </span>
        <div className="flex flex-wrap gap-2">
          <ColumnChooser columns={columns.filter((c) => c.id !== 'cve' && c.id !== 'actions').map((c) => ({ id: c.id!, label: String(c.header) }))} value={vis} onChange={setVis} />
          <button type="button" className="btn" onClick={() => void exportCSV(query).catch((e) => toast(errorText(e), 'error'))}>
            <Download size={15} aria-hidden /> {t('vulns.export')}
          </button>
        </div>
      </div>
      <SplitView
        list={
          list.error ? (
            <ErrorState error={list.error} onRetry={() => void list.refetch()} />
          ) : !list.data ? (
            <LoadingState />
          ) : (
            <DataGrid
              label={t('vulns.title')}
              data={rows}
              columns={columns}
              getRowId={(v) => v.cve ?? ''}
              sort={query.sort}
              onSortChange={(sort) => go({ sort })}
              columnVisibility={vis}
              activeId={s.sel}
              onRowClick={(v) => go({ sel: v.cve })}
              onEndReached={list.hasNextPage ? () => void list.fetchNextPage() : undefined}
              loadingMore={list.isFetchingNextPage}
              maxHeight={s.full === 'on' ? 'calc(100dvh - 200px)' : 'calc(100dvh - 300px)'}
              empty={
                <EmptyState
                  compact
                  icon={ShieldCheck}
                  title={t('vulns.none')}
                  action={
                    filtered(s) && (
                      <button type="button" className="btn" onClick={() => go(cleared(s))}>
                        {t('vulns.filter.clear')}
                      </button>
                    )
                  }
                >
                  {t('vulns.noneBody')}
                </EmptyState>
              }
              card={(v) => (
                <span className="flex flex-col gap-1">
                  <span className="flex items-center justify-between gap-2">
                    <span className="font-mono text-meta">{v.cve}</span>
                    <StatusBadge status={v.status} />
                  </span>
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta">
                    <SevBar severity={v.severity} />
                    <span className="truncate font-mono text-muted">{v.packages?.join(', ')}</span>
                    <span className="num text-muted">
                      {t('vulns.col.devices')}: {fmt(v.devices ?? 0)}
                    </span>
                  </span>
                </span>
              )}
            />
          )
        }
        detail={
          s.sel ? (
            <Detail
              cve={s.sel}
              onClose={() => go({ sel: undefined })}
              onPrev={idx > 0 ? () => go({ sel: rows[idx - 1].cve }) : undefined}
              onNext={idx >= 0 && idx < rows.length - 1 ? () => go({ sel: rows[idx + 1].cve }) : undefined}
              onAccept={() => setAccepting(s.sel)}
              onReopen={() => setReopening(s.sel)}
            />
          ) : undefined
        }
      />
      {accepting && <AcceptDialog cve={accepting} onClose={() => setAccepting(undefined)} />}
      <ReopenDialog cve={reopening} onClose={() => setReopening(undefined)} />
    </>
  )
}

function Filters({ s, go, sum, text, setText }: { s: Search; go: (p: Partial<Search>) => void; sum: VulnSummary; text: string; setText: (v: string) => void }) {
  const t = useT()
  return (
    <div role="search" aria-label={t('vulns.filter.title')} className="card grid gap-3 p-[var(--pad-card)] sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-8">
      <div className="sm:col-span-2">
        <Field label={t('vulns.filter.search')}>
          {({ id }) => <input id={id} type="search" className="field" value={text} placeholder="CVE-2024-…, openssl" onChange={(e) => setText(e.target.value)} />}
        </Field>
      </div>
      <Field label={t('vulns.filter.severity')}>
        {({ id }) => (
          <select id={id} className="field" value={s.sev ?? ''} onChange={(e) => go({ sev: e.target.value || undefined })}>
            <option value="">{t('vulns.filter.allSeverities')}</option>
            {severities.map((v) => (
              <option key={v} value={v}>
                {t(sevKey(v))}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field label={t('vulns.filter.status')}>
        {({ id }) => (
          <select
            id={id}
            className="field"
            value={s.status ?? 'active'}
            onChange={(e) =>
              go({
                status: e.target.value === 'active' ? undefined : e.target.value,
              })
            }
          >
            {statuses.map((v) => (
              <option key={v} value={v}>
                {t(statusKey(v))}
              </option>
            ))}
            <option value="all">{t('vulns.status.all')}</option>
          </select>
        )}
      </Field>
      <Field label={t('vulns.filter.device')}>
        {({ id }) => (
          <select id={id} className="field" value={s.device ?? ''} onChange={(e) => go({ device: e.target.value || undefined })}>
            <option value="">{t('vulns.filter.allDevices')}</option>
            {(sum.devices ?? []).map((d) => (
              <option key={d.id} value={d.id}>
                {d.hostname || d.id}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field label={t('vulns.filter.os')}>
        {({ id }) => (
          <select id={id} className="field" value={s.os ?? ''} onChange={(e) => go({ os: e.target.value || undefined })}>
            <option value="">{t('vulns.filter.allOS')}</option>
            {(sum.os ?? []).map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field label={t('vulns.filter.package')}>
        {({ id }) => (
          <>
            <input id={id} className="field font-mono" list="vulns-pkgs" spellCheck={false} value={s.pkg ?? ''} onChange={(e) => go({ pkg: e.target.value.trim() || undefined })} />
            <datalist id="vulns-pkgs">
              {(sum.top_packages ?? []).map((p) => (
                <option key={p.name} value={p.name} />
              ))}
            </datalist>
          </>
        )}
      </Field>
      <Field label={t('vulns.filter.from')}>
        {({ id }) => <input id={id} type="date" className="field" value={s.from ?? ''} max={s.to} onChange={(e) => go({ from: e.target.value || undefined })} />}
      </Field>
      <Field label={t('vulns.filter.to')}>
        {({ id }) => <input id={id} type="date" className="field" value={s.to ?? ''} min={s.from} onChange={(e) => go({ to: e.target.value || undefined })} />}
      </Field>
      <label className="flex items-center gap-2 self-end pb-2 text-body">
        <input type="checkbox" checked={s.kev === 'on'} onChange={(e) => go({ kev: e.target.checked ? 'on' : undefined })} /> {t('vulns.filter.kev')}
      </label>
      <div className="flex items-end">
        <button
          type="button"
          className="btn"
          disabled={!filtered(s)}
          onClick={() => {
            setText('')
            go({
              ...Object.fromEntries(Object.keys(s).map((k) => [k, undefined])),
              ...cleared(s),
            })
          }}
        >
          <X size={15} aria-hidden /> {t('vulns.filter.clear')}
        </button>
      </div>
    </div>
  )
}

function Detail({ cve, onClose, onPrev, onNext, onAccept, onReopen }: { cve: string; onClose: () => void; onPrev?: () => void; onNext?: () => void; onAccept: () => void; onReopen: () => void }) {
  const t = useT()
  const admin = useCan('admin')
  const q = useVuln(cve)
  const reopen = useReopen()
  const v = q.data
  const activeAcc = (v?.acceptances ?? []).filter((a) => a.state === 'active')
  return (
    <SideSheet
      title={<span className="font-mono">{cve}</span>}
      sub={v && <StatusBadge status={v.status} />}
      onClose={onClose}
      onPrev={onPrev}
      onNext={onNext}
      actions={
        admin &&
        v && (
          <>
            {v.status !== 'remediated' && (
              <button type="button" className="btn" onClick={onAccept}>
                <ShieldOff size={15} aria-hidden /> {t('vulns.action.accept')}
              </button>
            )}
            {activeAcc.length > 0 && (
              <button type="button" className="btn" onClick={onReopen}>
                <CircleDot size={15} aria-hidden /> {t('vulns.action.reopen')}
              </button>
            )}
          </>
        )
      }
    >
      {q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !v ? (
        <LoadingState rows={6} />
      ) : (
        <div className="flex flex-col gap-5">
          <Facts
            rows={[
              [t('vulns.detail.severity'), <SevBar severity={v.severity} />],
              [t('vulns.detail.cvss'), v.cvss != null ? <span className="num">{fmt1(v.cvss)}</span> : <span className="text-muted">{t('vulns.detail.unknownCvss')}</span>],
              ...(v.vector ? [[t('vulns.detail.vector'), <span className="font-mono text-micro break-all">{v.vector}</span>] as [string, ReactNode]] : []),
              [
                t('vulns.detail.kev'),
                v.kev ? (
                  <span className="flex flex-col items-start gap-0.5">
                    <KevMark kev />
                    <span className="text-meta text-muted">{v.kev.name}</span>
                    {v.kev.added && (
                      <span className="text-meta text-muted">
                        {t('vulns.detail.kevAdded', {
                          date: dateShort(v.kev.added),
                          due: v.kev.due ? dateShort(v.kev.due) : '–',
                        })}
                      </span>
                    )}
                    {v.kev.ransomware && <span className="text-meta text-bad">{t('vulns.detail.ransomware')}</span>}
                  </span>
                ) : (
                  <span className="text-muted">{t('vulns.detail.notKev')}</span>
                ),
              ],
              [t('vulns.detail.first'), v.first_detected && dateTime(v.first_detected)],
              [t('vulns.detail.sources'), (v.sources ?? []).map((x) => (x === 'package manager' ? t('vulns.detail.source.package manager') : x)).join(', ')],
            ]}
          />
          <section>
            <h3 className="mb-2 text-body font-semibold">{t('vulns.detail.packages')}</h3>
            <table className="w-full text-meta">
              <thead className="text-left text-muted">
                <tr>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    {t('vulns.filter.package')}
                  </th>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    {t('vulns.detail.installed')}
                  </th>
                  <th scope="col" className="py-1 pr-3 font-medium">
                    {t('vulns.detail.fixed')}
                  </th>
                  <th scope="col" className="py-1 text-right font-medium">
                    {t('vulns.col.devices')}
                  </th>
                </tr>
              </thead>
              <tbody>
                {(v.packages ?? []).map((p) => (
                  <tr key={p.name} className="border-t border-line align-top">
                    <td className="py-1 pr-3 font-mono">{p.name}</td>
                    <td className="py-1 pr-3 font-mono break-all">{p.installed?.join(', ')}</td>
                    <td className="py-1 pr-3 font-mono break-all">{p.fixed?.join(', ')}</td>
                    <td className="num py-1 text-right">{fmt(p.devices ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section>
            <h3 className="mb-2 text-body font-semibold">
              {t('vulns.detail.devices')} <span className="num text-muted">({fmt(v.devices?.length ?? 0)})</span>
            </h3>
            <ul className="flex flex-col divide-y divide-line">
              {(v.devices ?? []).map((d) => (
                <li key={`${d.id}-${d.package}`} className="flex flex-wrap items-center justify-between gap-2 py-1.5 text-meta">
                  <span className="flex min-w-0 flex-col">
                    <Link to="/devices/$id" params={{ id: d.id ?? '' }} search={{ tab: 'updates' } as never} className="truncate text-accent hover:underline">
                      {d.hostname || d.id}
                    </Link>
                    <span className="truncate font-mono text-micro text-muted">
                      {d.package} {d.installed} → {d.fixed}
                    </span>
                  </span>
                  <span className="flex flex-col items-end gap-0.5">
                    <StatusBadge status={d.status} />
                    <span className="text-micro text-muted">
                      {d.remediated_at ? `${t('vulns.detail.remediatedAt')} ${dateShort(d.remediated_at)}` : `${t('vulns.detail.lastSeen')} ${d.last_seen ? dateShort(d.last_seen) : ''}`}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h3 className="mb-2 text-body font-semibold">{t('vulns.detail.acceptances')}</h3>
            {(v.acceptances ?? []).length === 0 ? (
              <p className="text-meta text-muted">{t('vulns.detail.noAcceptances')}</p>
            ) : (
              <ul className="flex flex-col gap-2">
                {(v.acceptances ?? []).map((a) => (
                  <li key={a.id} className="rounded-md border border-line p-2 text-meta">
                    <div className="flex items-start justify-between gap-2">
                      <span className="min-w-0 break-words">{a.reason}</span>
                      <Badge tone={a.state === 'active' ? 'info' : 'off'}>{t(`vulns.detail.state.${a.state ?? 'active'}` as MessageKey)}</Badge>
                    </div>
                    <div className="mt-1 text-micro text-muted">
                      {a.device_id || t('vulns.detail.scopeAll')} · {a.package || t('vulns.detail.scopeAllPackages')} ·{' '}
                      {t('vulns.detail.acceptedBy', {
                        who: a.created_by ?? '',
                        date: a.expires_at ? dateShort(lastDay(a.expires_at)) : '',
                      })}
                    </div>
                    {admin && a.state === 'active' && (
                      <button
                        type="button"
                        className="btn btn-ghost mt-1 text-bad"
                        disabled={reopen.isPending}
                        onClick={() =>
                          reopen.mutate(
                            { cve, id: a.id },
                            {
                              onSuccess: () => toast(t('vulns.reopen.done', { cve })),
                              onError: (e) => toast(errorText(e), 'error'),
                            },
                          )
                        }
                      >
                        {t('vulns.detail.revoke')}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section>
            <h3 className="mb-2 text-body font-semibold">{t('vulns.detail.refs')}</h3>
            <ul className="flex flex-col gap-1 text-meta">
              {(v.references ?? []).map((r) => (
                <li key={r.url}>
                  <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
                    {r.label} <ExternalLink size={12} aria-hidden />
                  </a>
                </li>
              ))}
            </ul>
          </section>
        </div>
      )}
    </SideSheet>
  )
}

function AcceptDialog({ cve, onClose }: { cve: string; onClose: () => void }) {
  const t = useT()
  const me = useMe()
  const detail = useVuln(cve)
  const accept = useAccept()
  // an admin limited to tags accepts for one device of its scope (the server checks it again)
  const scoped = (me.scope_tags ?? []).length > 0
  const devices = useMemo(() => [...new Map((detail.data?.devices ?? []).filter((d) => d.status !== 'remediated').map((d) => [d.id, d])).values()], [detail.data])
  const [d, setD] = useState<AcceptDraft>({
    reason: '',
    expires: '',
    device_id: '',
    package: '',
  })
  const [shown, setShown] = useState(false)
  const deviceId = d.device_id || (scoped ? (devices[0]?.id ?? '') : '')
  const errs = checkAccept(d)
  const set = (k: keyof AcceptDraft) => (e: { target: { value: string } }) => setD({ ...d, [k]: e.target.value })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setShown(true)
    if (Object.keys(errs).length) return
    accept.mutate(
      {
        cve,
        reason: d.reason.trim(),
        expires: d.expires,
        device_id: deviceId || undefined,
        package: d.package || undefined,
      },
      {
        onSuccess: () => (toast(t('vulns.accept.done', { cve })), onClose()),
        onError: (x) => toast(errorText(x), 'error'),
      },
    )
  }
  const today = new Date()
  const max = new Date(today.getFullYear() + 1, today.getMonth(), today.getDate())
  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={t('vulns.accept.title', { cve })}
      description={t('vulns.accept.sub')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="submit" form="vuln-accept" className="btn btn-primary" disabled={accept.isPending}>
            {t('vulns.accept.submit')}
          </button>
        </>
      }
    >
      <form id="vuln-accept" noValidate onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <div className="md:col-span-2">
          <Field label={t('vulns.accept.reason')} error={shown && errs.reason ? t('vulns.accept.errReason') : undefined} required>
            {({ id, describedBy, invalid }) => (
              <textarea id={id} rows={3} maxLength={1000} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" value={d.reason} onChange={set('reason')} />
            )}
          </Field>
        </div>
        <Field label={t('vulns.accept.expires')} help={t('vulns.accept.expiresHelp')} error={shown && errs.expires ? t('vulns.accept.errExpires') : undefined} required>
          {({ id, describedBy, invalid }) => (
            <input
              id={id}
              type="date"
              aria-describedby={describedBy}
              aria-invalid={invalid || undefined}
              className="field"
              min={isoDay(today)}
              max={isoDay(max)}
              value={d.expires}
              onChange={set('expires')}
            />
          )}
        </Field>
        <Field label={t('vulns.accept.device')}>
          {({ id }) => (
            <select id={id} className="field" value={deviceId} onChange={set('device_id')}>
              {!scoped && <option value="">{t('vulns.accept.deviceAll')}</option>}
              {devices.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.hostname || x.id}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('vulns.accept.package')}>
          {({ id }) => (
            <select id={id} className="field" value={d.package} onChange={set('package')}>
              <option value="">{t('vulns.accept.packageAll')}</option>
              {(detail.data?.packages ?? []).map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
          )}
        </Field>
      </form>
    </Modal>
  )
}

function ReopenDialog({ cve, onClose }: { cve?: string; onClose: () => void }) {
  const t = useT()
  const reopen = useReopen()
  return (
    <Modal
      open={!!cve}
      onClose={onClose}
      title={t('vulns.reopen.title', { cve: cve ?? '' })}
      description={t('vulns.reopen.body')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={reopen.isPending}
            onClick={() =>
              reopen.mutate(
                { cve: cve! },
                {
                  onSuccess: () => (toast(t('vulns.reopen.done', { cve: cve ?? '' })), onClose()),
                  onError: (e) => toast(errorText(e), 'error'),
                },
              )
            }
          >
            {t('vulns.action.reopen')}
          </button>
        </>
      }
    />
  )
}
