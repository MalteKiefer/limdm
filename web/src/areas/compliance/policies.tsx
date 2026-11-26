// Compliance policies and custom checks of the library: levels, advisory
// and excluded checks, grace period and automatic lock, the blueprints
// using them, and the fleet result of each custom check. Editing happens in
// the configuration area; every item links there.
import { Link } from '@tanstack/react-router'
import { Clock, Lock, Pencil } from 'lucide-react'
import { useMemo } from 'react'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge, Card, PageHeader } from '../../components/ui'
import { useT } from '../../i18n'
import { fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useCompliance, usePolicies } from './api'
import { SectionNav, SeverityBadge } from './parts'
import type { Schemas } from '../../api/client'

type Policy = Schemas['CompliancePolicies']['policies'][number]
type Custom = Schemas['CompliancePolicies']['custom_checks'][number]

export function PoliciesPage() {
  const t = useT()
  const q = usePolicies()
  const fleet = useCompliance().data
  const byId = useMemo(() => new Map((fleet?.checks ?? []).map((c) => [c.id, c])), [fleet])
  const cols = useMemo<GridColumn<Custom>[]>(
    () => [
      {
        id: 'check',
        header: t('compliance.col.check'),
        cell: ({ row: { original: c } }) => (
          <Link to="/compliance" search={{ sel: c.id } as never} className="flex min-w-0 flex-col hover:text-accent">
            <span className="truncate font-medium">{c.title}</span>
            <span className="truncate font-mono text-[11.5px] text-muted">{c.id}</span>
          </Link>
        ),
      },
      { id: 'severity', header: t('compliance.pol.severity'), cell: ({ row: { original: c } }) => <span className="flex gap-1"><Badge>L{c.level}</Badge><SeverityBadge severity={c.severity} /></span> },
      { id: 'test', header: t('compliance.pol.test'), cell: ({ row: { original: c } }) => <span className="font-mono text-[12px]">{c.test}</span> },
      {
        id: 'fleet',
        header: t('compliance.pol.fleet'),
        cell: ({ row: { original: c } }) => {
          const f = byId.get(c.id)
          return f ? (
            <span className="num">
              {fmt(f.pass)} / <span className={cx(f.fail > 0 && 'font-semibold text-bad')}>{fmt(f.fail)}</span>
            </span>
          ) : (
            <span className="text-muted">{t('compliance.pol.notReported')}</span>
          )
        },
      },
      {
        id: 'item',
        header: t('compliance.pol.item'),
        cell: ({ row: { original: c } }) => (
          <Link to="/config/library/$id" params={{ id: String(c.item_id) } as never} className="hover:text-accent">
            {c.item_name}
          </Link>
        ),
      },
    ],
    [t, byId],
  )
  return (
    <div className="flex flex-col">
      <PageHeader title={t('compliance.pol.title')} sub={t('compliance.pol.sub')} />
      <SectionNav />
      <div className="flex flex-col gap-[var(--gap)]">
        <Card title={t('compliance.pol.graceTitle')} id="pol-grace">
          <div className="grid gap-4 text-[13px] md:grid-cols-2">
            <p className="flex gap-2">
              <Clock size={16} className="mt-0.5 shrink-0 text-muted" aria-hidden />
              {t('compliance.pol.graceBody')}
            </p>
            <p className="flex gap-2">
              <Lock size={16} className="mt-0.5 shrink-0 text-muted" aria-hidden />
              {t('compliance.pol.lockBody')}
            </p>
          </div>
        </Card>
        {q.error ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : !q.data ? (
          <LoadingState />
        ) : (
          <>
            <section aria-labelledby="pol-list">
              <h2 id="pol-list" className="mb-2 text-[15px] font-semibold">
                {t('compliance.pol.policies')}
              </h2>
              {!q.data.policies.length ? (
                <div className="card">
                  <EmptyState title={t('compliance.pol.none')} />
                </div>
              ) : (
                <div className="grid gap-[var(--gap)] lg:grid-cols-2">
                  {q.data.policies.map((p) => (
                    <PolicyCard key={p.id} p={p} />
                  ))}
                </div>
              )}
            </section>
            <Card title={t('compliance.pol.custom')} sub={t('compliance.pol.customSub')} id="pol-custom" bodyClass="!p-0">
              <DataGrid
                label={t('compliance.pol.custom')}
                data={q.data.custom_checks}
                columns={cols}
                getRowId={(c) => `${c.item_id}|${c.id}`}
                maxHeight="480px"
                empty={<EmptyState title={t('compliance.pol.customNone')} />}
                card={(c) => (
                  <span className="flex flex-col">
                    <span className="font-medium">{c.title}</span>
                    <span className="font-mono text-[11.5px] text-muted">{c.id} · {c.item_name}</span>
                  </span>
                )}
              />
            </Card>
          </>
        )}
      </div>
    </div>
  )
}

function PolicyCard({ p }: { p: Policy }) {
  const t = useT()
  const hours = (n?: number) => (n ? t('compliance.pol.hours', { count: n }) : undefined)
  const rows: [string, React.ReactNode][] = [
    [t('compliance.pol.level'), t(p.level === 2 ? 'compliance.pol.level2' : 'compliance.pol.level1')],
    [t('compliance.pol.remediate'), t(p.remediate ? 'compliance.pol.on' : 'compliance.pol.off')],
    [t('compliance.pol.grace'), hours(p.grace_hours) ?? t('compliance.pol.none0')],
    [t('compliance.pol.notify'), t(p.notify ? 'compliance.pol.on' : 'compliance.pol.off')],
    [t('compliance.pol.lock'), hours(p.lock_after_hours) ?? t('compliance.pol.never')],
    [t('compliance.pol.unlock'), t(p.unlock_when_compliant ? 'compliance.pol.on' : 'compliance.pol.off')],
  ]
  const list = (v?: string[] | null) => (v?.length ? v.map((x) => <Badge key={x}><span className="font-mono">{x}</span></Badge>) : <span className="text-muted">·</span>)
  return (
    <Card
      title={p.name}
      id={`pol-${p.id}`}
      action={
        <Link to="/config/library/$id" params={{ id: String(p.id) } as never} className="btn btn-ghost" aria-label={`${t('compliance.pol.edit')}: ${p.name}`}>
          <Pencil size={14} aria-hidden /> <span className="max-sm:sr-only">{t('compliance.pol.edit')}</span>
        </Link>
      }
    >
      <dl className="grid grid-cols-[minmax(140px,auto)_1fr] gap-x-4 gap-y-1.5 text-[13px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
        <dt className="text-muted">{t('compliance.pol.advisory')}</dt>
        <dd className="flex flex-wrap gap-1">{list(p.advisory)}</dd>
        <dt className="text-muted">
          {t('compliance.pol.exclude')}
          <span className="block text-[11.5px]">{t('compliance.pol.excludeHint')}</span>
        </dt>
        <dd className="flex flex-wrap gap-1">{list(p.exclude)}</dd>
        <dt className="text-muted">{t('compliance.pol.blueprints')}</dt>
        <dd className="flex flex-wrap gap-1">{p.blueprints.length ? p.blueprints.map((b) => <Badge key={b}>{b}</Badge>) : <span className="text-muted">{t('compliance.pol.unused')}</span>}</dd>
      </dl>
    </Card>
  )
}
