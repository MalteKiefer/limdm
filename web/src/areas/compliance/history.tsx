// Compliance history: the state of every device, or one device with its
// state per check and its changes, at the end of a chosen day.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { ArrowLeft, Download, ExternalLink } from 'lucide-react'
import { useMemo } from 'react'
import { useCan } from '../../api/me'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, errorText, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { Card, PageHeader } from '../../components/ui'
import { useT } from '../../i18n'
import { dateShort, dateTime, fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useHistory } from './api'
import { downloadExport } from './export'
import { isoDay } from './logic'
import { ResultBadge, SectionNav } from './parts'

type Row = { id: string; hostname: string; pass: number; fail: number; other: number }
type Change = { check_id: string; status: string; detail: string; since: string; catalog_version: string }

export function HistoryPage() {
  const t = useT()
  const s = useSearch({ strict: false }) as { at?: string; device?: string }
  const navigate = useNavigate()
  const go = (patch: Record<string, string | undefined>) => void navigate({ to: '/compliance/history', search: { ...s, ...patch } as never })
  const today = isoDay(new Date())
  const at = s.at && /^\d{4}-\d{2}-\d{2}$/.test(s.at) ? s.at : today
  const canExport = useCan('audit')
  const q = useHistory(at, s.device)
  const d = q.data
  const host = d?.devices.find((x) => x.id === s.device)?.hostname ?? s.device
  const devCols = useMemo<GridColumn<Row>[]>(
    () => [
      { id: 'host', header: t('compliance.hist.device'), cell: ({ row: { original: r } }) => <span className="font-mono">{r.hostname || r.id}</span> },
      { id: 'pass', header: t('compliance.col.pass'), meta: { className: 'text-right' }, cell: ({ row: { original: r } }) => <span className="num">{fmt(r.pass)}</span> },
      { id: 'fail', header: t('compliance.col.fail'), meta: { className: 'text-right' }, cell: ({ row: { original: r } }) => <span className={cx('num font-semibold', r.fail ? 'text-bad' : 'text-muted')}>{r.fail || '·'}</span> },
      { id: 'other', header: t('compliance.hist.other'), meta: { className: 'text-right' }, cell: ({ row: { original: r } }) => <span className="num text-muted">{r.other || '·'}</span> },
    ],
    [t],
  )
  const stateCols = useMemo<GridColumn<Change>[]>(
    () => [
      { id: 'check', header: t('compliance.col.check'), cell: ({ row: { original: r } }) => <span className="font-mono text-[12.5px]">{r.check_id}</span> },
      { id: 'status', header: t('compliance.exc.col.state'), cell: ({ row: { original: r } }) => <ResultBadge status={r.status} /> },
      { id: 'since', header: t('compliance.hist.since'), cell: ({ row: { original: r } }) => <span className="num">{dateTime(r.since)}</span> },
      { id: 'detail', header: t('compliance.hist.detail'), cell: ({ row: { original: r } }) => <span className="truncate text-muted" title={r.detail}>{r.detail}</span> },
      { id: 'catalog', header: t('compliance.hist.catalog'), cell: ({ row: { original: r } }) => <span className="font-mono text-[12px] text-muted">{r.catalog_version}</span> },
    ],
    [t],
  )
  const changeCols = useMemo<GridColumn<Change>[]>(() => [{ ...stateCols[2], header: t('compliance.hist.time') }, stateCols[0], stateCols[1], stateCols[3]], [stateCols, t])
  const csv = () => downloadExport('compliance-history.csv', { at, device: s.device }).catch((e) => toast(errorText(e), 'error'))
  return (
    <div className="flex flex-col">
      <PageHeader
        title={t('compliance.hist.title')}
        sub={t('compliance.hist.sub')}
        actions={
          canExport && (
            <button type="button" className="btn btn-primary" onClick={() => void csv()}>
              <Download size={15} aria-hidden /> {t('compliance.hist.csv')}
            </button>
          )
        }
      />
      <SectionNav />
      <div className="mb-[var(--gap)] flex flex-wrap items-end gap-3">
        <Field label={t('compliance.hist.at')} required>
          {({ id }) => <input id={id} type="date" className="field" value={at} max={today} onChange={(e) => e.target.value && go({ at: e.target.value === today ? undefined : e.target.value })} />}
        </Field>
        {s.device && (
          <>
            <button type="button" className="btn" onClick={() => go({ device: undefined })}>
              <ArrowLeft size={14} aria-hidden /> {t('compliance.hist.back')}
            </button>
            <Link to="/devices/$id" params={{ id: s.device } as never} className="btn btn-ghost">
              <ExternalLink size={14} aria-hidden /> {t('compliance.hist.open')}
            </Link>
          </>
        )}
      </div>
      {q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !d ? (
        <LoadingState rows={6} />
      ) : !s.device ? (
        <Card title={t('compliance.hist.devices', { at: dateShort(`${d.at}T12:00:00`) })} id="hist-devices" bodyClass="!p-0">
          <DataGrid
            label={t('compliance.hist.devices', { at: d.at })}
            data={d.devices}
            columns={devCols}
            getRowId={(r) => r.id}
            onRowClick={(r) => go({ device: r.id })}
            empty={<EmptyState title={t('compliance.hist.none')} />}
            card={(r) => (
              <span className="flex justify-between gap-2">
                <span className="font-mono">{r.hostname}</span>
                <span className={cx('num font-semibold', r.fail ? 'text-bad' : 'text-muted')}>{r.fail || '·'}</span>
              </span>
            )}
          />
        </Card>
      ) : (
        <div className="flex flex-col gap-[var(--gap)]">
          <Card title={`${t('compliance.hist.state')}: ${host}`} id="hist-state" bodyClass="!p-0">
            <DataGrid label={t('compliance.hist.state')} data={d.state} columns={stateCols} getRowId={(r) => r.check_id} maxHeight="420px" empty={<EmptyState title={t('compliance.hist.none')} />} card={(r) => <span className="flex justify-between gap-2"><span className="font-mono text-[12.5px]">{r.check_id}</span><ResultBadge status={r.status} /></span>} />
          </Card>
          <Card title={t('compliance.hist.changes')} id="hist-changes" bodyClass="!p-0">
            <DataGrid label={t('compliance.hist.changes')} data={d.changes} columns={changeCols} getRowId={(r) => `${r.since}|${r.check_id}|${r.status}`} maxHeight="420px" empty={<EmptyState title={t('compliance.hist.noChanges')} />} card={(r) => <span className="flex justify-between gap-2"><span className="font-mono text-[12.5px]">{r.check_id}</span><ResultBadge status={r.status} /></span>} />
          </Card>
        </div>
      )}
    </div>
  )
}
