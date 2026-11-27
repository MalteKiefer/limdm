// Building blocks of the config area: the review of a change (devices,
// expected effect, diff), the version history with rollback, the type
// picker of new library items and the list of deleted objects.
import { Link } from '@tanstack/react-router'
import { CheckCircle2, History, RotateCcw, Search, ShieldAlert, Trash2, Users } from 'lucide-react'
import { useId, useMemo, useState } from 'react'
import { useCan } from '../../api/me'
import { DiffViewer } from '../../components/diff'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal, StatusPill, type DeviceStatus } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateTime, fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useRollback, useTypes, useVersions, type Kind, type Preview, type TypeInfo } from './api'

/** The effect of a change: devices online and offline, expected compliance effect, sample devices. */
export function Impact({ preview, busy, error }: { preview?: Preview; busy?: boolean; error?: unknown }) {
  const t = useT()
  if (error) return <p className="rounded-lg bg-bad-soft p-3 text-body text-bad">{errorText(error)}</p>
  if (!preview) return <p className="rounded-lg bg-surface-2 p-3 text-body text-muted">{t(busy ? 'config.reviewing' : 'config.noChange')}</p>
  const bad = preview.impact.filter((i) => ['level', 'excluded_added', 'advisory_added', 'items_removed'].includes(i.code))
  return (
    <div className="flex flex-col gap-4" aria-live="polite" aria-busy={busy || undefined}>
      <div>
        <div className="num text-display leading-tight font-semibold">{t('config.devicesN', { count: preview.devices })}</div>
        <p className="text-meta text-muted">{preview.devices ? t('config.onlineOffline', { online: fmt(preview.online), offline: fmt(preview.offline) }) : t('config.noDevices')}</p>
        {preview.blueprints.length > 0 && (
          <p className="mt-1 text-meta text-muted">
            {t('config.viaBlueprints')}{' '}
            {preview.blueprints.map((b, i) => (
              <span key={b}>
                {i > 0 && ', '}
                <Link to="/devices" search={{ q: `blueprint:"${b}"` }} className="text-accent hover:underline">
                  {b}
                </Link>
              </span>
            ))}
          </p>
        )}
      </div>
      {preview.impact.length === 0 ? (
        <div className="flex items-center gap-2 rounded-lg bg-ok-soft p-3 text-body text-ok">
          <CheckCircle2 size={15} aria-hidden /> {t('config.noImpact')}
        </div>
      ) : (
        <div className={cx('rounded-lg border p-3 text-body', bad.length ? 'border-warn/40 bg-warn-soft' : 'border-line bg-surface-2')}>
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <ShieldAlert size={15} aria-hidden /> {t('config.expected')}
          </div>
          <ul className="flex flex-col gap-0.5">
            {preview.impact.map((i) => (
              <li key={i.code}>
                {t(`config.impact.${i.code}` as MessageKey, { from: i.values[0] ?? '', to: i.values[1] ?? '' })}
                {i.code !== 'level' && <span className="font-mono text-meta"> {i.values.join(', ')}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {preview.needs_approval && <p className="flex items-center gap-1.5 text-meta text-muted"><Users size={14} aria-hidden /> {t('config.fourEyesNote')}</p>}
      {preview.sample.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-meta font-semibold text-muted">{t('config.sample')}</h3>
          <ul className="divide-y divide-line rounded-lg border border-line">
            {preview.sample.slice(0, 8).map((d) => (
              <li key={d.id} className="flex items-center gap-2 px-2.5 py-1.5">
                <Link to="/devices/$id" params={{ id: d.id }} className="flex-1 truncate font-mono text-meta hover:text-accent">
                  {d.hostname}
                </Link>
                <StatusPill status={d.status as DeviceStatus} compact />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

/** The server's line diff of a preview (stored version against the edit). */
export function PreviewDiff({ preview }: { preview?: Preview }) {
  const t = useT()
  const [before, after] = useMemo(() => {
    const a: string[] = []
    const b: string[] = []
    for (const l of preview?.diff ?? []) {
      if (l.op !== 'add') a.push(l.text)
      if (l.op !== 'del') b.push(l.text)
    }
    return [a.join('\n'), b.join('\n')]
  }, [preview])
  if (!preview) return <p className="text-body text-muted">{t('config.noChange')}</p>
  return <DiffViewer before={before} after={after} label={t('config.diffLabel')} />
}

/** Version history with a diff between two versions and rollback or restore. */
export function Versions({ kind, id }: { kind: Kind; id: number }) {
  const t = useT()
  const admin = useCan('admin')
  const q = useVersions(kind, id)
  const rollback = useRollback(kind)
  const [pick, setPick] = useState<{ a?: number; b?: number }>({})
  const [confirm, setConfirm] = useState<number>()
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <LoadingState />
  const vs = q.data.items
  const b = vs.find((v) => v.version === pick.b) ?? vs[0]
  const a = vs.find((v) => v.version === pick.a) ?? vs.find((v) => v.version < b.version)
  const latest = vs[0].version
  return (
    <div className="grid gap-[var(--gap)] xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0">
        {!q.data.exists && (
          <p className="mb-3 rounded-lg bg-warn-soft p-3 text-body">
            <Trash2 size={14} className="mr-1 inline" aria-hidden /> {t('config.deletedNote')}
          </p>
        )}
        <DiffViewer before={a?.doc ?? ''} after={b.doc} label={a ? t('config.versionAB', { a: a.version, b: b.version }) : t('config.versionN', { n: b.version })} />
      </div>
      <Card title={t('config.history')} bodyClass="!px-0 !pb-1">
        <table className="w-full text-left text-body">
          <caption className="sr-only">{t('config.history')}</caption>
          <thead className="text-meta text-muted">
            <tr className="border-b border-line">
              <th className="px-3 py-1.5 font-medium">#</th>
              <th className="font-medium">{t('config.compare')}</th>
              <th className="font-medium">{t('config.change')}</th>
              <th className="pr-3">
                <span className="sr-only">{t('config.actions')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {vs.map((v) => (
              <tr key={v.version} className={cx('border-b border-line last:border-0', v.version === b.version && 'bg-accent-soft/40')}>
                <td className="num px-3 py-1.5 align-top">{v.version}</td>
                <td className="py-1.5 align-top">
                  <span className="inline-flex gap-1">
                    <input type="radio" name="va" aria-label={t('config.compareOld', { n: v.version })} checked={a?.version === v.version} onChange={() => setPick({ ...pick, a: v.version })} />
                    <input type="radio" name="vb" aria-label={t('config.compareNew', { n: v.version })} checked={b.version === v.version} onChange={() => setPick({ ...pick, b: v.version })} />
                  </span>
                </td>
                <td className="py-1.5 align-top">
                  <div>{v.deleted ? <Badge tone="bad">{t('config.deleted')}</Badge> : v.note}</div>
                  <div className="text-meta text-muted">
                    {v.by} · <time dateTime={v.at} title={dateTime(v.at)}>{ago(v.at)}</time>
                  </div>
                </td>
                <td className="py-1.5 pr-3 text-right align-top">
                  {admin && !v.deleted && (v.version !== latest || !q.data.exists) && (
                    <button type="button" className="btn !h-7 px-2 text-meta" onClick={() => setConfirm(v.version)}>
                      <RotateCcw size={13} aria-hidden /> {t(q.data.exists ? 'config.rollback' : 'config.restore')}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Modal
        open={confirm !== undefined}
        onClose={() => setConfirm(undefined)}
        title={t(q.data.exists ? 'config.rollbackTitle' : 'config.restoreTitle', { n: confirm ?? 0 })}
        description={t('config.rollbackBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setConfirm(undefined)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={rollback.isPending}
              onClick={() =>
                rollback.mutate(
                  { id, version: confirm! },
                  {
                    onSuccess: (r) => {
                      toast(t(r.pending ? 'config.pendingToast' : 'config.rolledBack'))
                      setConfirm(undefined)
                      setPick({})
                    },
                    onError: (e) => toast(errorText(e), 'error'),
                  },
                )
              }
            >
              {t(q.data.exists ? 'config.rollback' : 'config.restore')}
            </button>
          </>
        }
      />
    </div>
  )
}

/** Deleted blueprints or items: open their history to restore one. */
export function DeletedList({ kind, items }: { kind: Kind; items: { id: number; name: string; at: string; by: string }[] }) {
  const t = useT()
  if (!items.length) return null
  return (
    <Card title={t('config.deletedTitle')} sub={t('config.deletedSub')} bodyClass="!px-0 !pb-1">
      <ul className="divide-y divide-line">
        {items.map((d) => (
          <li key={d.id} className="flex flex-wrap items-center gap-3 px-[var(--pad-card)] py-2">
            <History size={15} className="text-muted" aria-hidden />
            <Link to={kind === 'blueprints' ? '/config/blueprints/$id' : '/config/library/$id'} params={{ id: String(d.id) }} search={{ view: 'versions' }} className="font-medium hover:text-accent">
              {d.name}
            </Link>
            <span className="text-meta text-muted">
              {t('config.deletedBy', { by: d.by })} · <time dateTime={d.at}>{ago(d.at)}</time>
            </span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

/** Picks the declaration type of a new item; every type with its description. */
export function TypePicker({ open, onClose, onPick }: { open: boolean; onClose: () => void; onPick: (type: string) => void }) {
  const t = useT()
  const types = useTypes()
  const [q, setQ] = useState('')
  const id = useId()
  const list = (types.data ?? []).filter((x) => `${x.title} ${x.type} ${x.description}`.toLowerCase().includes(q.toLowerCase())).sort((a, b) => a.title.localeCompare(b.title))
  return (
    <Modal open={open} onClose={onClose} title={t('config.pickType')} description={t('config.pickTypeSub')} wide>
      <div className="relative mb-3">
        <Search size={15} className="absolute top-1/2 left-3 -translate-y-1/2 text-muted" aria-hidden />
        <input id={id} className="field !pl-9" autoFocus placeholder={t('config.searchTypes')} aria-label={t('config.searchTypes')} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {types.error && <ErrorState error={types.error} />}
      {!types.data && !types.error && <LoadingState />}
      {types.data && !list.length && <EmptyState title={t('config.noTypes')} />}
      <ul className="flex max-h-[50vh] flex-col gap-1 overflow-y-auto">
        {list.map((x: TypeInfo) => (
          <li key={x.type}>
            <button type="button" className="flex w-full items-start gap-3 rounded-lg px-3 py-2 text-left hover:bg-surface-2 focus-visible:bg-surface-2" onClick={() => onPick(x.type)}>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2 font-medium">
                  {x.title}
                  {x.four_eyes && <Badge tone="info">{t('config.fourEyes')}</Badge>}
                </span>
                <span className="block text-meta text-muted">{x.description}</span>
                <span className="block font-mono text-micro text-muted">{x.type}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </Modal>
  )
}
