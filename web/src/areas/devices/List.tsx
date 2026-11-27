// The device list: query bar with the filter language (package versions
// included), facets, a virtualized grid with column chooser and sort,
// saved views, bulk actions and the side sheet. The whole view state lives
// in the URL (q, sort, sel).
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Bot, Download, FileCode2, Layers, Lock, LockOpen, Monitor, MoreHorizontal, Package, Plus, Power, RefreshCw, Server, Tag } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { useCan } from '../../api/me'
import { BulkActionBar, ColumnChooser, DataGrid, useColumnVisibility, type GridColumn, type RowSelectionState } from '../../components/datagrid'
import { BlueprintSelect } from '../../components/blueprintselect'
import { Field } from '../../components/form'
import { SideSheet, SplitView } from '../../components/layout'
import { Facets, QueryBar, type Facet } from '../../components/querybar'
import { SavedViewsMenu } from '../../components/savedviews'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { ActionMenu, Badge, Modal, PageHeader, StatusPill, type DeviceStatus } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, bytes, fmt } from '../../i18n/format'
import { addToken } from '../../lib/query'
import { ScriptFields, scriptParams, scriptValid, DeviceDialog, useDeviceMenu, type Dialog } from './actions'
import { useBulk, useCatalogApps, useDetail, useDeviceList, useFacets, usePatch, useTimeline, type Device, type Params } from './api'
import { pkgValue, statusTone } from './logic'

const facetKeys = ['status', 'os', 'agent', 'blueprint', 'tag'] as const

export function DevicesPage() {
  const t = useT()
  const search = useSearch({ strict: false }) as { q?: string; sort?: string; sel?: string }
  const nav = useNavigate()
  const q = search.q ?? ''
  const sort = search.sort ?? 'hostname'
  const go = useCallback((s: Partial<{ q: string; sort: string; sel: string }>) => void nav({ to: '/devices', search: (old: Record<string, unknown>) => ({ ...old, ...s }), replace: true }), [nav])
  const list = useDeviceList(q, sort)
  const facets = useFacets(q)
  const [vis, setVis] = useColumnVisibility('devices')
  const [selection, setSelection] = useState<RowSelectionState>({})
  const [pkg, setPkg] = useState('')
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data])
  const columns = useColumns()
  const idx = rows.findIndex((r) => r.id === search.sel)
  const active = idx >= 0 ? rows[idx] : undefined
  const keys = facets.data?.keys ?? []
  const facetList: Facet[] = facetKeys.map((k) => ({
    key: k,
    title: t(`devices.col.${k}` as MessageKey),
    values: (facets.data?.facets[k] ?? []).map((v) => ({ value: k === 'status' ? v.value.replace(' ', '-') : v.value, count: v.count, label: k === 'status' ? t(`status.${v.value}` as MessageKey) : undefined })),
  }))
  const chooser = columns.filter((c) => c.id !== 'hostname').map((c) => ({ id: c.id as string, label: c.meta?.label ?? '' }))
  const selected = Object.keys(selection).filter((id) => selection[id])
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader
        title={t('devices.title')}
        sub={facets.data ? t('devices.count', { count: facets.data.total }) : undefined}
        actions={
          <>
            <a className="btn" href="/api/v1/exports/inventory.csv">
              <Download size={15} aria-hidden /> {t('devices.export.inventory')}
            </a>
            <a className="btn" href="/api/v1/exports/packages.csv">
              <Download size={15} aria-hidden /> {t('devices.export.packages')}
            </a>
            <Link to="/devices/enroll" className="btn btn-primary">
              <Plus size={15} aria-hidden /> {t('devices.add')}
            </Link>
          </>
        }
      />
      <div className="grid gap-[var(--gap)] lg:grid-cols-[220px_1fr]">
        <aside className="max-lg:hidden">{facets.data && <Facets facets={facetList} value={q} onChange={(v) => go({ q: v, sel: undefined })} />}</aside>
        <div className="flex min-w-0 flex-col gap-3">
          <QueryBar value={q} onChange={(v) => go({ q: v, sel: undefined })} keys={keys} placeholder={t('devices.query.placeholder')} />
          <div className="flex flex-wrap items-end gap-2">
            <form
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                if (pkg.trim()) go({ q: addToken(q, { key: 'pkg', value: pkgValue(pkg) }) })
                setPkg('')
              }}
            >
              <Field label={t('devices.pkg.label')}>
                {({ id }) => <input id={id} className="field !h-9 w-64 font-mono text-body" placeholder={t('devices.pkg.placeholder')} value={pkg} onChange={(e) => setPkg(e.target.value)} spellCheck={false} />}
              </Field>
              <button type="submit" className="btn">
                <Package size={15} aria-hidden /> {t('devices.pkg.add')}
              </button>
            </form>
            <span className="flex-1" />
            <SavedViewsMenu list="devices" current={{ query: q, sort, columns: Object.keys(vis).filter((k) => vis[k] === false) }} onApply={(v) => (setVis(Object.fromEntries(v.columns.map((c) => [c, false]))), go({ q: v.query, sort: v.sort || undefined, sel: undefined }))} />
            <ColumnChooser columns={chooser} value={vis} onChange={setVis} />
          </div>
          {list.error ? (
            <div className="card">
              <ErrorState error={list.error} onRetry={() => void list.refetch()} />
            </div>
          ) : list.isPending ? (
            <LoadingState rows={8} />
          ) : (
            <SplitView
              list={
                <DataGrid
                  label={t('devices.title')}
                  data={rows}
                  columns={active ? columns.filter((c) => ['hostname', 'status', 'failing', 'last_seen'].includes(c.id as string)) : columns}
                  getRowId={(r) => r.id}
                  sort={sort}
                  onSortChange={(s) => go({ sort: s })}
                  selection={selection}
                  onSelectionChange={setSelection}
                  columnVisibility={vis}
                  activeId={active?.id}
                  onRowClick={(r) => go({ sel: r.id === search.sel ? undefined : r.id })}
                  onEndReached={list.hasNextPage ? () => void list.fetchNextPage() : undefined}
                  loadingMore={list.isFetchingNextPage}
                  card={(r) => <DeviceCard d={r} />}
                  empty={
                    <EmptyState
                      icon={Monitor}
                      title={q ? t('devices.empty.filter') : t('devices.empty.none')}
                      action={
                        q ? (
                          <button type="button" className="btn" onClick={() => go({ q: '' })}>
                            {t('query.clear')}
                          </button>
                        ) : (
                          <Link to="/devices/enroll" className="btn btn-primary">
                            {t('devices.add')}
                          </Link>
                        )
                      }
                    >
                      {q ? t('devices.empty.filterBody') : t('devices.empty.noneBody')}
                    </EmptyState>
                  }
                />
              }
              detail={active && <DeviceSheet d={active} onClose={() => go({ sel: undefined })} onPrev={idx > 0 ? () => go({ sel: rows[idx - 1].id }) : undefined} onNext={idx < rows.length - 1 ? () => go({ sel: rows[idx + 1].id }) : undefined} />}
            />
          )}
        </div>
      </div>
      <BulkBar ids={selected} onClear={() => setSelection({})} />
    </div>
  )
}

function useColumns(): GridColumn<Device>[] {
  const t = useT()
  return useMemo<GridColumn<Device>[]>(
    () => [
      {
        id: 'hostname',
        header: t('devices.col.device'),
        meta: { sortKey: 'hostname', label: t('devices.col.device') },
        cell: ({ row: { original: d } }) => (
          <div className="flex min-w-0 items-center gap-2">
            {d.desktop ? <Monitor size={14} className="shrink-0 text-muted" aria-hidden /> : <Server size={14} className="shrink-0 text-muted" aria-hidden />}
            <Link to="/devices/$id" params={{ id: d.id }} className="truncate font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
              {d.hostname}
            </Link>
            {d.tags.slice(0, 3).map((tag) => (
              <Badge key={tag}>#{tag}</Badge>
            ))}
          </div>
        ),
      },
      { id: 'status', header: t('devices.col.status'), meta: { label: t('devices.col.status') }, cell: ({ row: { original: d } }) => <StatusPill status={d.status as DeviceStatus} /> },
      {
        id: 'failing',
        header: t('devices.col.failing'),
        meta: { sortKey: 'failing', label: t('devices.col.failing'), className: 'text-right' },
        cell: ({ row: { original: d } }) => (d.failing ? <Badge tone="bad">{fmt(d.failing)}</Badge> : <span className="text-muted">0</span>),
      },
      {
        id: 'os',
        header: t('devices.col.os'),
        meta: { sortKey: 'os', label: t('devices.col.os') },
        cell: ({ row: { original: d } }) => (
          <span className="truncate">
            {d.os || '–'}
            {d.desktop && <span className="text-muted"> · {d.desktop}</span>}
          </span>
        ),
      },
      { id: 'memory', header: t('devices.col.memory'), meta: { label: t('devices.col.memory'), className: 'text-right' }, cell: ({ row: { original: d } }) => <span className="num">{d.memory_mb ? bytes(d.memory_mb * 1024 * 1024) : '–'}</span> },
      { id: 'blueprint', header: t('devices.col.blueprint'), meta: { label: t('devices.col.blueprint') }, cell: ({ row: { original: d } }) => d.blueprint },
      { id: 'agent', header: t('devices.col.agent'), meta: { sortKey: 'agent', label: t('devices.col.agent') }, cell: ({ row: { original: d } }) => <span className="font-mono text-meta">{d.agent_version}</span> },
      {
        id: 'last_seen',
        header: t('devices.col.lastSeen'),
        meta: { sortKey: 'last_seen', label: t('devices.col.lastSeen') },
        cell: ({ row: { original: d } }) => <span className="whitespace-nowrap text-muted">{d.last_seen ? ago(d.last_seen) : t('devices.never')}</span>,
      },
    ],
    [t],
  )
}

function DeviceCard({ d }: { d: Device }) {
  const t = useT()
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-medium">{d.hostname}</span>
        <StatusPill status={d.status as DeviceStatus} />
      </div>
      <div className="flex justify-between gap-2 text-meta text-muted">
        <span className="truncate">{d.os}</span>
        <span>{d.last_seen ? ago(d.last_seen) : t('devices.never')}</span>
      </div>
    </div>
  )
}

/** The side sheet: status, facts, quick actions, failing checks, recent commands. */
function DeviceSheet({ d, onClose, onPrev, onNext }: { d: Device; onClose: () => void; onPrev?: () => void; onNext?: () => void }) {
  const t = useT()
  const detail = useDetail(d.id)
  const cmds = useTimeline(d.id, 'command', 5)
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const target = { id: d.id, hostname: d.hostname, retired: d.retired, detail: detail.data }
  const menu = useDeviceMenu(target, setDialog)
  const failing = (detail.data?.check_results ?? []).filter((c) => c.status === 'fail') as { id: string; title: string; detail?: string }[]
  return (
    <SideSheet
      title={d.hostname}
      sub={<StatusPill status={d.status as DeviceStatus} />}
      onClose={onClose}
      onPrev={onPrev}
      onNext={onNext}
      actions={
        <>
          <Link to="/devices/$id" params={{ id: d.id }} className="btn btn-primary">
            {t('devices.sheet.open')}
          </Link>
          {menu.length > 0 && (
            <ActionMenu
              trigger={
                <button type="button" className="btn" aria-label={t('devices.actionsFor', { name: d.hostname })}>
                  <MoreHorizontal size={16} aria-hidden /> {t('devices.actions')}
                </button>
              }
              items={menu}
            />
          )}
        </>
      }
    >
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-body">
        <dt className="text-muted">{t('devices.col.os')}</dt>
        <dd>{d.os || '–'}</dd>
        <dt className="text-muted">{t('devices.col.blueprint')}</dt>
        <dd>{d.blueprint}</dd>
        <dt className="text-muted">{t('devices.col.agent')}</dt>
        <dd className="font-mono">{d.agent_version}</dd>
        <dt className="text-muted">{t('devices.col.lastSeen')}</dt>
        <dd>{d.last_seen ? ago(d.last_seen) : t('devices.never')}</dd>
        <dt className="text-muted">{t('devices.fact.user')}</dt>
        <dd>{detail.data?.primary_user || '–'}</dd>
        <dt className="text-muted">{t('devices.fact.serial')}</dt>
        <dd className="font-mono">{detail.data?.inventory.serial || '–'}</dd>
      </dl>
      <h3 className="mt-5 mb-2 text-meta font-semibold text-muted">{t('devices.sheet.failing', { count: failing.length })}</h3>
      {detail.isPending ? (
        <LoadingState rows={2} />
      ) : failing.length ? (
        <ul className="flex flex-col gap-2 text-body">
          {failing.slice(0, 8).map((c) => (
            <li key={c.id} className="rounded-md border border-line p-2">
              <div className="font-medium">{c.title || c.id}</div>
              {c.detail && <div className="text-meta text-muted">{c.detail}</div>}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-body text-muted">{t('devices.sheet.allPass')}</p>
      )}
      <h3 className="mt-5 mb-2 text-meta font-semibold text-muted">{t('devices.sheet.commands')}</h3>
      <ul className="flex flex-col gap-1.5 text-body">
        {(cmds.data?.pages[0]?.items ?? []).map((c) => (
          <li key={c.id} className="flex items-center justify-between gap-2">
            <span>{t(`devices.type.${c.title}` as MessageKey)}</span>
            <span className="flex items-center gap-2 text-meta text-muted">
              <Badge tone={statusTone(c.status)}>{t(`devices.cstatus.${c.status}` as MessageKey)}</Badge>
              {ago(c.at)}
            </span>
          </li>
        ))}
        {cmds.data && !cmds.data.pages[0]?.items.length && <li className="text-muted">{t('devices.sheet.noCommands')}</li>}
      </ul>
      <DeviceDialog dialog={dialog} target={target} onClose={() => setDialog(null)} />
    </SideSheet>
  )
}

type BulkDialog = 'reboot' | 'lock' | 'script' | 'tags' | 'apps' | 'blueprint' | null

/** Actions for the selected devices; risky ones ask first, scripts may become approvals. */
function BulkBar({ ids, onClear }: { ids: string[]; onClear: () => void }) {
  const t = useT()
  const admin = useCan('admin')
  const commands = useCan('commands')
  const bulk = useBulk()
  const [dialog, setDialog] = useState<BulkDialog>(null)
  if (!commands) return null
  const send = (action: string, params?: Params) =>
    bulk.mutate(
      { ids, action, params },
      {
        onSuccess: (r) => {
          const res = r as { status: string; approvals?: number }
          toast(res.status === 'approval' ? t('devices.bulk.approvals', { count: res.approvals ?? 0 }) : t('devices.bulk.queued', { count: ids.length }))
          setDialog(null)
          onClear()
        },
        onError: (e) => toast(errorText(e), 'error'),
      },
    )
  return (
    <>
      <BulkActionBar count={ids.length} onClear={onClear}>
        <button type="button" className="btn" onClick={() => send('command:sync')}>
          <RefreshCw size={14} aria-hidden /> {t('devices.cmd.sync')}
        </button>
        <button type="button" className="btn" onClick={() => send('command:update')}>
          <Download size={14} aria-hidden /> {t('devices.cmd.update')}
        </button>
        <button type="button" className="btn" onClick={() => setDialog('reboot')}>
          <Power size={14} aria-hidden /> {t('devices.cmd.rebootNow')}
        </button>
        <button type="button" className="btn" onClick={() => setDialog('lock')}>
          <Lock size={14} aria-hidden /> {t('devices.cmd.lock')}
        </button>
        <button type="button" className="btn" onClick={() => send('command:unlock')}>
          <LockOpen size={14} aria-hidden /> {t('devices.cmd.unlock')}
        </button>
        {admin && (
          <ActionMenu
            align="start"
            trigger={
              <button type="button" className="btn">
                <MoreHorizontal size={14} aria-hidden /> {t('devices.bulk.more')}
              </button>
            }
            items={[
              { label: t('devices.bulk.agent'), icon: Bot, onClick: () => send('agent-update') },
              { label: t('devices.bulk.apps'), icon: Package, onClick: () => setDialog('apps') },
              { label: t('devices.cmd.script'), icon: FileCode2, onClick: () => setDialog('script') },
              { label: t('devices.bulk.tags'), icon: Tag, onClick: () => setDialog('tags') },
              { label: t('devices.bulk.blueprint'), icon: Layers, onClick: () => setDialog('blueprint') },
            ]}
          />
        )}
      </BulkActionBar>
      {(dialog === 'reboot' || dialog === 'lock') && (
        <Modal
          open
          onClose={() => setDialog(null)}
          title={t(dialog === 'reboot' ? 'devices.cmd.rebootNow' : 'devices.cmd.lock')}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setDialog(null)}>
                {t('common.cancel')}
              </button>
              <button type="button" className="btn btn-primary" disabled={bulk.isPending} onClick={() => send(`command:${dialog}`, dialog === 'reboot' ? { minutes: 0 } : undefined)}>
                {t(dialog === 'reboot' ? 'devices.cmd.rebootNow' : 'devices.cmd.lock')}
              </button>
            </>
          }
        >
          <p>{t(dialog === 'reboot' ? 'devices.bulk.rebootConfirm' : 'devices.bulk.lockConfirm', { count: ids.length })}</p>
        </Modal>
      )}
      {dialog === 'script' && <BulkScript count={ids.length} busy={bulk.isPending} onClose={() => setDialog(null)} onRun={(p) => send('command:script', p)} />}
      {dialog === 'tags' && <BulkTags busy={bulk.isPending} onClose={() => setDialog(null)} onRun={(op, tag) => send(op, { tag })} />}
      {dialog === 'apps' && <BulkApps busy={bulk.isPending} onClose={() => setDialog(null)} onRun={(op, app) => send(`command:${op}`, { app })} />}
      {dialog === 'blueprint' && (
        <BulkBlueprint
          ids={ids}
          onClose={() => {
            setDialog(null)
            onClear()
          }}
        />
      )}
    </>
  )
}

function BulkScript({ count, busy, onClose, onRun }: { count: number; busy: boolean; onClose: () => void; onRun: (p: Params) => void }) {
  const t = useT()
  const [v, set] = useState({ payload: '#!/bin/sh\n', params: '', timeout: '' })
  const [reason, setReason] = useState('')
  return (
    <Modal
      open
      wide
      onClose={onClose}
      title={t('devices.cmd.script')}
      description={t('devices.bulk.scriptConfirm', { count })}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="submit" form="bulk-script" className="btn btn-primary" disabled={busy || !scriptValid(v)}>
            {t('devices.f.run')}
          </button>
        </>
      }
    >
      <form id="bulk-script" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), onRun({ ...scriptParams(v), ...(reason ? { reason } : {}) }))}>
        <ScriptFields v={v} set={set} />
        <Field label={t('devices.f.reason')} help={t('devices.f.reasonHelp')}>
          {({ id, describedBy }) => <input id={id} className="field" aria-describedby={describedBy} value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </form>
    </Modal>
  )
}

function BulkTags({ busy, onClose, onRun }: { busy: boolean; onClose: () => void; onRun: (op: 'tag-add' | 'tag-remove', tag: string) => void }) {
  const t = useT()
  const [tag, setTag] = useState('')
  const ok = /^[a-z0-9._-]{1,32}$/.test(tag.trim().toLowerCase())
  return (
    <Modal
      open
      onClose={onClose}
      title={t('devices.bulk.tags')}
      footer={
        <>
          <button type="button" className="btn" onClick={() => onRun('tag-remove', tag.trim())} disabled={busy || !ok}>
            {t('devices.bulk.tagRemove')}
          </button>
          <button type="button" className="btn btn-primary" onClick={() => onRun('tag-add', tag.trim())} disabled={busy || !ok}>
            {t('devices.bulk.tagAdd')}
          </button>
        </>
      }
    >
      <Field label={t('devices.bulk.tag')} help={t('devices.bulk.tagHelp')}>
        {({ id, describedBy }) => <input id={id} className="field font-mono" aria-describedby={describedBy} value={tag} maxLength={32} onChange={(e) => setTag(e.target.value)} autoFocus />}
      </Field>
    </Modal>
  )
}

function BulkApps({ busy, onClose, onRun }: { busy: boolean; onClose: () => void; onRun: (op: 'app_install' | 'app_remove', app: string) => void }) {
  const t = useT()
  const apps = useCatalogApps(true)
  const [app, setApp] = useState('')
  const value = app || apps.data?.[0]?.id || ''
  return (
    <Modal
      open
      onClose={onClose}
      title={t('devices.bulk.apps')}
      footer={
        <>
          <button type="button" className="btn" onClick={() => onRun('app_remove', value)} disabled={busy || !value}>
            {t('devices.sw.remove')}
          </button>
          <button type="button" className="btn btn-primary" onClick={() => onRun('app_install', value)} disabled={busy || !value}>
            {t('devices.sw.install')}
          </button>
        </>
      }
    >
      <Field label={t('devices.bulk.app')}>
        {({ id }) => (
          <select id={id} className="field" value={value} onChange={(e) => setApp(e.target.value)}>
            {(apps.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        )}
      </Field>
      {apps.data && !apps.data.length && <EmptyState compact icon={Package} title={t('devices.bulk.noApps')} action={<Link className="btn" to="/config" search={{ tab: 'software' }}>{t('devices.sw.manageCatalog')}</Link>} />}
    </Modal>
  )
}

/** Assigns a blueprint to every selected device (PATCH each, as the details dialog does). */
function BulkBlueprint({ ids, onClose }: { ids: string[]; onClose: () => void }) {
  const t = useT()
  const patch = usePatch()
  const [bp, setBp] = useState('0')
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    let failed = 0
    for (const id of ids) {
      try {
        await patch.mutateAsync({ id, body: { blueprint_id: Number(bp) > 0 ? Number(bp) : null } })
      } catch {
        failed++
      }
    }
    setBusy(false)
    toast(failed ? t('devices.bulk.blueprintFailed', { count: failed }) : t('devices.bulk.blueprintDone', { count: ids.length }), failed ? 'error' : 'ok')
    onClose()
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={t('devices.bulk.blueprint')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void run()} disabled={busy}>
            {t('devices.bulk.assign')}
          </button>
        </>
      }
    >
      <Field label={t('devices.edit.blueprint')}>
        {({ id }) => <BlueprintSelect id={id} value={Number(bp)} onChange={(v) => setBp(String(v))} noneLabel={t('devices.bulk.defaultBlueprint')} />}
      </Field>
    </Modal>
  )
}
