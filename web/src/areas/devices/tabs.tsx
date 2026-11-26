// Software, inventory and activity tabs of the device page.
import { Link } from '@tanstack/react-router'
import { Download, FileCode2, KeyRound, MoreHorizontal, Network as NetworkIcon, Package, Plus, ScrollText, ShieldCheck, Terminal, Activity as ActivityIcon, Search } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { api, unwrap } from '../../api/client'
import { useCan } from '../../api/me'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { ScrollHint } from '../../components/layout'
import { Field } from '../../components/form'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { Timeline, type TimelineItem } from '../../components/timeline'
import { toast } from '../../components/toast'
import { ActionMenu, Badge, Card, Segmented, Switch, type MenuEntry } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateTime, fmt } from '../../i18n/format'
import { useQueryClient } from '@tanstack/react-query'
import { useRun, type Dialog } from './actions'
import { usePackages, useTimeline, type DeviceDetail, type Params, type TimelineEntry } from './api'
import { accountActionable, checkTone, filterByName, statusTone, usedPct } from './logic'

type Col = { label: ReactNode; className?: string }

/** A plain table of a card; rows are cells. */
function Table({ caption, cols, rows, empty }: { caption: string; cols: Col[]; rows: { key: string; cells: ReactNode[] }[]; empty: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-body">
        <caption className="sr-only">{caption}</caption>
        <thead className="text-meta text-muted">
          <tr>
            {cols.map((c, i) => (
              <th key={i} scope="col" className={'py-1.5 pr-3 font-medium ' + (c.className ?? '')}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((r) => (
              <tr key={r.key} className="border-t border-line align-top">
                {r.cells.map((c, i) => (
                  <td key={i} className={'py-1.5 pr-3 ' + (cols[i]?.className ?? '')}>
                    {c}
                  </td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={cols.length}>
                <EmptyState compact title={empty} />
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function SubTabs({ subs, value, onChange, label }: { subs: { value: string; label: string; count?: number }[]; value: string; onChange: (v: string) => void; label: string }) {
  return (
    <ScrollHint>
      <Segmented label={label} value={value} onChange={onChange} options={subs.map((s) => ({ value: s.value, label: s.count != null ? `${s.label} ${fmt(s.count)}` : s.label }))} />
    </ScrollHint>
  )
}

const mono = (v?: string | number) => <span className="font-mono text-meta">{v ?? ''}</span>

// ---- software ----

export function SoftwareTab({ d, sub, setSub, open }: { d: DeviceDetail; sub?: string; setSub: (s: string) => void; open: (x: Dialog) => void }) {
  const t = useT()
  const inv = d.inventory
  const value = ['packages', 'sources', 'apps', 'catalog', 'requests'].includes(sub ?? '') ? (sub as string) : 'packages'
  void open
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <SubTabs
        label={t('devices.tab.software')}
        value={value}
        onChange={setSub}
        subs={[
          { value: 'packages', label: t('devices.sw.packages'), count: d.package_count },
          { value: 'sources', label: t('devices.sw.sources'), count: inv.repos?.length ?? 0 },
          { value: 'apps', label: t('devices.sw.apps'), count: (inv.flatpaks?.length ?? 0) + (inv.snaps?.length ?? 0) + (inv.appimages?.length ?? 0) },
          { value: 'catalog', label: t('devices.sw.catalog'), count: inv.apps?.length ?? 0 },
          { value: 'requests', label: t('devices.sw.requests'), count: d.catalog_requests.filter((r) => r.status === 'pending').length },
        ]}
      />
      {value === 'packages' && <Packages d={d} />}
      {value === 'sources' && <Sources d={d} />}
      {value === 'apps' && <Apps d={d} />}
      {value === 'catalog' && <Catalog d={d} />}
      {value === 'requests' && <Requests d={d} />}
    </div>
  )
}

/** A removal command asked for in the app's dialog first; render dialog once. */
function useRemove(d: DeviceDetail) {
  const { run } = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const t = useT()
  const [ask, setAsk] = useState<{ text: string; type: string; params: Params }>()
  return {
    ask: (text: string, type: string, params: Params) => setAsk({ text, type, params }),
    remove: (kind: string, name: string, installation?: string) => setAsk({ text: t('devices.sw.removeConfirm', { name }), type: 'software_remove', params: { kind, name, ...(installation ? { installation } : {}) } }),
    dialog: (
      <Confirm
        open={!!ask}
        onClose={() => setAsk(undefined)}
        title={ask?.text ?? ''}
        body={d.hostname}
        confirm={t('devices.sw.remove')}
        danger
        onConfirm={() => {
          if (ask) run(ask.type, ask.params)
          setAsk(undefined)
        }}
      />
    ),
  }
}

function Packages({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const pk = usePackages(d.id)
  const [q, setQ] = useState('')
  const { remove, dialog } = useRemove(d)
  const rows = useMemo(() => filterByName(pk.data ?? [], q), [pk.data, q])
  const columns = useMemo<GridColumn<{ name: string; version: string; arch: string }>[]>(
    () => [
      { id: 'name', header: t('devices.sw.package'), cell: ({ row }) => mono(row.original.name) },
      { id: 'version', header: t('devices.sw.version'), cell: ({ row }) => mono(row.original.version) },
      { id: 'arch', header: t('devices.sw.arch'), cell: ({ row }) => row.original.arch },
      ...(admin && !d.retired
        ? [
            {
              id: 'act',
              header: '',
              meta: { className: 'text-right' },
              cell: ({ row }: { row: { original: { name: string } } }) => (
                <button type="button" className="btn btn-ghost !h-7 text-meta" onClick={() => remove('package', row.original.name)}>
                  {t('devices.sw.remove')}
                </button>
              ),
            } as GridColumn<{ name: string; version: string; arch: string }>,
          ]
        : []),
    ],
    [t, admin, d.retired, remove],
  )
  if (pk.error) return <ErrorState error={pk.error} onRetry={() => void pk.refetch()} />
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t('devices.sw.filter')}>
          {({ id }) => <input id={id} type="search" className="field !h-9 w-72" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('devices.sw.filterPlaceholder')} />}
        </Field>
        <span className="pb-2 text-body text-muted">{t('devices.sw.shown', { shown: fmt(rows.length), total: fmt(pk.data?.length ?? 0) })}</span>
        <Link to="/devices" search={{ q: q ? `pkg:${q}` : '' }} className="btn ml-auto">
          <Search size={14} aria-hidden /> {t('devices.sw.fleet')}
        </Link>
      </div>
      {pk.isPending ? <LoadingState /> : <DataGrid label={t('devices.sw.packages')} data={rows} columns={columns} getRowId={(r) => `${r.name}:${r.arch}`} maxHeight="60dvh" empty={t('devices.sw.noPackages')} />}
      {dialog}
    </div>
  )
}

function Sources({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const repos = d.inventory.repos ?? []
  return (
    <Card title={t('devices.sw.sources')} sub={t('devices.sw.sourcesSub', { count: repos.length })} id="dv-src">
      <Table
        caption={t('devices.sw.sources')}
        empty={t('devices.sw.noSources')}
        cols={[{ label: t('devices.sw.source') }, { label: 'URL' }, { label: t('devices.sw.suites') }, { label: t('devices.sw.state') }, { label: t('devices.sw.signature') }, ...(admin ? [{ label: '' }] : [])]}
        rows={repos.map((r) => ({
          key: r.file + r.name,
          cells: [
            <>
              {r.name}
              <span className="block font-mono text-micro text-muted">{r.file}</span>
            </>,
            mono(r.url),
            <>
              {r.suites} <span className="text-muted">{r.components}</span>
            </>,
            <Badge tone={r.enabled ? 'ok' : 'off'}>{t(r.enabled ? 'devices.sw.enabled' : 'devices.sw.disabled')}</Badge>,
            <Badge tone={r.signed ? 'ok' : 'warn'}>{t(r.signed ? 'devices.sw.pinned' : 'devices.sw.globalKey')}</Badge>,
            ...(admin
              ? [
                  r.name.startsWith('limdm-') ? (
                    <span className="text-muted">{t('devices.sw.managed')}</span>
                  ) : (
                    <span className="flex gap-3">
                      <Link to="/config/library/$id" params={{ id: 'new' }} search={{ device: d.id, file: r.file, mode: 'edit' }}>
                        {t('devices.sw.edit')}
                      </Link>
                      <Link to="/config/library/$id" params={{ id: 'new' }} search={{ device: d.id, file: r.file, mode: 'disable' }}>
                        {t('devices.sw.disable')}
                      </Link>
                    </span>
                  ),
                ]
              : []),
          ],
        }))}
      />
    </Card>
  )
}

function Apps({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin') && !d.retired
  const qc = useQueryClient()
  const inv = d.inventory
  const { remove, dialog } = useRemove(d)
  const rm = (kind: string, name: string, inst?: string) => (
    <button type="button" className="btn btn-ghost !h-7 text-meta" onClick={() => remove(kind, name, inst)}>
      {t('devices.sw.remove')}
    </button>
  )
  const inst = (i: string) => (i === 'system' ? t('devices.sw.system') : <Badge>{i}</Badge>)
  const addToCatalog = (flatpak: string) =>
    unwrap(api.POST('/api/v1/software/import', { body: { flatpaks: [flatpak] } }))
      .then(() => (toast(t('devices.sw.added')), void qc.invalidateQueries({ queryKey: ['devices'] })))
      .catch((e: unknown) => toast(errorText(e), 'error'))
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      {dialog}
      <Card title={t('devices.sw.remotes')} id="dv-rem" action={admin ? <Link className="btn" to="/config/library/$id" params={{ id: 'new' }} search={{ type: 'com.limdm.flatpak' }}>
              {t('devices.sw.addRemote')}
            </Link> : undefined}>
        <Table
          caption={t('devices.sw.remotes')}
          empty={t('devices.sw.noRemotes')}
          cols={[{ label: t('devices.sw.remote') }, { label: 'URL' }, { label: t('devices.sw.installation') }, { label: t('devices.sw.state') }, ...(admin ? [{ label: '' }] : [])]}
          rows={(inv.flatpak_remotes ?? []).map((r) => ({
            key: r.installation + r.name,
            cells: [
              <>
                {r.name}
                {r.title && <span className="block text-meta text-muted">{r.title}</span>}
              </>,
              mono(r.url),
              inst(r.installation),
              <Badge tone={r.disabled ? 'off' : 'ok'}>{t(r.disabled ? 'devices.sw.disabled' : 'devices.sw.enabled')}</Badge>,
              ...(admin
                ? [
                    <span className="flex gap-3">
                      <Link to="/config/library/$id" params={{ id: 'new' }} search={{ device: d.id, remote: r.name, inst: r.installation, mode: 'edit' }}>
                        {t('devices.sw.edit')}
                      </Link>
                      <Link to="/config/library/$id" params={{ id: 'new' }} search={{ device: d.id, remote: r.name, inst: r.installation, mode: r.disabled ? 'enable' : 'disable' }}>
                        {t(r.disabled ? 'devices.sw.enable' : 'devices.sw.disable')}
                      </Link>
                    </span>,
                  ]
                : []),
            ],
          }))}
        />
      </Card>
      <Card title={t('devices.sw.flatpaks')} sub={fmt(inv.flatpaks?.length ?? 0)} id="dv-fp">
        <Table
          caption={t('devices.sw.flatpaks')}
          empty={t('devices.sw.noFlatpaks')}
          cols={[{ label: t('devices.sw.app') }, { label: t('devices.sw.version') }, { label: t('devices.sw.branch') }, { label: t('devices.sw.remote') }, { label: t('devices.sw.installation') }, { label: t('devices.sw.catalog') }, ...(admin ? [{ label: '' }] : [])]}
          rows={(inv.flatpaks ?? []).map((f) => ({
            key: f.installation + f.id,
            cells: [
              <>
                {f.name || f.id}
                <span className="block font-mono text-micro text-muted">{f.id}</span>
              </>,
              f.version,
              mono(f.branch),
              f.origin,
              inst(f.installation),
              d.catalog_flatpaks[f.id] ? (
                <Link to="/config/software/$id" params={{ id: d.catalog_flatpaks[f.id] }}>
                  {t('devices.sw.inCatalog')}
                </Link>
              ) : admin ? (
                <button type="button" className="btn btn-ghost !h-7 text-meta" onClick={() => void addToCatalog(f.id)}>
                  <Plus size={13} aria-hidden /> {t('devices.sw.addToCatalog')}
                </button>
              ) : (
                '–'
              ),
              ...(admin ? [rm('flatpak', f.id, f.installation)] : []),
            ],
          }))}
        />
      </Card>
      <Card title={t('devices.sw.snaps')} sub={fmt(inv.snaps?.length ?? 0)} id="dv-snap">
        <Table
          caption={t('devices.sw.snaps')}
          empty={t('devices.sw.noSnaps')}
          cols={[{ label: 'Snap' }, { label: t('devices.sw.version') }, { label: t('devices.sw.publisher') }, { label: t('devices.sw.notes') }, ...(admin ? [{ label: '' }] : [])]}
          rows={(inv.snaps ?? []).map((s) => ({
            key: s.name,
            cells: [mono(s.name), mono(s.version), s.publisher, <span className="text-muted">{s.notes}</span>, ...(admin ? [['base', 'snapd', 'core'].includes(s.notes) ? <span className="text-muted">{t('devices.sw.system')}</span> : rm('snap', s.name)] : [])],
          }))}
        />
      </Card>
      <Card title={t('devices.sw.appimages')} sub={fmt(inv.appimages?.length ?? 0)} id="dv-ai">
        <Table
          caption={t('devices.sw.appimages')}
          empty={t('devices.sw.noAppimages')}
          cols={[{ label: t('devices.sw.file') }, { label: t('devices.sw.owner') }, { label: t('devices.sw.size'), className: 'text-right' }, ...(admin ? [{ label: '' }] : [])]}
          rows={(inv.appimages ?? []).map((a) => ({ key: a.path, cells: [mono(a.path), a.owner, `${fmt(a.size_mb)} MB`, ...(admin ? [rm('appimage', a.path)] : [])] }))}
        />
      </Card>
    </div>
  )
}

function Catalog({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin') && !d.retired
  const { run, pending } = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const { ask, dialog } = useRemove(d)
  const apps = d.inventory.apps ?? []
  return (
    <div className="flex flex-col gap-3">
      {dialog}
      {d.app_notes.map((n) => (
        <div key={n.app + n.at} role="status" className={'rounded-lg border px-4 py-2 text-body ' + (n.ok ? 'border-ok/30 bg-ok-soft' : 'border-bad/30 bg-bad-soft')}>
          <strong>{n.app}</strong>{' '}
          {n.ok ? t(n.type === 'install' ? 'devices.sw.noteInstalled' : 'devices.sw.noteRemoved') : t(n.type === 'install' ? 'devices.sw.noteInstallFailed' : 'devices.sw.noteRemoveFailed', { error: n.error ?? '' })} <span className="text-muted">{dateTime(n.at)}</span>
        </div>
      ))}
      <Card title={t('devices.sw.catalogTitle')} id="dv-cat" action={<Link className="btn" to="/config" search={{ tab: 'software' }}>
                {t('devices.sw.manageCatalog')}
              </Link>}>
        <Table
          caption={t('devices.sw.catalogTitle')}
          empty={t('devices.sw.noCatalog')}
          cols={[{ label: t('devices.sw.app') }, { label: t('devices.sw.state') }, { label: t('devices.sw.via') }, { label: t('devices.sw.lastError') }, ...(admin ? [{ label: '' }] : [])]}
          rows={apps.map((a) => {
            const busy = d.app_busy[a.id]
            return {
              key: a.id,
              cells: [
                d.app_names[a.id] ?? a.id,
                <Badge tone={a.installed ? 'ok' : 'off'}>{t(a.installed ? 'devices.sw.installed' : 'devices.sw.notInstalled')}</Badge>,
                a.via === 'flatpak' ? 'Flatpak' : a.via === 'package' ? t('devices.sw.systemPackage') : '',
                <span className="text-muted">{a.error}</span>,
                ...(admin
                  ? [
                      busy ? (
                        <span role="status" className="text-muted">
                          {t(busy === 'install' ? 'devices.sw.installing' : 'devices.sw.removing')}
                        </span>
                      ) : a.installed ? (
                        <button type="button" className="btn !h-7 text-meta" disabled={pending} onClick={() => ask(t('devices.sw.removeAppConfirm'), 'app_remove', { app: a.id })}>
                          {t('devices.sw.remove')}
                        </button>
                      ) : (
                        <button type="button" className="btn btn-primary !h-7 text-meta" disabled={pending} onClick={() => run('app_install', { app: a.id })}>
                          {t('devices.sw.install')}
                        </button>
                      ),
                    ]
                  : []),
              ],
            }
          })}
        />
      </Card>
    </div>
  )
}

function Requests({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const qc = useQueryClient()
  const decide = (id: number, op: 'approve' | 'deny') =>
    unwrap(api.POST('/api/v1/software/requests/{id}/{op}', { params: { path: { id, op } } }))
      .then(() => (toast(t('devices.sw.decided')), void qc.invalidateQueries({ queryKey: ['devices'] })))
      .catch((e: unknown) => toast(errorText(e), 'error'))
  return (
    <Card title={t('devices.sw.requests')} sub={t('devices.sw.requestsSub')} id="dv-req">
      <Table
        caption={t('devices.sw.requests')}
        empty={t('devices.sw.noRequests')}
        cols={[{ label: t('devices.sw.app') }, { label: t('devices.sw.user') }, { label: t('devices.sw.note') }, { label: t('devices.sw.state') }, { label: t('devices.sw.when') }, ...(admin ? [{ label: '' }] : [])]}
        rows={d.catalog_requests.map((r) => ({
          key: String(r.id),
          cells: [
            r.name,
            r.username,
            <span className="text-muted">{r.note}</span>,
            <Badge tone={r.status === 'approved' ? 'ok' : r.status === 'denied' ? 'bad' : 'warn'}>{t(`devices.req.${r.status}` as MessageKey)}</Badge>,
            <span className="whitespace-nowrap">{ago(r.created_at)}</span>,
            ...(admin
              ? [
                  r.status === 'pending' ? (
                    <span className="flex gap-2">
                      <button type="button" className="btn btn-primary !h-7 text-meta" onClick={() => void decide(r.id, 'approve')}>
                        {t('devices.sw.approve')}
                      </button>
                      <button type="button" className="btn !h-7 text-meta" onClick={() => void decide(r.id, 'deny')}>
                        {t('devices.sw.deny')}
                      </button>
                    </span>
                  ) : (
                    <span className="text-meta text-muted">{r.decided_by}</span>
                  ),
                ]
              : []),
          ],
        }))}
      />
    </Card>
  )
}

// ---- inventory ----

export function InventoryTab({ d, sub, setSub, open }: { d: DeviceDetail; sub?: string; setSub: (s: string) => void; open: (x: Dialog) => void }) {
  const t = useT()
  const value = ['hardware', 'disks', 'network', 'accounts'].includes(sub ?? '') ? (sub as string) : 'hardware'
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <SubTabs
        label={t('devices.tab.inventory')}
        value={value}
        onChange={setSub}
        subs={[
          { value: 'hardware', label: t('devices.inv.hardware') },
          { value: 'disks', label: t('devices.inv.disks') },
          { value: 'network', label: t('devices.inv.network') },
          { value: 'accounts', label: t('devices.inv.accounts') },
        ]}
      />
      {value === 'hardware' && <Hardware d={d} />}
      {value === 'disks' && <Disks d={d} open={open} />}
      {value === 'network' && <Network d={d} />}
      {value === 'accounts' && <Accounts d={d} open={open} />}
    </div>
  )
}

function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-body">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v || '–'}</dd>
        </div>
      ))}
    </dl>
  )
}

function Hardware({ d }: { d: DeviceDetail }) {
  const t = useT()
  const inv = d.inventory
  const tpm = inv.tpm
  return (
    <div className="grid gap-[var(--gap)] lg:grid-cols-2">
      <Card title={t('devices.inv.board')} id="dv-board">
        <KV
          rows={[
            [t('devices.inv.vendor'), inv.vendor],
            [t('devices.fact.model'), inv.model],
            [t('devices.fact.serial'), mono(inv.serial)],
            [t('devices.inv.firmware'), [inv.bios_vendor, inv.bios_version].filter(Boolean).join(' ')],
            [
              'TPM',
              tpm ? (
                tpm.present ? (
                  <>
                    {tpm.version}
                    {(tpm.luks_bound ?? []).map((l) => (
                      <span key={l} className="block font-mono text-meta">
                        {t('devices.inv.tpmBound', { dev: l })}
                      </span>
                    ))}
                  </>
                ) : (
                  t('devices.sys.none')
                )
              ) : (
                ''
              ),
            ],
          ]}
        />
      </Card>
      <Card title={t('devices.inv.cpuMem')} id="dv-cpu">
        <KV
          rows={[
            [t('devices.sys.cpu'), inv.cpu],
            [t('devices.inv.coresThreads'), inv.cpu_cores ? `${inv.cpu_cores} / ${inv.cpu_threads}` : ''],
            [t('devices.sys.memory'), inv.memory_mb ? `${fmt(Math.round(inv.memory_mb / 102.4) / 10)} GiB` : ''],
            [t('devices.inv.swap'), inv.swap_mb ? `${fmt(Math.round(inv.swap_mb / 102.4) / 10)} GiB` : ''],
          ]}
        />
      </Card>
    </div>
  )
}

function Disks({ d, open }: { d: DeviceDetail; open: (x: Dialog) => void }) {
  const t = useT()
  const helpdesk = useCan('commands')
  const inv = d.inventory
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card title={t('devices.inv.disks')} id="dv-disks">
        <Table
          caption={t('devices.inv.disks')}
          empty={t('devices.inv.noDisks')}
          cols={[{ label: t('devices.inv.device') }, { label: t('devices.fact.model') }, { label: t('devices.inv.type') }, { label: t('devices.sw.size'), className: 'text-right' }]}
          rows={(inv.disks ?? []).map((x) => ({ key: x.name, cells: [mono(x.name), x.model, x.type, `${fmt(x.size_gb)} GB`] }))}
        />
      </Card>
      <Card title={t('devices.inv.volumes')} id="dv-vols">
        <Table
          caption={t('devices.inv.volumes')}
          empty={t('devices.inv.noVolumes')}
          cols={[{ label: t('devices.inv.mount') }, { label: t('devices.inv.device') }, { label: t('devices.inv.fs') }, { label: t('devices.inv.encryption') }, { label: t('devices.inv.usage') }]}
          rows={(inv.volumes ?? []).map((v) => ({
            key: v.mount + v.device,
            cells: [
              mono(v.mount),
              mono(v.device),
              v.fs,
              v.encrypted ? <Badge tone="ok">{v.encryption || t('devices.inv.encrypted')}</Badge> : d.encryption_exempt.includes(v.mount) ? <Badge>{t('devices.inv.excluded')}</Badge> : <Badge tone="bad">{t('devices.sys.none')}</Badge>,
              <span className="flex items-center gap-2 whitespace-nowrap">
                <meter min={0} max={100} low={80} high={90} optimum={0} value={usedPct(v.size_gb, v.free_gb)} aria-label={t('devices.inv.usage')} />
                <span className="text-meta text-muted">{t('devices.inv.usageVal', { used: fmt(v.size_gb - v.free_gb), size: fmt(v.size_gb) })}</span>
              </span>,
            ],
          }))}
        />
      </Card>
      <Card title={t('devices.rec.title')} sub={t('devices.rec.sub')} id="dv-rec">
        <Table
          caption={t('devices.rec.title')}
          empty={t('devices.rec.none')}
          cols={[{ label: t('devices.inv.device') }, { label: t('devices.rec.uuid') }, { label: t('devices.rec.escrowed') }, { label: t('devices.rec.viewed') }, ...(helpdesk ? [{ label: '' }] : [])]}
          rows={d.recovery_keys.map((k) => ({
            key: k.uuid,
            cells: [
              mono(k.device),
              mono(k.uuid),
              dateTime(k.escrowed),
              k.viewed_at ? (
                <>
                  {dateTime(k.viewed_at)}
                  {k.viewed_by && ` · ${k.viewed_by}`} {k.rotate && <Badge tone="warn">{t('devices.rec.rotation')}</Badge>}
                </>
              ) : (
                <span className="text-muted">{t('devices.rec.never')}</span>
              ),
              ...(helpdesk
                ? [
                    <button type="button" className="btn !h-7 text-meta" onClick={() => open({ kind: 'recovery', uuid: k.uuid, path: k.device })}>
                      <KeyRound size={13} aria-hidden /> {t('devices.rec.show')}
                    </button>,
                  ]
                : []),
            ],
          }))}
        />
      </Card>
    </div>
  )
}

function Network({ d }: { d: DeviceDetail }) {
  const t = useT()
  const inv = d.inventory
  const audit = useCan('audit')
  const tags = (l?: string[]) => (l ?? []).map((x) => <Badge key={x}>{x}</Badge>)
  const routes = inv.routes ?? []
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      {!(inv.interfaces ?? []).some((i) => i.ips?.length) && !(inv.dns ?? []).length && <EmptyState compact icon={NetworkIcon} title={t('devices.net.noInfo')} />}
      {d.external_ip && (
        <Card title={t('devices.net.public')} sub={t('devices.net.publicSub')} id="dv-pub">
          <KV
            rows={[
              [t('devices.net.address'), mono(d.external_ip)],
              [t('devices.net.location'), d.place],
              [t('devices.net.provider'), d.geo ? `${String(d.geo.isp ?? '')}${d.geo.asn ? ` AS${String(d.geo.asn)}` : ''}` : ''],
            ]}
          />
        </Card>
      )}
      <Card title={t('devices.net.interfaces')} id="dv-if">
        <Table
          caption={t('devices.net.interfaces')}
          empty={t('devices.net.noInterfaces')}
          cols={[{ label: t('devices.net.interface') }, { label: t('devices.inv.type') }, { label: t('devices.sw.state') }, { label: t('devices.net.addresses') }, { label: 'MAC' }, { label: 'MTU', className: 'text-right' }]}
          rows={(inv.interfaces ?? []).map((i) => ({
            key: i.name,
            cells: [
              <>
                {mono(i.name)} {i.vpn && <Badge tone="accent">{i.vpn}</Badge>}
              </>,
              i.kind,
              i.state ? <Badge tone={i.state === 'up' ? 'ok' : 'off'}>{i.state}</Badge> : '',
              <span className="flex flex-wrap gap-1">{tags(i.ips)}</span>,
              mono(i.mac),
              i.mtu ? fmt(i.mtu) : '',
            ],
          }))}
        />
      </Card>
      <Card title="VPN" sub={t('devices.net.vpnSub')} id="dv-vpn">
        <Table
          caption="VPN"
          empty={t('devices.net.noVpn')}
          cols={[{ label: t('devices.net.client') }, { label: t('devices.net.service') }, { label: t('devices.net.interface') }, { label: t('devices.sw.state') }]}
          rows={(inv.vpns ?? []).map((v) => ({ key: v.name + v.service, cells: [v.name, mono(v.service), mono(v.interface), <Badge tone={v.active ? 'ok' : 'off'}>{t(v.active ? 'devices.net.active' : 'devices.net.inactive')}</Badge>] }))}
        />
      </Card>
      {(inv.wireguard_keys ?? []).length > 0 && (
        <Card title={t('devices.net.wg')} sub={t('devices.net.wgSub')} id="dv-wg">
          <Table
            caption={t('devices.net.wg')}
            empty=""
            cols={[{ label: t('devices.net.profile') }, { label: t('devices.net.interface') }, { label: t('devices.net.publicKey') }]}
            rows={(inv.wireguard_keys ?? []).map((k) => ({ key: k.profile + k.interface, cells: [k.profile, mono(k.interface), mono(k.public_key)] }))}
          />
        </Card>
      )}
      {d.network_certs.length > 0 && (
        <Card title={t('devices.net.certs')} id="dv-nc" action={audit ? <Link to="/settings" search={{ s: 'network', sel: undefined }}>
                {t('devices.net.ca')}
              </Link> : undefined}>
          <Table
            caption={t('devices.net.certs')}
            empty=""
            cols={[{ label: t('devices.fact.serial') }, { label: t('devices.net.sans') }, { label: t('devices.net.issued') }, { label: t('devices.net.expires') }, { label: t('devices.sw.state') }]}
            rows={d.network_certs.map((c) => ({
              key: c.serial,
              cells: [
                mono(c.serial),
                mono(c.sans),
                dateTime(c.not_before),
                dateTime(c.not_after),
                <>
                  <Badge tone={c.state === 'valid' ? 'ok' : c.state === 'revoked' ? 'bad' : 'off'}>{t(`devices.nc.${c.state}` as MessageKey)}</Badge>
                  {c.reason && <span className="block text-meta text-muted">{c.reason}</span>}
                </>,
              ],
            }))}
          />
        </Card>
      )}
      <div className="grid gap-[var(--gap)] lg:grid-cols-2">
        <Card title="DNS" id="dv-dns">
          <Table caption="DNS" empty={t('devices.net.notCollected')} cols={[{ label: t('devices.net.scope') }, { label: t('devices.net.servers') }, { label: t('devices.net.domains') }]} rows={(inv.dns ?? []).map((x) => ({ key: x.scope, cells: [mono(x.scope), <span className="flex flex-wrap gap-1">{tags(x.servers)}</span>, <span className="flex flex-wrap gap-1">{tags(x.domains)}</span>] }))} />
        </Card>
        <Card title={t('devices.net.gateways')} id="dv-gw">
          <Table
            caption={t('devices.net.gateways')}
            empty={t('devices.net.notCollected')}
            cols={[{ label: t('devices.net.family') }, { label: t('devices.net.gateway') }, { label: t('devices.net.interface') }, { label: t('devices.net.metric'), className: 'text-right' }]}
            rows={routes
              .filter((r) => r.dst === 'default')
              .map((r, i) => ({ key: String(i), cells: [r.family === 'inet6' ? 'IPv6' : 'IPv4', mono(r.gateway), mono(r.dev), r.metric ?? ''] }))}
          />
        </Card>
      </div>
      <Card title={t('devices.net.routes')} sub={fmt(routes.length)} id="dv-rt">
        <Table
          caption={t('devices.net.routes')}
          empty={t('devices.net.notCollected')}
          cols={[{ label: t('devices.net.dest') }, { label: t('devices.net.gateway') }, { label: t('devices.net.interface') }, { label: t('devices.net.proto') }, { label: t('devices.net.metric'), className: 'text-right' }]}
          rows={routes.map((r, i) => ({ key: String(i), cells: [mono(r.dst), mono(r.gateway), mono(r.dev), <span className="text-muted">{r.proto}</span>, r.metric || ''] }))}
        />
      </Card>
    </div>
  )
}

function Accounts({ d, open }: { d: DeviceDetail; open: (x: Dialog) => void }) {
  const t = useT()
  const admin = useCan('admin')
  const hd = useCan('commands') && !d.retired
  const [system, setSystem] = useState(false)
  const [groups, setGroups] = useState(false)
  const { run } = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const inv = d.inventory
  const ask = (type: string, user: string, title: MessageKey, body: MessageKey, extra: Record<string, boolean> = {}) => open({ kind: 'confirm', type, params: { username: user, ...extra }, title, body, danger: type === 'user_delete' })
  const menu = (a: { name: string; admin: boolean }): MenuEntry[] =>
    ([
      admin && (a.admin ? { label: t('devices.acc.revokeAdmin'), onClick: () => run('user_admin', { username: a.name }) } : { label: t('devices.acc.makeAdmin'), onClick: () => ask('user_admin', a.name, 'devices.acc.makeAdmin', 'devices.acc.makeAdminConfirm', { admin: true }) }),
      { label: t('devices.acc.lock'), onClick: () => ask('user_lock', a.name, 'devices.acc.lock', 'devices.acc.lockConfirm') },
      { label: t('devices.acc.unlock'), onClick: () => run('user_unlock', { username: a.name }) },
      { label: t('devices.acc.password'), onClick: () => open({ kind: 'user-password', user: a.name }) },
      admin && { label: t('devices.acc.delete'), danger: true, onClick: () => ask('user_delete', a.name, 'devices.acc.delete', 'devices.acc.deleteConfirm') },
    ] as (MenuEntry | false)[]).filter((x): x is MenuEntry => !!x)
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-4">
        <Segmented
          label={t('devices.inv.accounts')}
          value={groups ? 'groups' : 'users'}
          onChange={(v) => setGroups(v === 'groups')}
          options={[
            { value: 'users', label: t('devices.acc.users') },
            { value: 'groups', label: t('devices.acc.groups') },
          ]}
        />
        <label className="flex items-center gap-2 text-body" htmlFor="acc-sys">
          <Switch id="acc-sys" checked={system} onChange={setSystem} label={t('devices.acc.showSystem')} /> {t('devices.acc.showSystem')}
        </label>
        <span className="flex-1" />
        {admin && !d.retired && !groups && (
          <button type="button" className="btn btn-primary" onClick={() => open({ kind: 'user-create' })}>
            <Plus size={14} aria-hidden /> {t('devices.user.create')}
          </button>
        )}
      </div>
      <p className="text-meta text-muted">{t('devices.acc.nss')}</p>
      <div className="card p-[var(--pad-card)]">
        {groups ? (
          <Table
            caption={t('devices.acc.groups')}
            empty={t('devices.acc.none')}
            cols={[{ label: t('devices.acc.group') }, { label: 'GID', className: 'text-right' }, { label: t('devices.acc.members') }, { label: t('devices.acc.source') }]}
            rows={(inv.groups ?? [])
              .filter((g) => system || !g.system || g.members?.length)
              .map((g) => ({
                key: g.name,
                cells: [
                  <>
                    {mono(g.name)} {g.system && <Badge>{t('devices.sw.system')}</Badge>}
                  </>,
                  g.gid,
                  <span className="flex flex-wrap gap-1">
                    {(g.members ?? []).map((m) => (
                      <Badge key={m}>{m}</Badge>
                    ))}
                  </span>,
                  g.source === 'local' ? t('devices.acc.local') : <Badge tone="accent">{t('devices.acc.directory')}</Badge>,
                ],
              }))}
          />
        ) : (
          <Table
            caption={t('devices.acc.users')}
            empty={t('devices.acc.none')}
            cols={[{ label: t('devices.acc.account') }, { label: 'UID', className: 'text-right' }, { label: t('devices.acc.name') }, { label: t('devices.acc.home') }, { label: t('devices.acc.shell') }, { label: t('devices.acc.source') }, { label: t('devices.acc.rights') }, { label: 'SSO' }, ...(hd ? [{ label: '' }] : [])]}
            rows={(inv.accounts ?? [])
              .filter((a) => system || !a.system)
              .map((a) => ({
                key: a.name,
                cells: [
                  mono(a.name),
                  a.uid,
                  a.gecos,
                  <span className="font-mono text-meta text-muted">{a.home}</span>,
                  <span className="font-mono text-meta text-muted">{a.shell}</span>,
                  <>
                    {a.source === 'nss' ? <Badge tone="accent">{t('devices.acc.directory')}</Badge> : t('devices.acc.local')} {a.system && <Badge>{t('devices.sw.system')}</Badge>}
                  </>,
                  <Badge tone={a.admin ? 'warn' : 'off'}>{t(a.admin ? 'devices.acc.admin' : 'devices.acc.user')}</Badge>,
                  a.sso ? (
                    <>
                      {a.last_sso ? t('devices.acc.ssoConfirmed', { ago: ago(a.last_sso) }) : <span className="text-muted">{t('devices.acc.ssoNever')}</span>}
                      {a.pwd_locked && <Badge tone="warn">{t('devices.acc.pwdLocked')}</Badge>}
                    </>
                  ) : (
                    '–'
                  ),
                  ...(hd
                    ? [
                        accountActionable(a) ? (
                          <ActionMenu
                            trigger={
                              <button type="button" className="btn btn-ghost !h-7 px-1.5" aria-label={t('devices.actionsFor', { name: a.name })}>
                                <MoreHorizontal size={15} />
                              </button>
                            }
                            items={menu(a)}
                          />
                        ) : (
                          ''
                        ),
                      ]
                    : []),
                ],
              }))}
          />
        )}
      </div>
    </div>
  )
}

// ---- activity ----

const kinds = ['', 'event', 'command', 'script', 'shell', 'diagnostics', 'compliance', 'audit'] as const
const kindIcon: Record<string, ReactNode> = {
  event: <ActivityIcon size={7} />,
  command: <Package size={7} />,
  script: <FileCode2 size={7} />,
  shell: <Terminal size={7} />,
  diagnostics: <Download size={7} />,
  compliance: <ShieldCheck size={7} />,
  audit: <ScrollText size={7} />,
}

export function ActivityTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const helpdesk = useCan('commands')
  const audit = useCan('audit')
  const [kind, setKind] = useState<(typeof kinds)[number]>('')
  const tl = useTimeline(d.id, kind)
  const { run, pending } = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const items: TimelineItem[] = (tl.data?.pages.flatMap((p) => p.items) ?? []).map((e) => ({ id: `${e.kind}:${e.id}`, at: e.at, icon: kindIcon[e.kind], title: <Entry e={e} d={d} />, meta: e.by || undefined }))
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <ScrollHint className="max-w-full">
          <Segmented label={t('devices.act.filter')} value={kind || 'all'} onChange={(v) => setKind(v === 'all' ? '' : (v as typeof kind))} options={kinds.filter((k) => audit || k !== 'audit').map((k) => ({ value: k || 'all', label: t(`devices.act.kind.${k || 'all'}` as MessageKey) }))} />
        </ScrollHint>
        <span className="flex-1" />
        {helpdesk && !d.retired && (
          <button type="button" className="btn" disabled={pending} onClick={() => run('diagnostics')}>
            <Download size={14} aria-hidden /> {t('devices.act.collect')}
          </button>
        )}
      </div>
      {helpdesk && <p className="text-meta text-muted">{t('devices.act.diagHelp')}</p>}
      <div className="card p-[var(--pad-card)]">
        {tl.error ? (
          <ErrorState error={tl.error} onRetry={() => void tl.refetch()} />
        ) : tl.isPending ? (
          <LoadingState />
        ) : items.length ? (
          <Timeline items={items} label={t('devices.tab.activity')} />
        ) : (
          <EmptyState icon={ActivityIcon} title={t('devices.act.none')}>
            {t('devices.act.noneBody')}
          </EmptyState>
        )}
        {tl.hasNextPage && (
          <button type="button" className="btn mt-3" disabled={tl.isFetchingNextPage} onClick={() => void tl.fetchNextPage()}>
            {t('devices.act.more')}
          </button>
        )}
      </div>
    </div>
  )
}

function Out({ text, label }: { text: string; label: string }) {
  if (!text.trim()) return null
  return (
    <details className="mt-1">
      <summary className="cursor-pointer text-meta text-muted">{label}</summary>
      <pre className="mt-1 max-h-72 overflow-auto rounded-md bg-surface-2 p-2 font-mono text-meta whitespace-pre-wrap">{text}</pre>
    </details>
  )
}

function Entry({ e, d }: { e: TimelineEntry; d: DeviceDetail }) {
  const t = useT()
  switch (e.kind) {
    case 'command':
      return (
        <div>
          <span className="font-medium">{t(`devices.type.${e.title}` as MessageKey)}</span> <Badge tone={statusTone(e.status)}>{t(`devices.cstatus.${e.status}` as MessageKey)}</Badge> <span className="text-meta text-muted">#{e.id}</span>
          <Out text={e.detail} label={t('devices.act.output')} />
        </div>
      )
    case 'script':
      return (
        <div>
          <span className="font-medium">{t('devices.act.script', { name: e.title })}</span> <Badge tone={statusTone(e.status)}>{t('devices.act.exit', { code: e.status })}</Badge>
          <Out text={e.detail} label={t('devices.act.output')} />
          <Out text={e.extra} label={t('devices.act.errors')} />
        </div>
      )
    case 'shell':
      return (
        <div>
          <span className="font-medium">{t('devices.act.shell', { user: e.title })}</span> <Badge tone={statusTone(e.status)}>{t(`devices.shell.state.${e.status}` as MessageKey)}</Badge>{' '}
          <Link to="/devices/$id/shell/$sid" params={{ id: d.id, sid: e.id }} className="text-meta">
            {t('devices.act.openSession')}
          </Link>
          {e.detail && <span className="block text-meta text-muted">{e.detail}</span>}
        </div>
      )
    case 'diagnostics':
      return (
        <div>
          <span className="font-medium">{t('devices.act.diag', { size: fmt(Number(e.detail)) })}</span>{' '}
          <a href={`/api/v1/devices/${encodeURIComponent(d.id)}/diagnostics/${e.id}`} className="text-meta" download>
            {t('devices.act.download')}
          </a>
        </div>
      )
    case 'compliance': {
      const c = (d.check_results as { id: string; title?: string }[]).find((x) => x.id === e.title)
      return (
        <div>
          <span className="font-medium">{t('devices.act.check', { name: c?.title || e.title })}</span> <Badge tone={checkTone(e.status)}>{t(`devices.check.${e.status}` as MessageKey)}</Badge>
          {e.detail && <span className="block text-meta text-muted">{e.detail}</span>}
        </div>
      )
    }
    case 'audit':
      return (
        <div>
          <span className="font-medium">{e.extra || e.title}</span> <span className="font-mono text-micro text-muted">{e.title}</span>
          {e.detail && <span className="block text-meta text-muted">{e.detail}</span>}
        </div>
      )
    default:
      return <span>{e.detail}</span>
  }
}
