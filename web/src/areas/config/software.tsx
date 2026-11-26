// Software catalog: apps with sources and modes, Flathub search, installed
// Flatpaks to take over, user requests with approve and deny, Flatpak
// remotes (allowed, blocked, catalog only) and the store settings. The app
// editor is its own page (/config/software/$id).
import { Link, useNavigate, useParams } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { AppWindow, ArrowLeft, Check, Download, Inbox, Plus, Search, ShieldBan, ShieldCheck, Trash2, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ApiError } from '../../api/client'
import { useCan, useMe } from '../../api/me'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal, PageHeader, Segmented, Switch } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, fmt } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { searchFlathub, useBlueprints, useCatalog, useRemotes, useRequests, useSoftware, useStoreSettings, type CatalogApp, type CatalogAppInput, type Remote } from './api'

type Sub = 'catalog' | 'requests' | 'remotes' | 'settings'
type Mode = 'available' | 'request' | 'required'

const iconURL = (a: { id: string; icon_hash?: string }) => `/software/icons/${encodeURIComponent(a.id)}?v=${a.icon_hash ?? ''}`

export function SoftwareTab({ sub, setSub, q, setQ }: { sub?: string; setSub: (s?: string) => void; q: string; setQ: (q: string) => void }) {
  const t = useT()
  const cat = useCatalog()
  const cur = (['requests', 'remotes', 'settings'].includes(sub ?? '') ? sub : 'catalog') as Sub
  const pending = cat.data?.pending_requests ?? 0
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Segmented
        label={t('config.softwareViews')}
        value={cur}
        onChange={(v) => setSub(v === 'catalog' ? undefined : v)}
        options={[
          { value: 'catalog', label: t('config.swCatalog') },
          { value: 'requests', label: pending ? t('config.swRequestsN', { count: pending }) : t('config.swRequests') },
          { value: 'remotes', label: t('config.swRemotes') },
          { value: 'settings', label: t('config.swSettings') },
        ]}
      />
      {cur === 'catalog' && <CatalogView q={q} setQ={setQ} />}
      {cur === 'requests' && <RequestsView />}
      {cur === 'remotes' && <RemotesView />}
      {cur === 'settings' && <SettingsView />}
    </div>
  )
}

const modeTone = { available: 'ok', request: 'info', required: 'accent' } as const

function CatalogView({ q, setQ }: { q: string; setQ: (q: string) => void }) {
  const t = useT()
  const admin = useCan('admin')
  const cat = useCatalog()
  const sw = useSoftware()
  const [flathub, setFlathub] = useState(false)
  const [take, setTake] = useState<string[]>([])
  if (cat.error) return <ErrorState error={cat.error} onRetry={() => void cat.refetch()} />
  if (!cat.data) return <LoadingState rows={6} />
  const apps = cat.data.items.filter((a) => `${a.name} ${a.id} ${a.summary ?? ''} ${a.category ?? ''}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-md">
          <Search size={15} className="absolute top-1/2 left-3 -translate-y-1/2 text-muted" aria-hidden />
          <input type="search" className="field !pl-9" placeholder={t('config.searchApps')} aria-label={t('config.searchApps')} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {admin && (
          <span className="ml-auto flex gap-2">
            <button type="button" className="btn" onClick={() => setFlathub(true)}>
              <Download size={14} aria-hidden /> {t('config.fromFlathub')}
            </button>
            <Link to="/config/software/$id" params={{ id: 'new' }} className="btn btn-primary">
              <Plus size={14} aria-hidden /> {t('config.addApp')}
            </Link>
          </span>
        )}
      </div>
      <Card bodyClass="!px-0 !py-0">
        {!apps.length ? (
          <EmptyState icon={AppWindow} title={t('config.noApps')}>
            {t('config.noAppsBody')}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left">
              <caption className="sr-only">{t('config.swCatalog')}</caption>
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="w-12 px-[var(--pad-card)] py-2">
                    <span className="sr-only">{t('config.icon')}</span>
                  </th>
                  <th className="py-2 font-medium">{t('config.app')}</th>
                  <th className="font-medium">{t('config.mode')}</th>
                  <th className="font-medium">{t('config.sourcesCol')}</th>
                  <th className="num font-medium">{t('config.installs')}</th>
                  <th className="pr-[var(--pad-card)] font-medium">{t('config.updated')}</th>
                </tr>
              </thead>
              <tbody>
                {apps.map((a) => (
                  <tr key={a.id} className="row-h border-b border-line last:border-0">
                    <td className="px-[var(--pad-card)]">{a.has_icon ? <img src={iconURL(a)} alt="" width={28} height={28} className="rounded" /> : <AppWindow size={22} className="text-muted" aria-hidden />}</td>
                    <td className="py-1.5">
                      <Link to="/config/software/$id" params={{ id: a.id }} className="font-medium hover:text-accent">
                        {a.name}
                      </Link>
                      {!a.enabled && (
                        <Badge tone="off">
                          <span className="ml-1">{t('config.paused')}</span>
                        </Badge>
                      )}
                      <div className="text-[12px] text-muted">{a.summary || a.category}</div>
                    </td>
                    <td>
                      <Badge tone={modeTone[a.mode as Mode] ?? 'neutral'}>{t(`config.mode.${a.mode}` as MessageKey)}</Badge>
                    </td>
                    <td className="font-mono text-[12px] text-muted">{a.sources.map((s) => (s.kind === 'flatpak' ? s.flatpak : [s.debian, s.fedora].filter(Boolean).join(' / '))).join(', ')}</td>
                    <td className="num">
                      {a.installs ? (
                        <Link to="/devices" search={{ q: `app:${a.id}` }} className="hover:text-accent">
                          {fmt(a.installs)}
                        </Link>
                      ) : (
                        <span className="text-muted">0</span>
                      )}
                    </td>
                    <td className="pr-[var(--pad-card)] text-[12px] text-muted">{ago(a.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {cat.data.fleet.length > 0 && (
        <Card title={t('config.fleetTitle')} sub={t('config.fleetSub')}>
          <ul className="mb-3 flex flex-col gap-1">
            {cat.data.fleet.map((f) => (
              <li key={f.id}>
                <label className="flex items-center gap-2 text-[13px]">
                  {admin && <input type="checkbox" checked={take.includes(f.id)} onChange={(e) => setTake(e.target.checked ? [...take, f.id] : take.filter((x) => x !== f.id))} />}
                  <span className="font-medium">{f.name}</span>
                  <span className="font-mono text-[12px] text-muted">{f.id}</span>
                  {f.origin && f.origin !== 'flathub' && <Badge>{f.origin}</Badge>}
                  <span className="ml-auto text-[12px] text-muted">{t('config.devicesN', { count: f.devices })}</span>
                </label>
              </li>
            ))}
          </ul>
          {admin && (
            <button
              type="button"
              className="btn"
              disabled={!take.length || sw.importFleet.isPending}
              onClick={() =>
                sw.importFleet.mutate(take, {
                  onSuccess: () => {
                    toast(t('config.imported', { count: take.length }))
                    setTake([])
                  },
                  onError: (e) => toast(errorText(e), 'error'),
                })
              }
            >
              {t('config.takeOver', { count: take.length })}
            </button>
          )}
        </Card>
      )}
      <FlathubSearch open={flathub} onClose={() => setFlathub(false)} />
    </>
  )
}

/** Flathub search through the server; adding takes name, summary, category and icon over. */
function FlathubSearch({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const nav = useNavigate()
  const sw = useSoftware()
  const [draft, setDraft] = useState('')
  const [q, setQ] = useState('')
  const [mode, setMode] = useState<Mode>('available')
  const hits = useQuery({ queryKey: ['config', 'flathub', q], enabled: q.length >= 2, queryFn: () => searchFlathub(q), staleTime: 60_000 })
  return (
    <Modal open={open} onClose={onClose} title={t('config.fromFlathub')} description={t('config.flathubSub')} wide>
      <form
        className="mb-3 flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          setQ(draft.trim())
        }}
      >
        <input type="search" className="field min-w-0 flex-1" minLength={2} maxLength={80} placeholder={t('config.flathubPlaceholder')} aria-label={t('config.fromFlathub')} value={draft} onChange={(e) => setDraft(e.target.value)} autoFocus />
        <select className="field w-auto" aria-label={t('config.mode')} value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
          {(['available', 'request', 'required'] as const).map((m) => (
            <option key={m} value={m}>
              {t(`config.modeLong.${m}` as MessageKey)}
            </option>
          ))}
        </select>
        <button className="btn btn-primary">{t('config.search')}</button>
      </form>
      {hits.isFetching && <LoadingState rows={3} />}
      {hits.error && <ErrorState error={hits.error} />}
      {hits.data && !hits.data.length && <EmptyState title={t('config.flathubNone')} />}
      <ul className="flex max-h-[50vh] flex-col divide-y divide-line overflow-y-auto">
        {(hits.data ?? []).map((h) => (
          <li key={h.id} className="flex items-center gap-3 py-2">
            {h.icon ? <img src={`/software/flathub/icon?u=${encodeURIComponent(h.icon)}`} alt="" width={32} height={32} className="rounded" /> : <AppWindow size={28} className="text-muted" aria-hidden />}
            <div className="min-w-0 flex-1">
              <div className="font-medium">{h.name}</div>
              <div className="truncate text-[12px] text-muted">{h.summary}</div>
              <div className="font-mono text-[11.5px] text-muted">{h.id}</div>
            </div>
            <button
              type="button"
              className="btn"
              disabled={sw.addFlathub.isPending}
              onClick={() =>
                sw.addFlathub.mutate(
                  { id: h.id, mode },
                  {
                    onSuccess: (r) => {
                      onClose()
                      if (r.pending) toast(t('config.pendingToast', { name: h.name }))
                      else {
                        toast(t('config.savedToast', { name: h.name }))
                        if (r.id) void nav({ to: '/config/software/$id', params: { id: String(r.id) } })
                      }
                    },
                    onError: (e) => toast(e instanceof ApiError && e.status === 409 ? t('config.inCatalog') : errorText(e), 'error'),
                  },
                )
              }
            >
              <Plus size={14} aria-hidden /> {t('config.addToCatalog')}
            </button>
          </li>
        ))}
      </ul>
    </Modal>
  )
}

function RequestsView() {
  const t = useT()
  const admin = useCan('admin')
  const reqs = useRequests()
  const sw = useSoftware()
  if (reqs.error) return <ErrorState error={reqs.error} onRetry={() => void reqs.refetch()} />
  if (!reqs.data) return <LoadingState rows={5} />
  const decide = (id: number, op: 'approve' | 'approve-all' | 'deny') => sw.decide.mutate({ id, op }, { onSuccess: () => toast(t(op === 'deny' ? 'config.denied' : 'config.approved')), onError: (e) => toast(errorText(e), 'error') })
  return (
    <Card bodyClass="!px-0 !py-0">
      {!reqs.data.length ? (
        <EmptyState icon={Inbox} title={t('config.noRequests')}>
          {t('config.noRequestsBody')}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {reqs.data.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-3 px-[var(--pad-card)] py-2.5">
              <div className="min-w-0 flex-1 basis-64">
                <div className="flex flex-wrap items-center gap-2 font-medium">
                  {r.app_name || r.app || r.flatpak}
                  <Badge tone={r.status === 'pending' ? 'warn' : r.status === 'approved' ? 'ok' : 'off'}>{t(`config.req.${r.status}` as MessageKey)}</Badge>
                  {r.flatpak && !r.app && <Badge>{t('config.outsideCatalog')}</Badge>}
                </div>
                <div className="text-[12.5px] text-muted">
                  {t('config.requestBy', { user: r.user || '·', host: r.hostname })} · {ago(r.created_at)}
                  {r.decided_by && ` · ${t('config.decidedBy', { by: r.decided_by })}`}
                </div>
                {r.note && <p className="mt-0.5 text-[13px]">„{r.note}“</p>}
              </div>
              {admin && r.status === 'pending' && (
                <span className="flex flex-wrap gap-2">
                  <button type="button" className="btn" onClick={() => decide(r.id, 'deny')}>
                    <X size={14} aria-hidden /> {t('config.deny')}
                  </button>
                  {r.flatpak && !r.app && (
                    <button type="button" className="btn" onClick={() => decide(r.id, 'approve-all')}>
                      {t('config.approveAll')}
                    </button>
                  )}
                  <button type="button" className="btn btn-primary" onClick={() => decide(r.id, 'approve')}>
                    <Check size={14} aria-hidden /> {t('config.approve')}
                  </button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function RemotesView() {
  const t = useT()
  const admin = useCan('admin')
  const rs = useRemotes()
  const sw = useSoftware()
  const [edit, setEdit] = useState<Remote>()
  if (rs.error) return <ErrorState error={rs.error} onRetry={() => void rs.refetch()} />
  if (!rs.data) return <LoadingState rows={5} />
  const op = (name: string, o: 'allow' | 'block' | 'filter' | 'unmanage') => sw.remoteOp.mutate({ name, op: o }, { onSuccess: () => toast(t('config.remoteSaved', { name })), onError: (e) => toast(errorText(e), 'error') })
  const managed = rs.data.filter((r) => r.managed)
  const found = rs.data.filter((r) => !r.managed)
  return (
    <>
      <Card title={t('config.managedRemotes')} sub={t('config.managedRemotesSub')} action={admin && <button type="button" className="btn" onClick={() => setEdit({ name: '', url: 'https://', title: '', state: 'allowed', catalog_only: false, devices: 0, managed: false })}><Plus size={14} aria-hidden /> {t('config.addRemote')}</button>} bodyClass="!px-0 !pb-1">
        <ul className="divide-y divide-line">
          {managed.map((r) => (
            <li key={r.name} className="flex flex-wrap items-center gap-3 px-[var(--pad-card)] py-2.5">
              <div className="min-w-0 flex-1 basis-64">
                <div className="flex flex-wrap items-center gap-2 font-medium">
                  {r.title || r.name}
                  <Badge tone={r.state === 'blocked' ? 'bad' : 'ok'}>{t(r.state === 'blocked' ? 'config.blocked' : 'config.allowed')}</Badge>
                  {r.catalog_only && <Badge tone="info">{t('config.catalogOnly')}</Badge>}
                </div>
                <div className="truncate font-mono text-[12px] text-muted">{r.url}</div>
                <div className="text-[12px] text-muted">{t('config.devicesN', { count: r.devices })}</div>
              </div>
              {admin && (
                <span className="flex flex-wrap gap-1.5">
                  {r.state === 'blocked' ? (
                    <button type="button" className="btn" onClick={() => op(r.name, 'allow')}>
                      <ShieldCheck size={14} aria-hidden /> {t('config.allow')}
                    </button>
                  ) : (
                    <button type="button" className="btn" onClick={() => op(r.name, 'block')}>
                      <ShieldBan size={14} aria-hidden /> {t('config.block')}
                    </button>
                  )}
                  <button type="button" className="btn" aria-pressed={r.catalog_only} onClick={() => op(r.name, 'filter')}>
                    {t('config.catalogOnly')}
                  </button>
                  <button type="button" className="btn" onClick={() => setEdit(r)}>
                    {t('config.edit')}
                  </button>
                  <button type="button" className="btn btn-ghost text-bad" aria-label={t('config.unmanage', { name: r.name })} onClick={() => op(r.name, 'unmanage')}>
                    <Trash2 size={14} aria-hidden />
                  </button>
                </span>
              )}
            </li>
          ))}
        </ul>
      </Card>
      {found.length > 0 && (
        <Card title={t('config.foundRemotes')} sub={t('config.foundRemotesSub')} bodyClass="!px-0 !pb-1">
          <ul className="divide-y divide-line">
            {found.map((r) => (
              <li key={r.name} className="flex flex-wrap items-center gap-3 px-[var(--pad-card)] py-2.5">
                <div className="min-w-0 flex-1 basis-64">
                  <div className="font-medium">{r.title || r.name}</div>
                  <div className="truncate font-mono text-[12px] text-muted">{r.url}</div>
                  <Link to="/devices" search={{ q: `remote:${r.name}` }} className="text-[12px] text-accent hover:underline">
                    {t('config.devicesN', { count: r.devices })}
                  </Link>
                </div>
                {admin && (
                  <span className="flex gap-1.5">
                    <button type="button" className="btn" onClick={() => sw.saveRemote.mutate({ ...r, state: 'allowed' }, { onSuccess: () => toast(t('config.remoteSaved', { name: r.name })), onError: (e) => toast(errorText(e), 'error') })}>
                      {t('config.manageAllowed')}
                    </button>
                    <button type="button" className="btn" onClick={() => sw.saveRemote.mutate({ ...r, state: 'blocked' }, { onSuccess: () => toast(t('config.remoteSaved', { name: r.name })), onError: (e) => toast(errorText(e), 'error') })}>
                      {t('config.manageBlocked')}
                    </button>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
      {edit && <RemoteForm remote={edit} onClose={() => setEdit(undefined)} />}
    </>
  )
}

function RemoteForm({ remote, onClose }: { remote: Remote; onClose: () => void }) {
  const t = useT()
  const sw = useSoftware()
  const [r, setR] = useState(remote)
  const [err, setErr] = useState<string>()
  const isNew = !remote.name
  return (
    <Modal
      open
      onClose={onClose}
      title={t(isNew ? 'config.addRemote' : 'config.editRemote', { name: remote.name })}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!r.name || sw.saveRemote.isPending}
            onClick={() =>
              sw.saveRemote.mutate(r, {
                onSuccess: () => {
                  toast(t('config.remoteSaved', { name: r.name }))
                  onClose()
                },
                onError: (e) => setErr(errorText(e)),
              })
            }
          >
            {t('common.save')}
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <Field label={t('config.name')} required help={t('config.remoteNameHelp')}>
          {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} className="field font-mono" readOnly={!isNew} value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} />}
        </Field>
        <Field label={t('config.url')} help={t('config.remoteUrlHelp')} error={err}>
          {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field font-mono" value={r.url} onChange={(e) => setR({ ...r, url: e.target.value })} />}
        </Field>
        <Field label={t('config.remoteTitle')}>{({ id }) => <input id={id} className="field" maxLength={80} value={r.title} onChange={(e) => setR({ ...r, title: e.target.value })} />}</Field>
        <Segmented
          label={t('config.state')}
          value={r.state === 'blocked' ? 'blocked' : 'allowed'}
          onChange={(v) => setR({ ...r, state: v })}
          options={[
            { value: 'allowed', label: t('config.allowed') },
            { value: 'blocked', label: t('config.blocked') },
          ]}
        />
        <label className="flex items-center justify-between gap-4 text-[13px]">
          <span>
            <span className="font-medium">{t('config.catalogOnly')}</span>
            <span className="block text-[12.5px] text-muted">{t('config.catalogOnlyHelp')}</span>
          </span>
          <Switch checked={r.catalog_only} onChange={(v) => setR({ ...r, catalog_only: v })} label={t('config.catalogOnly')} />
        </label>
      </div>
    </Modal>
  )
}

function SettingsView() {
  const t = useT()
  const admin = useCan('admin')
  const q = useStoreSettings()
  const sw = useSoftware()
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <LoadingState rows={3} />
  const set = q.data
  const rows = [
    ['restrict_flathub', 'config.setRestrict', 'config.setRestrictHelp'],
    ['stores_read_only', 'config.setReadOnly', 'config.setReadOnlyHelp'],
    ['only_managed_remotes', 'config.setManaged', 'config.setManagedHelp'],
  ] as const
  return (
    <Card title={t('config.swSettings')} sub={t('config.settingsSub')}>
      <ul className="flex flex-col gap-4">
        {rows.map(([k, label, help]) => (
          <li key={k} className="flex items-start justify-between gap-6">
            <div>
              <div className="text-[13px] font-medium" id={`set-${k}`}>
                {t(label)}
              </div>
              <p className="text-[12.5px] text-muted">{t(help)}</p>
            </div>
            <Switch
              checked={set[k]}
              disabled={!admin || sw.saveSettings.isPending}
              label={t(label)}
              onChange={(v) => sw.saveSettings.mutate({ ...set, [k]: v }, { onSuccess: () => toast(t('config.settingsSaved')), onError: (e) => toast(errorText(e), 'error') })}
            />
          </li>
        ))}
      </ul>
    </Card>
  )
}

// ---- app editor ----

type Form = {
  id: string
  name: string
  summary: string
  category: string
  mode: Mode
  enabled: boolean
  flatpak: string
  remote: string
  debian: string
  fedora: string
  prefer: 'flatpak' | 'package'
  detect: string
  scope: number[]
  repoName: string
  debUrl: string
  debSuite: string
  debComponents: string
  debKey: string
  rpmUrl: string
  rpmKey: string
  rpmSigned: boolean
}

function toForm(a?: CatalogApp): Form {
  const f: Form = { id: a?.id ?? '', name: a?.name ?? '', summary: a?.summary ?? '', category: a?.category ?? '', mode: (a?.mode as Mode) ?? 'available', enabled: a?.enabled ?? true, flatpak: '', remote: 'flathub', debian: '', fedora: '', prefer: 'flatpak', detect: (a?.detect ?? []).join(' '), scope: a?.scope ?? [], repoName: '', debUrl: '', debSuite: '', debComponents: '', debKey: '', rpmUrl: '', rpmKey: '', rpmSigned: false }
  ;(a?.sources ?? []).forEach((s, i) => {
    if (s.kind === 'flatpak') {
      f.flatpak = s.flatpak ?? ''
      f.remote = s.remote || 'flathub'
    } else {
      f.debian = s.debian ?? ''
      f.fedora = s.fedora ?? ''
      if (i === 0) f.prefer = 'package'
      for (const r of s.repos ?? []) {
        f.repoName = r.name ?? ''
        if (r.family === 'debian') Object.assign(f, { debUrl: r.url ?? '', debSuite: r.suites ?? '', debComponents: r.components ?? '', debKey: (r.key ?? '').trim() })
        else Object.assign(f, { rpmUrl: r.url ?? '', rpmKey: (r.key ?? '').trim(), rpmSigned: !!r.signed_metadata })
      }
    }
  })
  return f
}

/** The catalog app as the API takes it; packages first, vendor repository named after the app. */
export function fromForm(f: Form, icon?: string, removeIcon?: boolean): CatalogAppInput {
  const words = (s: string) => s.split(/\s+/).filter(Boolean)
  const srcs: CatalogAppInput['sources'] = []
  if (f.flatpak.trim()) srcs.push({ kind: 'flatpak', flatpak: f.flatpak.trim(), ...(f.remote && f.remote !== 'flathub' ? { remote: f.remote } : {}) })
  const repos = []
  const repoName = f.repoName || f.id
  if (f.debUrl.trim()) repos.push({ name: repoName, family: 'debian', url: f.debUrl.trim(), suites: f.debSuite.trim(), components: f.debComponents.trim(), key: f.debKey.trim() })
  if (f.rpmUrl.trim()) repos.push({ name: repoName, family: 'fedora', url: f.rpmUrl.trim(), key: f.rpmKey.trim(), signed_metadata: f.rpmSigned })
  const deb = words(f.debian).join(' ')
  const rpm = words(f.fedora).join(' ')
  if (deb || rpm) {
    const pkg = { kind: 'package' as const, debian: deb || undefined, fedora: rpm || undefined, ...(repos.length ? { repos } : {}) }
    if (f.prefer === 'package') srcs.unshift(pkg)
    else srcs.push(pkg)
  }
  return { id: f.id.trim(), name: f.name.trim(), summary: f.summary.trim(), category: f.category.trim(), mode: f.mode, enabled: f.enabled, sources: srcs, detect: words(f.detect), scope: f.scope, ...(icon ? { icon } : {}), remove_icon: !!removeIcon }
}

export function AppPage() {
  const { id } = useParams({ strict: false }) as { id: string }
  const t = useT()
  const cat = useCatalog()
  if (cat.error) return <ErrorState error={cat.error} onRetry={() => void cat.refetch()} />
  if (!cat.data) return <LoadingState rows={8} />
  const app = cat.data.items.find((a) => a.id === id)
  if (id !== 'new' && !app) return <EmptyState title={t('state.notFoundTitle')}>{t('state.notFoundBody')}</EmptyState>
  return <AppEditor key={id} app={app} />
}

function AppEditor({ app }: { app?: CatalogApp }) {
  const t = useT()
  const nav = useNavigate()
  const admin = useCan('admin')
  const me = useMe()
  const sw = useSoftware()
  const bps = useBlueprints()
  const remotes = useRemotes()
  const initial = useMemo(() => toForm(app), [app])
  const [f, setF] = useState(initial)
  const [icon, setIcon] = useState<string>()
  const [removeIcon, setRemoveIcon] = useState(false)
  const [err, setErr] = useState<string>()
  const [confirm, setConfirm] = useState(false)
  const isNew = !app
  const set = (p: Partial<Form>) => setF({ ...f, ...p })
  const needsPkgs = (f.debUrl.trim() || f.rpmUrl.trim()) && !f.debian.trim() && !f.fedora.trim()
  const valid = /^[a-z0-9][a-z0-9-]{0,47}$/.test(f.id) && f.name.trim() && (f.flatpak.trim() || f.debian.trim() || f.fedora.trim()) && !needsPkgs
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setErr(undefined)
    sw.saveApp.mutate(
      { isNew, app: fromForm(f, icon, removeIcon) },
      {
        onSuccess: (r) => {
          toast(t(r.pending ? 'config.pendingToast' : 'config.savedToast', { name: f.name }))
          void nav({ to: '/config', search: { tab: 'software' } })
        },
        onError: (e) => setErr(errorText(e)),
      },
    )
  }
  const field = (k: keyof Form, label: string, help?: string, mono = false) => (
    <Field label={label} help={help}>
      {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} className={cx('field', mono && 'font-mono')} spellCheck={!mono} value={String(f[k])} onChange={(e) => set({ [k]: e.target.value } as Partial<Form>)} />}
    </Field>
  )
  return (
    <form onSubmit={submit} className="pb-24" noValidate>
      <Link to="/config" search={{ tab: 'software' }} className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {t('config.tabSoftware')}
      </Link>
      <PageHeader title={app?.name ?? t('config.addApp')} sub={app && t('config.devicesN', { count: app.installs })} />
      <fieldset disabled={!admin} className="grid gap-[var(--gap)] xl:grid-cols-[minmax(0,1fr)_360px]">
        <legend className="sr-only">{t('config.app')}</legend>
        <div className="flex min-w-0 flex-col gap-[var(--gap)]">
          <Card title={t('config.appGeneral')}>
            <div className="grid gap-4 md:grid-cols-2">
              <Field label={t('config.appId')} required help={t('config.appIdHelp')} error={f.id && !/^[a-z0-9][a-z0-9-]{0,47}$/.test(f.id) ? t('config.appIdHelp') : undefined}>
                {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field font-mono" readOnly={!isNew} value={f.id} onChange={(e) => set({ id: e.target.value })} />}
              </Field>
              <Field label={t('config.name')} required>
                {({ id }) => <input id={id} className="field" maxLength={80} value={f.name} onChange={(e) => set({ name: e.target.value })} />}
              </Field>
              <div className="md:col-span-2">{field('summary', t('config.summary'))}</div>
              <Field label={t('config.category')}>
                {({ id }) => (
                  <>
                    <input id={id} className="field" list="app-categories" maxLength={40} value={f.category} onChange={(e) => set({ category: e.target.value })} />
                    <datalist id="app-categories">
                      {['Internet', 'Office', 'Communication', 'Multimedia', 'Graphics', 'Development', 'Security', 'Utilities'].map((c) => (
                        <option key={c} value={c} />
                      ))}
                    </datalist>
                  </>
                )}
              </Field>
              <Field label={t('config.mode')} help={t(`config.modeLong.${f.mode}` as MessageKey)}>
                {({ id, describedBy }) => (
                  <select id={id} aria-describedby={describedBy} className="field" value={f.mode} onChange={(e) => set({ mode: e.target.value as Mode })}>
                    {(['available', 'request', 'required'] as const).map((m) => (
                      <option key={m} value={m}>
                        {t(`config.mode.${m}` as MessageKey)}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            </div>
          </Card>
          <Card title={t('config.sourcesCol')} sub={t('config.howInstalls')}>
            <div className="grid gap-4 md:grid-cols-2">
              {field('flatpak', t('config.flatpakId'), t('config.flatpakIdHelp'), true)}
              <Field label={t('config.remote')}>
                {({ id }) => (
                  <select id={id} className="field" value={f.remote} onChange={(e) => set({ remote: e.target.value })}>
                    <option value="flathub">flathub</option>
                    {(remotes.data ?? [])
                      .filter((r) => r.managed && r.name !== 'flathub')
                      .map((r) => (
                        <option key={r.name} value={r.name}>
                          {r.name}
                        </option>
                      ))}
                  </select>
                )}
              </Field>
              {field('debian', t('config.debian'), undefined, true)}
              {field('fedora', t('config.fedora'), undefined, true)}
              <Field label={t('config.prefer')}>
                {({ id }) => (
                  <select id={id} className="field" value={f.prefer} onChange={(e) => set({ prefer: e.target.value as Form['prefer'] })}>
                    <option value="flatpak">{t('config.preferFlatpak')}</option>
                    <option value="package">{t('config.preferPackage')}</option>
                  </select>
                )}
              </Field>
              {field('detect', t('config.detect'), t('config.detectHelp'), true)}
            </div>
            <details className="mt-4 rounded-lg border border-line p-3" open={!!(f.debUrl || f.rpmUrl)}>
              <summary className="cursor-pointer font-medium">{t('config.vendorRepo')}</summary>
              <p className="mt-1 mb-3 text-[12.5px] text-muted">{t('config.vendorRepoHelp')}</p>
              {needsPkgs && <p className="mb-2 text-[12.5px] font-medium text-bad">{t('config.vendorNeedsPkgs')}</p>}
              <div className="grid gap-4 md:grid-cols-3">
                {field('debUrl', t('config.debUrl'), undefined, true)}
                {field('debSuite', t('config.suite'), undefined, true)}
                {field('debComponents', t('config.components'), undefined, true)}
              </div>
              <Field label={t('config.debKey')} help={t('config.keyHelp')}>
                {({ id, describedBy }) => <textarea id={id} aria-describedby={describedBy} rows={3} spellCheck={false} className="field font-mono text-[12px]" value={f.debKey} onChange={(e) => set({ debKey: e.target.value })} />}
              </Field>
              <div className="mt-4 grid gap-4">
                {field('rpmUrl', t('config.rpmUrl'), t('config.rpmUrlHelp'), true)}
                <Field label={t('config.rpmKey')} help={t('config.keyHelp')}>
                  {({ id, describedBy }) => <textarea id={id} aria-describedby={describedBy} rows={3} spellCheck={false} className="field font-mono text-[12px]" value={f.rpmKey} onChange={(e) => set({ rpmKey: e.target.value })} />}
                </Field>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="checkbox" checked={f.rpmSigned} onChange={(e) => set({ rpmSigned: e.target.checked })} /> {t('config.signedMetadata')}
                </label>
              </div>
            </details>
          </Card>
          <Card title={t('config.availability')}>
            <label className="mb-4 flex items-center justify-between gap-4 text-[13px]">
              <span className="font-medium">{t('config.inCatalogLabel')}</span>
              <Switch checked={f.enabled} onChange={(v) => set({ enabled: v })} label={t('config.inCatalogLabel')} />
            </label>
            <fieldset>
              <legend className="text-[13px] font-medium">{t('config.onlyFor')}</legend>
              <p className="mb-2 text-[12.5px] text-muted">{t('config.onlyForHelp')}</p>
              <div className="flex flex-wrap gap-2">
                {(bps.data?.items ?? [])
                  .filter((b) => !b.pilot_of)
                  .map((b) => (
                    <label key={b.id} className="inline-flex items-center gap-1.5 rounded-md border border-line px-2 py-1 text-[13px]">
                      <input type="checkbox" checked={f.scope.includes(b.id!)} onChange={(e) => set({ scope: e.target.checked ? [...f.scope, b.id!] : f.scope.filter((x) => x !== b.id) })} />
                      {b.name}
                    </label>
                  ))}
              </div>
            </fieldset>
          </Card>
        </div>
        <div className="flex flex-col gap-[var(--gap)]">
          <Card title={t('config.icon')}>
            {app?.has_icon && !removeIcon && !icon && <img src={iconURL(app)} alt="" width={64} height={64} className="mb-3 rounded" />}
            <label className="btn w-fit cursor-pointer">
              {t('config.uploadIcon')}
              <input
                type="file"
                accept="image/png"
                className="sr-only"
                onChange={async (e) => {
                  const file = e.target.files?.[0]
                  if (!file) return
                  const b = new Uint8Array(await file.arrayBuffer())
                  let bin = ''
                  b.forEach((x) => (bin += String.fromCharCode(x)))
                  setIcon(btoa(bin))
                }}
              />
            </label>
            {icon && <p className="mt-2 text-[12.5px] text-ok">{t('config.iconChosen')}</p>}
            <p className="mt-2 text-[12.5px] text-muted">{t('config.iconHelp')}</p>
            {app?.has_icon && (
              <label className="mt-2 flex items-center gap-2 text-[13px]">
                <input type="checkbox" checked={removeIcon} onChange={(e) => setRemoveIcon(e.target.checked)} /> {t('config.removeIcon')}
              </label>
            )}
          </Card>
          <Card title={t('config.howTitle')}>
            <p className="text-[12.5px] text-muted">{t('config.howBody')}</p>
          </Card>
          {app && admin && (
            <Card title={t('config.removeApp')}>
              <p className="mb-3 text-[12.5px] text-muted">{t('config.removeAppHint')}</p>
              <button type="button" className="btn text-bad" onClick={() => setConfirm(true)}>
                <Trash2 size={14} aria-hidden /> {t('config.remove')}
              </button>
            </Card>
          )}
        </div>
      </fieldset>
      {err && (
        <p role="alert" className="mt-[var(--gap)] rounded-lg bg-bad-soft p-3 text-[13px] text-bad">
          {err}
        </p>
      )}
      {admin && (
        <div className="fixed inset-x-0 bottom-0 z-20 border-t border-line bg-surface/95 backdrop-blur lg:left-[var(--sb,244px)]">
          <div className="mx-auto flex max-w-[1600px] items-center justify-end gap-2 px-4 py-2.5 lg:px-6">
            <span className="mr-auto text-[13px] text-muted">{t('config.appSaveHint')}</span>
            <button type="button" className="btn" onClick={() => setF(initial)}>
              {t('form.discard')}
            </button>
            <button type="submit" className="btn btn-primary" disabled={!valid || sw.saveApp.isPending}>
              {t(f.mode === 'required' && me.four_eyes ? 'config.submitApproval' : 'common.save')}
            </button>
          </div>
        </div>
      )}
      <Modal
        open={confirm}
        onClose={() => setConfirm(false)}
        title={t('config.removeAppTitle', { name: app?.name ?? '' })}
        description={t('config.removeAppHint')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setConfirm(false)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() =>
                sw.deleteApp.mutate(app!.id, {
                  onSuccess: () => {
                    toast(t('config.deletedToast', { name: app!.name }))
                    void nav({ to: '/config', search: { tab: 'software' } })
                  },
                  onError: (e) => toast(errorText(e), 'error'),
                })
              }
            >
              {t('config.remove')}
            </button>
          </>
        }
      />
    </form>
  )
}
