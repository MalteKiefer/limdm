// The configuration page: blueprints, library, software catalog and package
// repository as tabs; every view state (tab, search, type filter) lives in
// the URL.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { FilePlus2, FlaskConical, GitBranch, Info, Layers, Plus, Search, Share2, ShieldAlert } from 'lucide-react'
import { useCan } from '../../api/me'
import { TabBar, TabPanel } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge, Card, PageHeader } from '../../components/ui'
import { useT } from '../../i18n'
import { ago, dateTime, fmt, pct } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useBlueprints, useLibrary, useTypes, type BlueprintRow, type LibraryRow } from './api'
import { DeletedList, TypePicker } from './components'
import { PackagesTab } from './packages'
import { SoftwareTab } from './software'
import { treeItems } from './tree'

type Tab = 'blueprints' | 'library' | 'software' | 'packages'
type ConfigSearch = { tab?: string; q?: string; type?: string; sub?: string }

export function ConfigPage() {
  const t = useT()
  const s = useSearch({ strict: false }) as ConfigSearch
  const nav = useNavigate()
  const admin = useCan('admin')
  const audit = useCan('audit')
  const tab = (['library', 'software', 'packages'].includes(s.tab ?? '') ? s.tab : 'blueprints') as Tab
  const set = (next: ConfigSearch) => void nav({ to: '/config', search: { ...s, ...next }, replace: true })
  const tabs: { value: Tab; label: string }[] = [
    { value: 'blueprints', label: t('config.tabBlueprints') },
    { value: 'library', label: t('config.tabLibrary') },
    ...(audit ? [{ value: 'software' as Tab, label: t('config.tabSoftware') }, { value: 'packages' as Tab, label: t('config.tabPackages') }] : []),
  ]
  return (
    <div>
      <PageHeader
        title={t('config.title')}
        sub={t('config.sub')}
        actions={
          admin &&
          (tab === 'blueprints' ? (
            <Link to="/config/blueprints/$id" params={{ id: 'new' }} className="btn btn-primary">
              <Plus size={15} aria-hidden /> {t('config.newBlueprint')}
            </Link>
          ) : tab === 'library' ? (
            <button type="button" className="btn btn-primary" onClick={() => set({ sub: 'new' })}>
              <FilePlus2 size={15} aria-hidden /> {t('config.newItem')}
            </button>
          ) : null)
        }
      />
      <TabBar idBase="config" label={t('config.tabs')} value={tab} onChange={(v) => void nav({ to: '/config', search: { tab: v === 'blueprints' ? undefined : v }, replace: true })} tabs={tabs} />
      <TabPanel idBase="config" value={tab}>
        {tab === 'blueprints' && <BlueprintsTab q={s.q ?? ''} setQ={(q) => set({ q: q || undefined })} />}
        {tab === 'library' && <LibraryTab q={s.q ?? ''} type={s.type} set={set} />}
        {tab === 'software' && <SoftwareTab sub={s.sub} setSub={(sub) => set({ sub })} q={s.q ?? ''} setQ={(q) => set({ q: q || undefined })} />}
        {tab === 'packages' && <PackagesTab />}
      </TabPanel>
      <TypePicker open={tab === 'library' && s.sub === 'new'} onClose={() => set({ sub: undefined })} onPick={(type) => void nav({ to: '/config/library/$id', params: { id: 'new' }, search: { type } })} />
    </div>
  )
}

function SearchBox({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <div className="relative w-full max-w-md">
      <Search size={15} className="absolute top-1/2 left-3 -translate-y-1/2 text-muted" aria-hidden />
      <input type="search" className="field !pl-9" placeholder={label} aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  )
}

/** Share of compliant devices among the devices that report. */
function compliance(status: Record<string, number>) {
  const reporting = (status.compliant ?? 0) + (status['in grace'] ?? 0) + (status['non-compliant'] ?? 0)
  return reporting ? ((status.compliant ?? 0) / reporting) * 100 : undefined
}

function BlueprintsTab({ q, setQ }: { q: string; setQ: (q: string) => void }) {
  const t = useT()
  const bps = useBlueprints()
  const lib = useLibrary()
  if (bps.error) return <ErrorState error={bps.error} onRetry={() => void bps.refetch()} />
  if (!bps.data) return <LoadingState rows={6} />
  const names = new Map((lib.data?.items ?? []).map((i) => [i.id, i]))
  const list = bps.data.items.filter((b) => `${b.name} ${b.description ?? ''}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <p className="flex items-start gap-2 rounded-lg bg-info-soft p-3 text-[13px]">
        <Info size={15} className="mt-0.5 shrink-0 text-info" aria-hidden /> {t('config.assignOrder')}
      </p>
      <SearchBox value={q} onChange={setQ} label={t('config.searchBlueprints')} />
      {!list.length && (
        <Card>
          <EmptyState icon={Layers} title={t('config.noBlueprints')}>
            {t('config.noBlueprintsBody')}
          </EmptyState>
        </Card>
      )}
      <div className="grid gap-[var(--gap)] md:grid-cols-2 xl:grid-cols-3">
        {list.map((b) => (
          <BlueprintCard key={b.id} b={b} items={names} />
        ))}
      </div>
      <DeletedList kind="blueprints" items={bps.data.deleted} />
    </div>
  )
}

function BlueprintCard({ b, items }: { b: BlueprintRow; items: Map<number | undefined, LibraryRow> }) {
  const t = useT()
  const score = compliance(b.status)
  const tree = treeItems(b.tree)
  return (
    <article className="card flex flex-col p-[var(--pad-card)]" aria-labelledby={`bp-${b.id}`}>
      <div className="flex items-start gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-on-accent-soft">{b.pilot_of ? <FlaskConical size={18} aria-hidden /> : <Layers size={18} aria-hidden />}</span>
        <div className="min-w-0 flex-1">
          <h2 id={`bp-${b.id}`} className="font-semibold break-words">
            <Link to="/config/blueprints/$id" params={{ id: String(b.id) }} className="hover:text-accent">
              {b.name}
            </Link>
          </h2>
          {b.description && <p className="text-[12.5px] text-muted">{b.description}</p>}
          <div className="mt-1 flex flex-wrap gap-1">
            {b.parent && (
              <Badge>
                <GitBranch size={12} aria-hidden /> {t('config.inheritsFrom', { name: b.parent })}
              </Badge>
            )}
            {b.read_only && (
              <Badge tone="info">
                <Share2 size={12} aria-hidden /> {t('config.shared')}
              </Badge>
            )}
            {b.pilot && (
              <Badge tone="warn">
                <FlaskConical size={12} aria-hidden /> {t('config.pilotRunning', { count: b.pilot.devices.length })}
              </Badge>
            )}
            {!!b.pilot_of && <Badge tone="warn">{t('config.pilotCopy')}</Badge>}
          </div>
        </div>
      </div>
      <dl className="my-4 grid grid-cols-3 gap-2 text-center">
        <div className="rounded-lg bg-surface-2 py-2">
          <dt className="text-[11.5px] text-muted">{t('config.devices')}</dt>
          <dd className="num font-semibold">{fmt(b.devices)}</dd>
        </div>
        <div className="rounded-lg bg-surface-2 py-2">
          <dt className="text-[11.5px] text-muted">{t('config.items')}</dt>
          <dd className="num font-semibold">{fmt(b.items)}</dd>
        </div>
        <div className="rounded-lg bg-surface-2 py-2">
          <dt className="text-[11.5px] text-muted">{t('config.compliance')}</dt>
          <dd className={cx('num font-semibold', score !== undefined && score < 90 && 'text-bad')}>
            {score === undefined ? '·' : pct(score)}
            {score !== undefined && score < 90 && <ShieldAlert size={12} className="ml-1 inline" aria-label={t('config.belowTarget')} />}
          </dd>
        </div>
      </dl>
      <div className="mb-3">
        <h3 className="mb-1 text-[12px] font-medium text-muted">{t('config.sources')}</h3>
        <ul className="flex flex-wrap gap-1">
          {b.sources.map((s, i) => (
            <li key={i}>
              <Badge tone={s.kind === 'default' ? 'neutral' : 'accent'}>
                {s.kind === 'device' ? t('config.srcDevice', { count: s.devices ?? 0 }) : s.kind === 'group' ? t('config.srcGroup', { group: s.group ?? '', prio: s.priority ?? 0 }) : t('config.srcDefault')}
              </Badge>
            </li>
          ))}
          {!b.sources.length && <li className="text-[12.5px] text-muted">{t('config.srcNone')}</li>}
        </ul>
      </div>
      {tree.length > 0 && (
        <ul className="mb-4 flex flex-wrap gap-1" aria-label={t('config.items')}>
          {tree.slice(0, 12).map((id) => (
            <li key={id}>
              <Link to="/config/library/$id" params={{ id: String(id) }} className="inline-block rounded-md bg-surface-2 px-1.5 py-0.5 text-[12px] hover:text-accent">
                {items.get(id)?.name ?? `#${id}`}
              </Link>
            </li>
          ))}
          {tree.length > 12 && <li className="text-[12px] text-muted">{t('config.more', { count: tree.length - 12 })}</li>}
        </ul>
      )}
      <div className="mt-auto flex flex-wrap items-center gap-2">
        <Link to="/devices" search={{ q: `blueprint:"${b.name}"` }} className="btn">
          {t('config.toDevices')}
        </Link>
        <Link to="/config/blueprints/$id" params={{ id: String(b.id) }} className="btn">
          {t(b.read_only ? 'config.open' : 'config.edit')}
        </Link>
        <span className="ml-auto text-[12px] text-muted" title={b.updated_at ? dateTime(b.updated_at) : undefined}>
          {b.updated_at && ago(b.updated_at)}
        </span>
      </div>
    </article>
  )
}

function LibraryTab({ q, type, set }: { q: string; type?: string; set: (s: ConfigSearch) => void }) {
  const t = useT()
  const lib = useLibrary()
  const types = useTypes()
  if (lib.error) return <ErrorState error={lib.error} onRetry={() => void lib.refetch()} />
  if (!lib.data) return <LoadingState rows={8} />
  const title = new Map((types.data ?? []).map((x) => [x.type, x.title]))
  const items = lib.data.items.filter((i) => (!type || i.type === type) && `${i.name} ${i.type} ${i.description ?? ''} ${i.used_by.join(' ')}`.toLowerCase().includes(q.toLowerCase()))
  const groups = [...new Set(items.map((i) => i.type))].sort((a, b) => (title.get(a) ?? a).localeCompare(title.get(b) ?? b))
  const present = [...new Set(lib.data.items.map((i) => i.type))].sort((a, b) => (title.get(a) ?? a).localeCompare(title.get(b) ?? b))
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <div className="flex flex-wrap items-center gap-2">
        <SearchBox value={q} onChange={(v) => set({ q: v || undefined })} label={t('config.searchLibrary')} />
        <select className="field w-auto" aria-label={t('config.filterType')} value={type ?? ''} onChange={(e) => set({ type: e.target.value || undefined })}>
          <option value="">{t('config.allTypes')}</option>
          {present.map((x) => (
            <option key={x} value={x}>
              {title.get(x) ?? x}
            </option>
          ))}
        </select>
      </div>
      {!items.length && (
        <Card>
          <EmptyState icon={Search} title={t(lib.data.items.length ? 'config.noMatch' : 'config.libraryEmpty')}>
            {t('config.libraryEmptyBody')}
          </EmptyState>
        </Card>
      )}
      {groups.map((g) => {
        const rows = items.filter((i) => i.type === g)
        return (
          <Card
            key={g}
            title={
              <span className="flex flex-wrap items-baseline gap-2">
                {title.get(g) ?? g} <span className="num text-[12px] font-normal text-muted">{rows.length}</span> <span className="font-mono text-[11.5px] font-normal text-muted">{g}</span>
              </span>
            }
            bodyClass="!px-0 !pt-2 !pb-1"
          >
            <ul className="divide-y divide-line">
              {rows.map((i) => (
                <li key={i.id}>
                  <Link to="/config/library/$id" params={{ id: String(i.id) }} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-[var(--pad-card)] py-2.5 hover:bg-surface-2">
                    <div className="min-w-0 flex-1 basis-56">
                      <div className="flex flex-wrap items-center gap-2 font-medium">
                        {i.name}
                        {i.invalid && <Badge tone="bad">{t('config.sigInvalid')}</Badge>}
                        {i.read_only && <Badge tone="info">{t('config.shared')}</Badge>}
                      </div>
                      {i.description && <div className="truncate text-[12.5px] text-muted">{i.description}</div>}
                    </div>
                    <span className="flex flex-wrap gap-1 text-[12.5px]">
                      {i.used_by.length ? i.used_by.map((u) => <Badge key={u}>{u}</Badge>) : <span className="text-muted">{t('config.unused')}</span>}
                    </span>
                    <span className="w-28 text-right text-[12px] text-muted" title={dateTime(i.updated_at)}>
                      {ago(i.updated_at)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )
      })}
      <DeletedList kind="library" items={lib.data.deleted} />
    </div>
  )
}
