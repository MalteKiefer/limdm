// Updates ("Updates"): update rings with their waves, the fleet's open
// security updates and CVEs, and the installed versions of a package.
// Rules per source live in the com.limdm.updates declaration (configuration).
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { CheckCheck, Layers, Pause, PackageCheck, PackageSearch, Pencil, Play, Plus, ShieldCheck, Trash2, Waves } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../api/me'
import { BlueprintSelect } from '../../components/blueprintselect'
import { Field } from '../../components/form'
import { TabBar, TabPanel } from '../../components/layout'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal, PageHeader, Switch } from '../../components/ui'
import { useT } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { useCVEDevices, useFleet, useRingAction, useRingDelete, useRingSave, useRings, useVersions, useWaveStart, type Ring, type RingInput } from './api'
import { approvable, severityTone, splitList } from './logic'
import { mono, SourceLabel, Table } from './parts'

const tabs = ['rings', 'security', 'versions'] as const
type Tab = (typeof tabs)[number]
type Search = { tab?: string; cve?: string; pkg?: string }

export function UpdatesPage() {
  const t = useT()
  const search = useSearch({ strict: false }) as Search
  const nav = useNavigate()
  const tab = (tabs as readonly string[]).includes(search.tab ?? '') ? (search.tab as Tab) : 'rings'
  const go = (s: Search) => void nav({ to: '/updates', search: { ...search, ...s }, replace: true })
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader title={t('updates.title')} sub={t('updates.sub')} />
      <TabBar idBase="upd" label={t('updates.title')} value={tab} onChange={(v) => go({ tab: v === 'rings' ? undefined : v })} tabs={tabs.map((v) => ({ value: v, label: t(`updates.tab.${v}`) }))} />
      <TabPanel idBase="upd" value={tab}>
        {tab === 'rings' && <Rings />}
        {tab === 'security' && <Security cve={search.cve} setCve={(cve) => go({ cve })} />}
        {tab === 'versions' && <Versions pkg={search.pkg} setPkg={(pkg) => go({ pkg })} />}
      </TabPanel>
    </div>
  )
}

const empty: RingInput = {
  name: '',
  position: 1,
  deferral_days: 0,
  wave_days: 0,
  require_approval: false,
  all_devices: false,
  tags: [],
  groups: [],
  blueprints: [],
}

function Rings() {
  const t = useT()
  const admin = useCan('admin')
  const rings = useRings()
  const action = useRingAction()
  const wave = useWaveStart()
  const del = useRingDelete()
  const [edit, setEdit] = useState<{ id?: number; v: RingInput } | null>(null)
  const [drop, setDrop] = useState<Ring | null>(null)
  if (rings.error) return <ErrorState error={rings.error} onRetry={() => void rings.refetch()} />
  if (!rings.data) return <LoadingState rows={4} />
  const list = rings.data.items ?? []
  const act = (r: Ring, a: 'pause' | 'resume' | 'approve') =>
    action.mutate(
      { id: r.id!, action: a },
      {
        onSuccess: () => toast(t(`updates.ring.done.${a}`, { name: r.name! })),
        onError: (e) => toast(errorText(e), 'error'),
      },
    )
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card
        title={t('updates.rings.title')}
        sub={t('updates.rings.sub')}
        action={
          admin && (
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="btn"
                disabled={!list.length || wave.isPending}
                onClick={() =>
                  wave.mutate(undefined, {
                    onSuccess: (w) => toast(t('updates.wave.started', { wave: w.wave ?? 0 })),
                    onError: (e) => toast(errorText(e), 'error'),
                  })
                }
              >
                <Waves size={14} aria-hidden /> {t('updates.wave.start')}
              </button>
              <button type="button" className="btn btn-primary" onClick={() => setEdit({ v: { ...empty, position: list.length + 1 } })}>
                <Plus size={14} aria-hidden /> {t('updates.ring.add')}
              </button>
            </div>
          )
        }
      >
        {list.length ? (
          <Table
            caption={t('updates.rings.title')}
            cols={[
              { label: t('updates.ring.name') },
              { label: t('updates.ring.members') },
              { label: t('updates.ring.deferral'), className: 'text-right' },
              { label: t('updates.ring.wave') },
              { label: t('updates.ring.devices'), className: 'text-right' },
              ...(admin ? [{ label: '' }] : []),
            ]}
            rows={list.map((r) => ({
              key: String(r.id),
              cells: [
                <div>
                  <div className="font-medium">
                    {r.position}. {r.name}
                  </div>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {r.paused ? (
                      <Badge tone="warn">
                        <Pause size={12} aria-hidden /> {t('updates.ring.paused')}
                      </Badge>
                    ) : (
                      <Badge tone="ok">
                        <Play size={12} aria-hidden /> {t('updates.ring.active')}
                      </Badge>
                    )}
                    {r.require_approval && (
                      <Badge tone="info">
                        {t('updates.ring.approvalBadge', {
                          wave: r.approved_wave ?? 0,
                        })}
                      </Badge>
                    )}
                  </div>
                </div>,
                <span className="text-muted">{members(t, r)}</span>,
                r.position === list.find((x) => x.tenant_id === r.tenant_id)?.position ? (r.wave_days ? t('updates.ring.every', { count: r.wave_days }) : t('updates.ring.manual')) : t('updates.ring.days', { count: r.deferral_days ?? 0 }),
                r.wave ? (
                  <span>
                    {t('updates.ring.waveN', { wave: r.wave })} <span className="text-muted">{r.wave_at ? dateTime(r.wave_at) : ''}</span>
                  </span>
                ) : (
                  <span className="text-muted">{t('updates.ring.noWave')}</span>
                ),
                fmt(r.devices ?? 0),
                ...(admin
                  ? [
                      <div className="flex flex-wrap justify-end gap-1">
                        {approvable(list, r) && (
                          <button type="button" className="btn" onClick={() => act(r, 'approve')}>
                            <CheckCheck size={14} aria-hidden /> {t('updates.ring.approve')}
                          </button>
                        )}
                        <button type="button" className="btn" onClick={() => act(r, r.paused ? 'resume' : 'pause')}>
                          {r.paused ? <Play size={14} aria-hidden /> : <Pause size={14} aria-hidden />} {r.paused ? t('updates.ring.resume') : t('updates.ring.pause')}
                        </button>
                        <button type="button" className="btn btn-ghost" aria-label={`${t('updates.ring.edit')}: ${r.name}`} onClick={() => setEdit({ id: r.id, v: toInput(r) })}>
                          <Pencil size={14} aria-hidden />
                        </button>
                        <button type="button" className="btn btn-ghost" aria-label={`${t('common.delete')}: ${r.name}`} onClick={() => setDrop(r)}>
                          <Trash2 size={14} aria-hidden />
                        </button>
                      </div>,
                    ]
                  : []),
              ],
            }))}
            empty=""
          />
        ) : (
          <EmptyState
            icon={Layers}
            title={t('updates.rings.none')}
            action={
              admin && (
                <button type="button" className="btn btn-primary" onClick={() => setEdit({ v: { ...empty, name: 'pilot' } })}>
                  <Plus size={14} aria-hidden /> {t('updates.ring.add')}
                </button>
              )
            }
          >
            {t('updates.rings.noneBody')}
          </EmptyState>
        )}
        <p className="mt-3 text-[12.5px] text-muted">{t('updates.rings.unassigned', { count: rings.data.unassigned ?? 0 })}</p>
      </Card>
      <Card title={t('updates.waves.title')} sub={t('updates.waves.sub')}>
        <Table
          caption={t('updates.waves.title')}
          cols={[{ label: t('updates.ring.wave') }, { label: t('updates.waves.at') }, { label: t('updates.waves.by') }]}
          rows={(rings.data.waves ?? []).map((w) => ({
            key: `${w.tenant_id}-${w.wave}`,
            cells: [t('updates.ring.waveN', { wave: w.wave ?? 0 }), dateTime(w.started_at!), w.started_by],
          }))}
          empty={t('updates.waves.none')}
        />
      </Card>
      <Card title={t('updates.rules.title')}>
        <p className="text-muted">{t('updates.rules.body')}</p>
        <Link to="/config" search={{ tab: 'library' } as never} className="mt-2 inline-flex text-accent hover:underline">
          {t('updates.rules.link')}
        </Link>
      </Card>
      {edit && <RingForm init={edit} onClose={() => setEdit(null)} />}
      <Confirm
        open={!!drop}
        onClose={() => setDrop(null)}
        title={t('updates.ring.deleteTitle', { name: drop?.name ?? '' })}
        body={t('updates.ring.deleteBody')}
        confirm={t('common.delete')}
        danger
        busy={del.isPending}
        onConfirm={() =>
          drop &&
          del.mutate(drop.id!, {
            onSuccess: () => {
              toast(t('updates.ring.deleted'))
              setDrop(null)
            },
            onError: (e) => toast(errorText(e), 'error'),
          })
        }
      />
    </div>
  )
}

function members(t: ReturnType<typeof useT>, r: Ring): string {
  if (r.all_devices) return t('updates.ring.all')
  const parts = [...(r.tags ?? []).map((x) => `#${x}`), ...(r.groups ?? []), ...(r.blueprints ?? []).map((b) => t('updates.ring.blueprintN', { id: b }))]
  return parts.length ? parts.join(', ') : t('updates.ring.nobody')
}

const toInput = (r: Ring): RingInput => ({
  name: r.name ?? '',
  position: r.position ?? 1,
  deferral_days: r.deferral_days ?? 0,
  wave_days: r.wave_days ?? 0,
  require_approval: !!r.require_approval,
  all_devices: !!r.all_devices,
  tags: r.tags ?? [],
  groups: r.groups ?? [],
  blueprints: r.blueprints ?? [],
})

function RingForm({ init, onClose }: { init: { id?: number; v: RingInput }; onClose: () => void }) {
  const t = useT()
  const save = useRingSave()
  const [v, setV] = useState(init.v)
  const [tags, setTags] = useState((init.v.tags ?? []).join(', '))
  const [groups, setGroups] = useState((init.v.groups ?? []).join(', '))
  const [err, setErr] = useState<{ field?: string; text: string } | null>(null)
  const set = (p: Partial<RingInput>) => setV({ ...v, ...p })
  const errFor = (f: string) => (err && (err.field === f || (!err.field && f === 'name')) ? err.text : undefined)
  const num = (s: string) => Math.max(0, Number.parseInt(s, 10) || 0)
  const submit = () =>
    save.mutate(
      {
        id: init.id,
        body: { ...v, tags: splitList(tags), groups: splitList(groups) },
      },
      {
        onSuccess: () => {
          toast(t('updates.ring.saved'))
          onClose()
        },
        onError: (e) =>
          setErr({
            field: (e as { problem?: { field?: string } }).problem?.field,
            text: errorText(e),
          }),
      },
    )
  return (
    <Modal
      open
      wide
      onClose={onClose}
      title={init.id ? t('updates.ring.edit') : t('updates.ring.add')}
      description={t('updates.ring.formSub')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="submit" form="ring-form" className="btn btn-primary" disabled={save.isPending}>
            {t('common.save')}
          </button>
        </>
      }
    >
      <form
        id="ring-form"
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <Field label={t('updates.ring.name')} required error={errFor('name')}>
          {({ id, describedBy, invalid }) => <input id={id} className="field" required maxLength={64} value={v.name} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => set({ name: e.target.value })} />}
        </Field>
        <Field label={t('updates.ring.position')} help={t('updates.ring.positionHelp')} error={errFor('position')}>
          {({ id, describedBy, invalid }) => (
            <input id={id} className="field" type="number" min={1} max={100} value={v.position} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => set({ position: num(e.target.value) })} />
          )}
        </Field>
        <Field label={t('updates.ring.deferral')} help={t('updates.ring.deferralHelp')} error={errFor('deferral_days')}>
          {({ id, describedBy, invalid }) => (
            <input id={id} className="field" type="number" min={0} max={90} value={v.deferral_days} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => set({ deferral_days: num(e.target.value) })} />
          )}
        </Field>
        <Field label={t('updates.ring.waveDays')} help={t('updates.ring.waveDaysHelp')} error={errFor('wave_days')}>
          {({ id, describedBy, invalid }) => (
            <input id={id} className="field" type="number" min={0} max={90} value={v.wave_days} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => set({ wave_days: num(e.target.value) })} />
          )}
        </Field>
        <Field label={t('updates.ring.tags')} help={t('updates.ring.listHelp')} error={errFor('tags')}>
          {({ id, describedBy, invalid }) => <input id={id} className="field" value={tags} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setTags(e.target.value)} />}
        </Field>
        <Field label={t('updates.ring.groups')} help={t('updates.ring.listHelp')} error={errFor('groups')}>
          {({ id, describedBy, invalid }) => <input id={id} className="field" value={groups} aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setGroups(e.target.value)} />}
        </Field>
        <Field label={t('updates.ring.blueprint')} help={t('updates.ring.blueprintHelp')} error={errFor('blueprints')}>
          {({ id, describedBy }) => <BlueprintSelect id={id} describedBy={describedBy} value={v.blueprints?.[0] ?? 0} noneLabel={t('updates.ring.noBlueprint')} onChange={(b) => set({ blueprints: b ? [b] : [] })} />}
        </Field>
        <div className="flex flex-col gap-3 pt-6">
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={!!v.all_devices} onChange={(x) => set({ all_devices: x })} label={t('updates.ring.all')} /> {t('updates.ring.all')}
          </label>
          <label className="flex items-center gap-2 text-[13px]">
            <Switch checked={!!v.require_approval} onChange={(x) => set({ require_approval: x })} label={t('updates.ring.requireApproval')} /> {t('updates.ring.requireApproval')}
          </label>
        </div>
      </form>
    </Modal>
  )
}

function Security({ cve, setCve }: { cve?: string; setCve: (c?: string) => void }) {
  const t = useT()
  const fleet = useFleet()
  const devices = useCVEDevices(cve ?? '')
  if (fleet.error) return <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />
  const f = fleet.data
  if (!f) return <LoadingState rows={6} />
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <div className="grid gap-[var(--gap)] sm:grid-cols-2 xl:grid-cols-4">
        {(
          [
            ['updates.kpi.security', f.security_devices],
            ['updates.kpi.pending', f.pending_devices],
            ['updates.kpi.cves', f.cves?.length ?? 0],
            ['updates.kpi.reporting', f.reporting],
          ] as const
        ).map(([k, n]) => (
          <Card key={k}>
            <div className="text-[12.5px] text-muted">{t(k)}</div>
            <div className="text-[24px] font-semibold tabular-nums">{fmt(n ?? 0)}</div>
          </Card>
        ))}
      </div>
      <Card title={t('updates.cves.title')} sub={t('updates.cves.sub')}>
        {f.cves?.length ? (
          <Table
            caption={t('updates.cves.title')}
            cols={[{ label: 'CVE' }, { label: t('updates.severity') }, { label: t('updates.devicesCol'), className: 'text-right' }, { label: t('updates.packages') }]}
            rows={f.cves.map((c) => ({
              key: c.id!,
              cells: [
                <button type="button" className="font-mono text-[12.5px] text-accent hover:underline" aria-expanded={cve === c.id} onClick={() => setCve(cve === c.id ? undefined : c.id)}>
                  {c.id}
                </button>,
                c.severity ? <Badge tone={severityTone(c.severity)}>{c.severity}</Badge> : <span className="text-muted">{t('updates.unknown')}</span>,
                fmt(c.devices ?? 0),
                <span className="text-muted">{(c.packages ?? []).join(', ')}</span>,
              ],
            }))}
            empty=""
          />
        ) : (
          <EmptyState icon={ShieldCheck} title={t('updates.cves.none')}>
            {t('updates.cves.noneBody')}
          </EmptyState>
        )}
        {(f.security_no_cve ?? 0) > 0 && <p className="mt-3 text-[12.5px] text-muted">{t('updates.cves.noIds', { count: f.security_no_cve ?? 0 })}</p>}
      </Card>
      {cve && (
        <Card title={t('updates.cves.devices', { cve })}>
          {devices.error ? (
            <ErrorState error={devices.error} />
          ) : !devices.data ? (
            <LoadingState rows={2} />
          ) : (
            <Table
              caption={t('updates.cves.devices', { cve })}
              cols={[{ label: t('updates.device') }, { label: t('updates.packages') }]}
              rows={devices.data.items.map((d) => ({
                key: d.id,
                cells: [
                  <Link to="/devices/$id" params={{ id: d.id }} search={{ tab: 'updates' } as never} className="text-accent hover:underline">
                    {d.hostname || d.id}
                  </Link>,
                  <span className="text-muted">{d.packages.join(', ')}</span>,
                ],
              }))}
              empty={t('updates.cves.noDevices')}
            />
          )}
        </Card>
      )}
      <Card title={t('updates.pkgs.title')} sub={t('updates.pkgs.sub')}>
        <Table
          caption={t('updates.pkgs.title')}
          cols={[{ label: t('updates.package') }, { label: t('updates.sourceCol') }, { label: t('updates.severity') }, { label: t('updates.devicesCol'), className: 'text-right' }]}
          rows={(f.packages ?? []).map((p) => ({
            key: `${p.name}-${p.source}`,
            cells: [
              mono(p.name),
              <SourceLabel source={p.source} />,
              p.security ? <Badge tone={severityTone(p.severity) === 'neutral' ? 'warn' : severityTone(p.severity)}>{p.severity || t('updates.security')}</Badge> : <span className="text-muted">{t('updates.no')}</span>,
              fmt(p.devices ?? 0),
            ],
          }))}
          empty={t('updates.pkgs.none')}
        />
      </Card>
    </div>
  )
}

function Versions({ pkg, setPkg }: { pkg?: string; setPkg: (p?: string) => void }) {
  const t = useT()
  const [text, setText] = useState(pkg ?? '')
  const versions = useVersions(pkg ?? '')
  return (
    <Card title={t('updates.versions.title')} sub={t('updates.versions.sub')}>
      <form
        className="mb-4 flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          setPkg(text.trim() || undefined)
        }}
      >
        <Field label={t('updates.package')}>{({ id }) => <input id={id} className="field font-mono" value={text} placeholder="openssl" onChange={(e) => setText(e.target.value)} />}</Field>
        <button type="submit" className="btn btn-primary">
          <PackageSearch size={14} aria-hidden /> {t('updates.versions.show')}
        </button>
      </form>
      {!pkg ? (
        <EmptyState icon={PackageCheck} title={t('updates.versions.pick')}>
          {t('updates.versions.pickBody')}
        </EmptyState>
      ) : versions.error ? (
        <ErrorState error={versions.error} />
      ) : !versions.data ? (
        <LoadingState rows={3} />
      ) : (
        <Table
          caption={t('updates.versions.title')}
          cols={[{ label: t('updates.version') }, { label: t('updates.arch') }, { label: t('updates.devicesCol'), className: 'text-right' }]}
          rows={(versions.data.items ?? []).map((v) => ({
            key: `${v.version}-${v.arch}`,
            cells: [mono(v.version), v.arch, fmt(v.devices ?? 0)],
          }))}
          empty={t('updates.versions.none', { name: pkg })}
        />
      )}
    </Card>
  )
}
