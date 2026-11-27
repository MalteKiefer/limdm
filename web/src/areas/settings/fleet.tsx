// Fleet sections: directory (Google Workspace, SCIM, groups to
// blueprints), network certificates (network CA, CRL token) and agent
// updates (policy, releases, spread in the fleet).
import { Ban, Check, Download, FolderTree, RefreshCw, Search, Wifi } from 'lucide-react'
import { useDeferredValue, useState } from 'react'
import { z } from '../../lib/zod'
import { api, unwrap, type Schemas } from '../../api/client'
import { useCan, useMe } from '../../api/me'
import { StackBar } from '../../components/charts'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { FormSection } from '../../components/form'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge } from '../../components/ui'
import { ago, dateTime, fmt } from '../../i18n/format'
import { useT, type MessageKey } from '../../i18n'
import { useAction, useAgents, useBlueprintNames, useDirectory, useDirectoryUsers, useNetwork, useSaveSection, useSettings } from './api'
import { Confirm, Facts, ListField, OnceSecret, SectionHead, SettingsForm, TextField, Toggle } from '../../components/settingsform'

// ---- directory ----

export function Directory() {
  const t = useT()
  const admin = useCan('admin')
  const q = useDirectory()
  const bps = useBlueprintNames()
  const [token, setToken] = useState('')
  const [rotate, setRotate] = useState(false)
  const key = ['settings', 'directory']
  const scim = useAction(key, () => unwrap(api.POST('/api/v1/directory/scim-token')))
  const sync = useAction(key, () => unwrap(api.POST('/api/v1/directory/google/sync')), (r) => r.message)
  const google = useAction(key, (body: { admin_email: string; service_account: string }) => unwrap(api.PUT('/api/v1/directory/google', { body })))
  const assign = useAction(key, (v: { id: number; blueprint_id: number; priority: number }) => unwrap(api.PUT('/api/v1/directory/groups/{id}', { params: { path: { id: v.id } }, body: { blueprint_id: v.blueprint_id, priority: v.priority } })), t('settings.saved'))
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const d = q.data
  const blueprints = (bps.data?.items ?? []).filter((b) => b.id != null) as { id: number; name?: string }[]
  type G = Schemas['DirectoryGroup']
  const columns: GridColumn<G>[] = [
    { id: 'name', header: t('settings.dir.group'), cell: (c) => <span className="flex flex-col"><span className="font-medium">{c.row.original.name}</span><span className="text-meta text-muted">{c.row.original.source}</span></span> },
    { id: 'members', header: t('settings.dir.members'), cell: (c) => <span className="num">{fmt(c.row.original.members)}</span> },
    {
      id: 'bp',
      header: t('settings.dir.blueprint'),
      cell: (c) => {
        const g = c.row.original
        return (
          <select
            className="field max-w-56"
            aria-label={t('settings.dir.blueprintFor', { name: g.name })}
            disabled={!admin}
            value={g.blueprint_id ?? 0}
            onChange={(e) => void assign.mutate({ id: g.id, blueprint_id: Number(e.target.value), priority: g.priority ?? 100 })}
          >
            <option value={0}>{t('settings.none')}</option>
            {blueprints.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
              </option>
            ))}
          </select>
        )
      },
    },
    {
      id: 'prio',
      header: t('settings.dir.priority'),
      cell: (c) => {
        const g = c.row.original
        return (
          <input
            type="number"
            min={0}
            max={10000}
            className="field w-24"
            aria-label={t('settings.dir.priorityFor', { name: g.name })}
            disabled={!admin || !g.blueprint_id}
            defaultValue={g.priority ?? 100}
            onBlur={(e) => {
              const p = Number(e.target.value)
              if (g.blueprint_id && p !== (g.priority ?? 100) && p >= 0 && p <= 10000) void assign.mutate({ id: g.id, blueprint_id: g.blueprint_id, priority: p })
            }}
          />
        )
      },
    },
  ]
  return (
    <>
      <SectionHead title={t('settings.nav.directory')} sub={t('settings.dir.sub')} />
      <FormSection title="Google Workspace" description={t('settings.dir.googleHelp')}>
        <Facts
          rows={[
            [t('settings.dir.state'), d.google.configured ? <Badge tone="ok">{t('settings.dir.configured')}</Badge> : <Badge tone="off">{t('settings.dir.notConfigured')}</Badge>],
            [t('settings.dir.lastSync'), d.google.last_sync ? `${dateTime(d.google.last_sync)} · ${d.google.last_result}` : t('settings.never')],
          ]}
        />
        {admin && (
          <SettingsForm
            schema={z.object({ admin_email: z.string().trim().email(t('settings.users.emailBad')), service_account: z.string().refine((v) => !v.trim() || v.includes('"private_key"'), t('settings.dir.keyBad')) })}
            values={{ admin_email: d.google.admin_email, service_account: '' }}
            okText={t('settings.dir.synced')}
            onSave={(v) => google.mutateAsync(v)}
          >
            {(f) => (
              <div className="flex flex-col gap-4">
                <TextField form={f} name="admin_email" label={t('settings.dir.adminEmail')} help={t('settings.dir.adminEmailHelp')} required />
                <ListField form={f} name="service_account" label={t('settings.dir.key')} help={d.google.configured ? t('settings.dir.keyKept') : t('settings.dir.keyHelp')} placeholder='{"type": "service_account", …}' rows={3} />
              </div>
            )}
          </SettingsForm>
        )}
        {admin && d.google.configured && (
          <button type="button" className="btn self-start" disabled={sync.isPending} onClick={() => void sync.mutate(undefined)}>
            <RefreshCw size={14} aria-hidden /> {t('settings.dir.syncNow')}
          </button>
        )}
      </FormSection>
      <FormSection title="SCIM" description={t('settings.dir.scimHelp')}>
        <Facts
          rows={[
            [t('settings.dir.scimUrl'), <code className="font-mono text-meta break-all">{d.scim.url}</code>],
            [t('settings.dir.state'), d.scim.configured ? <Badge tone="ok">{t('settings.dir.tokenSet')}</Badge> : <Badge tone="off">{t('settings.dir.noToken')}</Badge>],
          ]}
        />
        <p className="text-meta text-muted">{t('settings.dir.scimNets')}</p>
        {admin && (
          <button type="button" className="btn self-start" onClick={() => setRotate(true)}>
            {d.scim.configured ? t('settings.dir.rotate') : t('settings.dir.create')}
          </button>
        )}
      </FormSection>
      <section className="py-6">
        <h3 className="font-semibold">{t('settings.dir.groups')}</h3>
        <p className="mb-3 text-body text-muted">{t('settings.dir.groupsHelp')}</p>
        <DataGrid label={t('settings.dir.groups')} data={d.groups} columns={columns} getRowId={(g) => String(g.id)} maxHeight="420px" empty={<EmptyState icon={FolderTree} title={t('settings.dir.noGroups')}>{t('settings.dir.noGroupsBody')}</EmptyState>} card={(g) => <span>{g.name} · {fmt(g.members)}</span>} />
        <p className="mt-3 text-meta text-muted">
          {t('settings.dir.roleGroups', { n: d.role_groups.length })}{' '}
          <a className="text-accent underline-offset-2 hover:underline" href="/app/settings?s=signin">
            {t('settings.nav.signin')}
          </a>
        </p>
      </section>
      <People />
      <Confirm
        open={rotate}
        onClose={() => setRotate(false)}
        title={t('settings.dir.rotate')}
        body={t('settings.dir.rotateBody')}
        confirm={d.scim.configured ? t('settings.dir.rotate') : t('settings.dir.create')}
        danger={d.scim.configured}
        busy={scim.isPending}
        onConfirm={() =>
          void scim.mutateAsync(undefined).then((r) => {
            setRotate(false)
            setToken(r.token)
          })
        }
      />
      {token && <OnceSecret title={t('settings.dir.tokenTitle')} value={token} onClose={() => setToken('')} />}
    </>
  )
}

function People() {
  const t = useT()
  const [q, setQ] = useState('')
  const deferred = useDeferredValue(q)
  const users = useDirectoryUsers(deferred.trim())
  type U = Schemas['DirectoryUser']
  const columns: GridColumn<U>[] = [
    { id: 'name', header: t('settings.dir.person'), cell: (c) => <span className="flex flex-col"><span className="font-medium">{c.row.original.display_name || c.row.original.user_name}</span><span className="text-meta text-muted">{c.row.original.email}</span></span> },
    { id: 'dept', header: t('settings.dir.department'), cell: (c) => [c.row.original.department, c.row.original.title].filter(Boolean).join(' · ') },
    { id: 'groups', header: t('settings.dir.groups'), cell: (c) => c.row.original.groups.join(', ') },
    { id: 'state', header: t('settings.tokens.state'), cell: (c) => (c.row.original.active ? <Badge tone="ok">{t('settings.tenants.active')}</Badge> : <Badge tone="off">{t('settings.users.disabled')}</Badge>) },
    { id: 'src', header: t('settings.dir.source'), cell: (c) => <span className="text-meta">{c.row.original.source} · {ago(c.row.original.updated_at)}</span> },
  ]
  return (
    <section className="pb-6">
      <h3 className="font-semibold">{t('settings.dir.people')}</h3>
      <label className="relative mt-2 mb-3 block max-w-md">
        <span className="sr-only">{t('settings.dir.search')}</span>
        <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" aria-hidden />
        <input className="field pl-8" type="search" placeholder={t('settings.dir.search')} value={q} onChange={(e) => setQ(e.target.value)} />
      </label>
      {users.isError ? (
        <ErrorState error={users.error} />
      ) : (
        <DataGrid label={t('settings.dir.people')} data={users.data?.items ?? []} columns={columns} getRowId={(u) => String(u.id)} maxHeight="420px" empty={users.isPending ? <LoadingState rows={3} /> : <EmptyState title={t('settings.dir.noPeople')} />} card={(u) => <span>{u.display_name || u.email}</span>} />
      )}
    </section>
  )
}

// ---- network ----

const domainRe = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

/** The DNS domain of the certificates' DNS SAN (global setting). */
function CertDomain() {
  const t = useT()
  const q = useSettings()
  const save = useSaveSection('network')
  if (q.isPending) return <LoadingState rows={2} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  return (
    <SettingsForm
      schema={z.object({ network_cert_domain: z.string().trim().toLowerCase().refine((v) => !v || (v.length <= 200 && domainRe.test(v)), t('settings.net.domainBad')) })}
      values={{ network_cert_domain: q.data.network_cert_domain ?? '' }}
      onSave={(v) => save.mutateAsync(v)}
    >
      {(f) => (
        <FormSection title={t('settings.net.domain')} description={t('settings.net.domainHelp')}>
          <TextField form={f} name="network_cert_domain" label={t('settings.net.domainLabel')} placeholder="devices.example.com" mono />
        </FormSection>
      )}
    </SettingsForm>
  )
}

export function Network() {
  const t = useT()
  const admin = useCan('admin')
  const me = useMe()
  const global = admin && !(me.tenant && !me.super) && !me.scope_tags.length && !me.scope_groups.length
  const q = useNetwork()
  const [rotate, setRotate] = useState(false)
  const [token, setToken] = useState('')
  const crl = useAction(['settings', 'network'], () => unwrap(api.POST('/api/v1/network/crl-token')))
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const n = q.data
  type C = Schemas['NetworkCert']
  const tone = { valid: 'ok', expired: 'off', revoked: 'bad' } as const
  const columns: GridColumn<C>[] = [
    { id: 'host', header: t('settings.net.device'), cell: (c) => <a className="font-mono text-accent underline-offset-2 hover:underline" href={`/app/devices?sel=${encodeURIComponent(c.row.original.device_id)}`}>{c.row.original.hostname || c.row.original.device_id}</a> },
    { id: 'subject', header: t('settings.net.subject'), cell: (c) => <span className="flex flex-col"><span className="font-mono text-meta">{c.row.original.subject}</span><span className="text-meta text-muted">{c.row.original.sans}</span></span> },
    { id: 'valid', header: t('settings.net.valid'), cell: (c) => `${dateTime(c.row.original.not_before)} – ${dateTime(c.row.original.not_after)}` },
    { id: 'state', header: t('settings.tokens.state'), cell: (c) => <span className="flex flex-col"><Badge tone={tone[c.row.original.state]}>{t(`settings.net.state.${c.row.original.state}` as MessageKey)}</Badge>{c.row.original.reason && <span className="text-meta text-muted">{c.row.original.reason}</span>}</span> },
    { id: 'serial', header: t('settings.net.serial'), cell: (c) => <code className="font-mono text-micro">{c.row.original.serial}</code> },
  ]
  return (
    <>
      <SectionHead
        title={t('settings.nav.network')}
        sub={t('settings.net.sub')}
        actions={
          <a className="btn" href={n.ca_url} download>
            <Download size={14} aria-hidden /> {t('settings.net.caDownload')}
          </a>
        }
      />
      <FormSection title={t('settings.net.ca')} description={t('settings.net.caHelp')}>
        <Facts
          rows={[
            [t('settings.net.subject'), <span className="font-mono text-meta">{n.ca_subject}</span>],
            [t('settings.net.fingerprint'), <code className="font-mono text-meta break-all">{n.ca_fingerprint}</code>],
            [t('settings.net.until'), dateTime(n.ca_not_after)],
          ]}
        />
      </FormSection>
      {global && <CertDomain />}
      <FormSection title={t('settings.net.crl')} description={t('settings.net.crlHelp')}>
        <Facts
          rows={[
            ['URL', <code className="font-mono text-meta break-all">{n.crl_url}</code>],
            [t('settings.dir.state'), n.crl_token_set ? <Badge tone="ok">{t('settings.dir.tokenSet')}</Badge> : <Badge tone="off">{t('settings.dir.noToken')}</Badge>],
          ]}
        />
        {admin && (
          <button type="button" className="btn self-start" onClick={() => setRotate(true)}>
            {n.crl_token_set ? t('settings.dir.rotate') : t('settings.dir.create')}
          </button>
        )}
      </FormSection>
      <section className="py-6">
        <h3 className="mb-3 font-semibold">{t('settings.net.certs')}</h3>
        <DataGrid label={t('settings.net.certs')} data={n.certs} columns={columns} getRowId={(c) => c.serial} maxHeight="520px" empty={<EmptyState icon={Wifi} title={t('settings.net.none')}>{t('settings.net.noneBody')}</EmptyState>} card={(c) => <span className="font-mono">{c.hostname} · {t(`settings.net.state.${c.state}` as MessageKey)}</span>} />
      </section>
      <Confirm
        open={rotate}
        onClose={() => setRotate(false)}
        title={t('settings.net.crlRotate')}
        body={t('settings.net.crlRotateBody')}
        confirm={t('settings.dir.rotate')}
        danger={n.crl_token_set}
        busy={crl.isPending}
        onConfirm={() =>
          void crl.mutateAsync(undefined).then((r) => {
            setRotate(false)
            setToken(r.token)
          })
        }
      />
      {token && <OnceSecret title={t('settings.net.crlToken')} value={token} onClose={() => setToken('')} />}
    </>
  )
}

// ---- agents ----

export function Agents() {
  const t = useT()
  const admin = useCan('admin')
  const q = useAgents()
  const [older, setOlder] = useState(false)
  const [block, setBlock] = useState('')
  const key = ['settings', 'agents']
  const policy = useAction(key, (body: Schemas['UpdatePolicy']) => unwrap(api.PUT('/api/v1/agents/policy', { body })))
  const fetchR = useAction(key, () => unwrap(api.POST('/api/v1/agents/fetch')), t('settings.agents.checked'))
  const release = useAction(key, (v: { version: string; op: 'approve' | 'block' }) => unwrap(api.POST('/api/v1/agents/releases/{version}/{op}', { params: { path: v } })), t('settings.saved'))
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const a = q.data
  const rels = older ? a.releases : a.releases.filter((r) => !r.older)
  const total = a.fleet.reduce((s, f) => s + f.devices, 0)
  type R = Schemas['AgentRelease']
  const columns: GridColumn<R>[] = [
    { id: 'v', header: t('settings.agents.version'), cell: (c) => <span className="flex items-center gap-1.5 font-mono">{c.row.original.version}{c.row.original.version === a.latest && <Badge tone="accent">{t('settings.agents.latest')}</Badge>}</span> },
    { id: 'pub', header: t('settings.agents.published'), cell: (c) => <span className="flex flex-col"><span>{dateTime(c.row.original.published_at)}</span>{c.row.original.signed && <span className="text-meta text-muted">{t('settings.agents.signed')}</span>}</span> },
    {
      id: 'state',
      header: t('settings.tokens.state'),
      cell: (c) => {
        const r = c.row.original
        if (r.blocked) return <span className="flex flex-col"><Badge tone="bad">{t('settings.agents.blocked')}</Badge><span className="text-meta text-muted">{r.blocked_reason}</span></span>
        if (r.approved_at) return <span className="flex flex-col"><Badge tone="ok">{t('settings.agents.approved')}</Badge><span className="text-meta text-muted">{r.approved_by} · {ago(r.approved_at)}</span></span>
        return <Badge tone="warn">{t('settings.agents.waiting')}</Badge>
      },
    },
    { id: 'dev', header: t('settings.agents.devices'), cell: (c) => <span className="flex flex-col"><span className="num">{fmt(c.row.original.devices)}</span>{c.row.original.failed > 0 && <span className="text-meta text-bad">{t('settings.agents.failed', { n: c.row.original.failed })}</span>}</span> },
    ...(admin
      ? [
          {
            id: 'act',
            header: '',
            cell: (c: { row: { original: R } }) => {
              const r = c.row.original
              return (
                <span className="flex gap-1">
                  {(!r.approved_at || r.blocked) && (
                    <button type="button" className="btn" onClick={() => void release.mutate({ version: r.version, op: 'approve' })}>
                      <Check size={14} aria-hidden /> {t('settings.agents.approve')}
                    </button>
                  )}
                  {!r.blocked && (
                    <button type="button" className="btn btn-ghost" onClick={() => setBlock(r.version)}>
                      <Ban size={14} aria-hidden /> {t('settings.agents.block')}
                    </button>
                  )}
                </span>
              )
            },
          } as GridColumn<R>,
        ]
      : []),
  ]
  const palette = ['var(--c-s1)', 'var(--c-s2)', 'var(--c-s3)', 'var(--c-s4)', 'var(--c-s5)']
  return (
    <>
      <SectionHead
        title={t('settings.nav.agents')}
        sub={t('settings.agents.sub', { repo: a.repo })}
        actions={
          admin && (
            <button type="button" className="btn" disabled={fetchR.isPending} onClick={() => void fetchR.mutate(undefined)}>
              <RefreshCw size={14} aria-hidden /> {t('settings.agents.fetch')}
            </button>
          )
        }
      />
      <SettingsForm
        readOnly={!admin}
        schema={z.object({
          auto: z.boolean(),
          delay_days: z.number({ message: t('settings.err.number') }).int().min(0, t('settings.agents.delayRange')).max(90, t('settings.agents.delayRange')),
          spread_hours: z.number({ message: t('settings.err.number') }).int().min(0, t('settings.agents.spreadRange')).max(720, t('settings.agents.spreadRange')),
          pilot_tag: z.string().trim().max(32).regex(/^([a-zA-Z0-9][a-zA-Z0-9_.-]*)?$/, t('settings.agents.pilotBad')),
        })}
        values={a.policy}
        onSave={(v) => policy.mutateAsync({ ...v, pilot_tag: v.pilot_tag.trim().toLowerCase() })}
      >
        {(f) => (
          <FormSection title={t('settings.agents.policy')} description={t('settings.agents.policyHelp')}>
            <Toggle form={f} name="auto" label={t('settings.agents.auto')} help={t('settings.agents.autoHelp')} />
            <TextField form={f} name="pilot_tag" label={t('settings.agents.pilot')} help={t('settings.agents.pilotHelp')} placeholder="pilot" mono />
            <TextField form={f} name="delay_days" type="number" label={t('settings.agents.delay')} help={t('settings.agents.delayHelp')} />
            <TextField form={f} name="spread_hours" type="number" label={t('settings.agents.spread')} help={t('settings.agents.spreadHelp')} />
          </FormSection>
        )}
      </SettingsForm>
      {total > 0 && (
        <FormSection title={t('settings.agents.fleet')} description={a.outdated.length ? t('settings.agents.outdated', { n: a.outdated.length, v: a.latest }) : t('settings.agents.current')}>
          <StackBar label={t('settings.agents.fleet')} parts={a.fleet.map((x, i) => ({ label: x.version || t('settings.agents.unknown'), value: x.devices, color: palette[i % palette.length], note: fmt(x.devices) }))} />
          {a.outdated.length > 0 && (
            <ul className="flex max-h-40 flex-col gap-0.5 overflow-y-auto text-body">
              {a.outdated.slice(0, 50).map((d) => (
                <li key={d.id}>
                  <a className="font-mono text-accent underline-offset-2 hover:underline" href={`/app/devices?sel=${encodeURIComponent(d.id)}`}>{d.hostname}</a> <span className="text-muted">{d.version || '?'}</span>
                </li>
              ))}
            </ul>
          )}
        </FormSection>
      )}
      <section className="py-6">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-semibold">{t('settings.agents.releases')}</h3>
          {a.releases.some((r) => r.older) && (
            <button type="button" className="btn btn-ghost" onClick={() => setOlder((v) => !v)}>
              {older ? t('settings.agents.hideOlder') : t('settings.agents.showOlder', { n: a.releases.filter((r) => r.older).length })}
            </button>
          )}
        </div>
        <DataGrid label={t('settings.agents.releases')} data={rels} columns={columns} getRowId={(r) => r.version} maxHeight="520px" empty={<EmptyState title={t('settings.agents.none')}>{t('settings.agents.noneBody')}</EmptyState>} card={(r) => <span className="font-mono">{r.version}</span>} />
      </section>
      <Confirm
        open={!!block}
        onClose={() => setBlock('')}
        title={t('settings.agents.block')}
        body={t('settings.agents.blockBody', { v: block })}
        confirm={t('settings.agents.block')}
        danger
        busy={release.isPending}
        onConfirm={() => void release.mutateAsync({ version: block, op: 'block' }).finally(() => setBlock(''))}
      />
    </>
  )
}
