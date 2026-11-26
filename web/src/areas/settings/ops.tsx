// Operations sections: server keys and their rotation, notification
// channels with the compliance webhook, and backup (targets, schedules with
// a live preview, recipients, history).
import { Bell, CircleCheck, CirclePlay, DatabaseBackup, Pause, Pencil, Play, Plus, Send, ShieldCheck, Trash2, TriangleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { FieldValues, Path, UseFormReturn } from 'react-hook-form'
import { z } from 'zod'
import { api, unwrap, type Schemas } from '../../api/client'
import { useCan, useMe } from '../../api/me'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { FormSection } from '../../components/form'
import { EmptyState, ErrorState, errorText, LoadingState } from '../../components/states'
import { ActionMenu, Badge, Modal } from '../../components/ui'
import { ago, bytes, dateTime, fmt } from '../../i18n/format'
import { useT, type MessageKey } from '../../i18n'
import { useAction, useBackup, useChannels, useKeys, useSettings } from './api'
import { Confirm, Facts, ListField, SectionHead, SelectField, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { badTime, cleanSchedule, keepEmpty, lines, parseTimes, unlines, weekOrder, type Keep, type Schedule } from './logic'
import { Monitoring } from './server'

// ---- keys ----

export function Keys() {
  const t = useT()
  const q = useKeys()
  const [act, setAct] = useState<{ kind: string; op: 'rotate' | 'finish' } | null>(null)
  const [name, setName] = useState('')
  const [force, setForce] = useState(false)
  const run = useAction(['settings', 'keys'], (v: { kind: 'ca' | 'netca' | 'command' | 'session' | 'webhook'; op: 'rotate' | 'finish'; name: string; force: boolean }) =>
    unwrap(api.POST('/api/v1/keys/{kind}/{op}', { params: { path: { kind: v.kind, op: v.op } }, body: { name: v.name, force: v.force } })),
    (r) => r.message || t('settings.saved'),
  )
  if (q.isPending) return <LoadingState rows={5} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  type K = Schemas['KeyStatus']
  const columns: GridColumn<K>[] = [
    { id: 'kind', header: t('settings.keys.key'), cell: (c) => <span className="font-medium">{t(`settings.keys.kind.${c.row.original.kind}` as MessageKey)}</span> },
    { id: 'active', header: t('settings.keys.active'), cell: (c) => <code className="font-mono text-[12px] break-all">{c.row.original.active}</code> },
    {
      id: 'prev',
      header: t('settings.keys.retiring'),
      cell: (c) =>
        c.row.original.previous ? (
          <span className="flex flex-col">
            <code className="font-mono text-[12px] break-all">{c.row.original.previous}</code>
            {c.row.original.since && <span className="text-[12px] text-muted">{dateTime(c.row.original.since)}</span>}
          </span>
        ) : (
          <span className="text-muted">{t('settings.none')}</span>
        ),
    },
    {
      id: 'progress',
      header: t('settings.keys.progress'),
      cell: (c) => {
        const k = c.row.original
        if (!k.previous) return k.restart ? <Badge tone="bad">{t('settings.keys.restart')}</Badge> : null
        return (
          <span className="flex flex-col gap-1">
            {k.kind === 'session' ? t('settings.keys.sealed', { n: k.total }) : <span className="num">{fmt(k.done)} / {fmt(k.total)}</span>}
            {k.kind !== 'session' && k.total > 0 && (
              <progress className="h-1.5 w-28 accent-[var(--c-accent)]" max={k.total} value={k.done} aria-label={t('settings.keys.progress')} />
            )}
            {k.restart && <Badge tone="bad">{t('settings.keys.restart')}</Badge>}
          </span>
        )
      },
    },
    { id: 'loc', header: t('settings.keys.stored'), cell: (c) => <span className="font-mono text-[12px]">{c.row.original.location}</span> },
    {
      id: 'act',
      header: '',
      cell: (c) => {
        const k = c.row.original
        if (k.previous) return <button type="button" className="btn" onClick={() => setAct({ kind: k.kind, op: 'finish' })}>{t('settings.keys.finish')}</button>
        if (k.kind === 'session') return <code className="font-mono text-[11.5px] text-muted">limdm-server keys rotate session</code>
        return <button type="button" className="btn" onClick={() => setAct({ kind: k.kind, op: 'rotate' })}>{t('settings.keys.rotate')}</button>
      },
    },
  ]
  return (
    <>
      <SectionHead title={t('settings.nav.keys')} sub={t('settings.keys.sub')} />
      <div className="py-4">
        <DataGrid label={t('settings.nav.keys')} data={q.data.items} columns={columns} getRowId={(k) => k.kind} maxHeight="none" card={(k) => <span className="font-medium">{t(`settings.keys.kind.${k.kind}` as MessageKey)}</span>} />
      </div>
      <Confirm
        open={!!act}
        onClose={() => setAct(null)}
        title={act?.op === 'finish' ? t('settings.keys.finish') : t('settings.keys.rotate')}
        body={act?.op === 'finish' ? t('settings.keys.finishBody') : act?.kind === 'webhook' ? t('settings.keys.webhookBody') : t('settings.keys.rotateBody')}
        confirm={act?.op === 'finish' ? t('settings.keys.finish') : t('settings.keys.rotate')}
        danger={act?.op === 'finish'}
        busy={run.isPending}
        onConfirm={() =>
          act &&
          void run.mutateAsync({ kind: act.kind as 'ca', op: act.op, name: name.trim(), force }).then(() => {
            setAct(null)
            setName('')
            setForce(false)
          })
        }
      >
        {act?.op === 'rotate' && act.kind !== 'webhook' && (
          <label className="flex flex-col gap-1 text-[13px] font-medium">
            {t('settings.keys.newName')}
            <input className="field font-mono" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
        )}
        {act?.op === 'finish' && act.kind !== 'session' && (
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} /> {t('settings.keys.force')}
          </label>
        )}
      </Confirm>
    </>
  )
}

// ---- notifications ----

type Channel = Schemas['Channel']

export function Notifications() {
  const t = useT()
  const me = useMe()
  const admin = useCan('admin')
  const q = useChannels()
  const [adding, setAdding] = useState(false)
  const [del, setDel] = useState<Channel | null>(null)
  const key = ['settings', 'channels']
  const toggle = useAction(key, (v: { id: number; enabled: boolean }) => unwrap(api.PATCH('/api/v1/notification-channels/{id}', { params: { path: { id: v.id } }, body: { enabled: v.enabled } })))
  const remove = useAction(key, (id: number) => unwrap(api.DELETE('/api/v1/notification-channels/{id}', { params: { path: { id } } })), t('settings.notify.deleted'))
  const test = useAction(key, (id: number) => unwrap(api.POST('/api/v1/notification-channels/{id}/test', { params: { path: { id } } })), t('settings.notify.testOk'))
  if (q.isPending) return <LoadingState rows={5} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const labels = Object.fromEntries(q.data.events.map((e) => [e.type, e.label]))
  const columns: GridColumn<Channel>[] = [
    {
      id: 'name',
      header: t('settings.notify.channel'),
      cell: (c) => (
        <span className="flex flex-col">
          <span className="font-medium">{c.row.original.name}</span>
          <span className="font-mono text-[12px] text-muted">{c.row.original.target}</span>
        </span>
      ),
    },
    {
      id: 'kind',
      header: t('settings.notify.kind'),
      cell: (c) => (
        <span className="flex flex-wrap gap-1">
          {t(`settings.notify.k.${c.row.original.kind}` as MessageKey)}
          {!c.row.original.enabled && <Badge tone="off">{t('settings.notify.off')}</Badge>}
          {c.row.original.global && me.tenant && <Badge tone="info">{t('settings.users.global')}</Badge>}
        </span>
      ),
    },
    { id: 'events', header: t('settings.notify.events'), cell: (c) => (c.row.original.events.length ? c.row.original.events.map((e) => t(`settings.notify.e.${e}` as MessageKey) || labels[e]).join(', ') : <span className="text-muted">{t('settings.notify.allEvents')}</span>) },
    {
      id: 'last',
      header: t('settings.notify.last'),
      cell: (c) => {
        const x = c.row.original
        if (x.last_ok == null) return <span className="text-muted">{t('settings.never')}</span>
        return (
          <span className="flex flex-col">
            <span className="flex items-center gap-1.5">
              <Badge tone={x.last_ok ? 'ok' : 'bad'}>{x.last_ok ? t('settings.notify.delivered') : t('settings.notify.failed')}</Badge>
              {x.last_at && <span className="text-[12px] text-muted">{ago(x.last_at)}</span>}
            </span>
            {!x.last_ok && <span className="text-[12px] text-bad">{x.last_error}</span>}
          </span>
        )
      },
    },
    ...(admin
      ? [
          {
            id: 'act',
            header: '',
            cell: (c: { row: { original: Channel } }) => (
              <ActionMenu
                trigger={
                  <button type="button" className="btn btn-ghost px-2" aria-label={t('settings.notify.actions', { name: c.row.original.name })}>
                    ⋯
                  </button>
                }
                items={[
                  { label: t('settings.notify.test'), icon: Send, onClick: () => void test.mutateAsync(c.row.original.id).catch(() => undefined) },
                  { label: c.row.original.enabled ? t('settings.notify.disable') : t('settings.notify.enable'), icon: c.row.original.enabled ? Pause : Play, onClick: () => void toggle.mutate({ id: c.row.original.id, enabled: !c.row.original.enabled }) },
                  'sep',
                  { label: t('common.delete'), icon: Trash2, danger: true, onClick: () => setDel(c.row.original) },
                ]}
              />
            ),
          } as GridColumn<Channel>,
        ]
      : []),
  ]
  return (
    <>
      <SectionHead
        title={t('settings.nav.notifications')}
        sub={t('settings.notify.sub')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={() => setAdding(true)}>
              <Plus size={14} aria-hidden /> {t('settings.notify.add')}
            </button>
          )
        }
      />
      <div className="py-4">
        <DataGrid
          label={t('settings.nav.notifications')}
          data={q.data.items}
          columns={columns}
          getRowId={(x) => String(x.id)}
          maxHeight="none"
          empty={<EmptyState icon={Bell} title={t('settings.notify.none')}>{t('settings.notify.noneBody')}</EmptyState>}
          card={(x) => (
            <span className="flex flex-col">
              <span className="font-medium">{x.name}</span>
              <span className="text-[12px] text-muted">{t(`settings.notify.k.${x.kind}` as MessageKey)}</span>
            </span>
          )}
        />
        {q.data.tenant_signing_key && (
          <div className="mt-4">
            <Facts
              rows={[
                [t('settings.notify.tenantKey'), <code className="font-mono text-[12px] break-all">{q.data.tenant_signing_key}</code>],
                [t('settings.monitor.header'), <code className="font-mono text-[12px] break-all">{`X-LiMDM-Signature: sha256=HMAC-SHA256(key, timestamp + "." + "${q.data.tenant_id}" + "." + body), X-LiMDM-Tenant: ${q.data.tenant_id}`}</code>],
              ]}
            />
          </div>
        )}
      </div>
      {!me.tenant && <GlobalMonitoring />}
      {adding && <AddChannel events={q.data.events} onClose={() => setAdding(false)} />}
      <Confirm
        open={!!del}
        onClose={() => setDel(null)}
        title={t('settings.notify.deleteTitle')}
        body={del?.name}
        confirm={t('common.delete')}
        danger
        busy={remove.isPending}
        onConfirm={() => del && void remove.mutateAsync(del.id).then(() => setDel(null))}
      />
    </>
  )
}

function GlobalMonitoring() {
  const q = useSettings()
  const admin = useCan('admin')
  const save = useAction(['settings', 'server'], (body: Schemas['SettingsInput']) => unwrap(api.PATCH('/api/v1/settings/{section}', { params: { path: { section: 'monitoring' } }, body })))
  if (!q.data) return null
  return <Monitoring s={q.data} ro={!admin} save={(_, body) => save.mutateAsync(body)} />
}

function AddChannel({ events, onClose }: { events: { type: string; label: string }[]; onClose: () => void }) {
  const t = useT()
  const add = useAction(['settings', 'channels'], (body: Schemas['ChannelInput']) => unwrap(api.POST('/api/v1/notification-channels', { body })))
  const schema = z
    .object({
      kind: z.enum(['slack', 'discord', 'email', 'webhook']),
      name: z.string().trim().min(1, t('settings.err.required')).max(80),
      url: z.string(),
      host: z.string(),
      port: z.number({ message: t('settings.err.number') }).int().min(1).max(65535),
      tls: z.enum(['starttls', 'tls']),
      user: z.string(),
      password: z.string(),
      from: z.string(),
      to: z.string(),
      events: z.array(z.string()),
    })
    .superRefine((v, ctx) => {
      if (v.kind !== 'email' && !/^https:\/\/\S+$/.test(v.url.trim())) ctx.addIssue({ code: 'custom', path: ['url'], message: t('settings.notify.urlBad') })
      if (v.kind === 'email') {
        if (!v.host.trim()) ctx.addIssue({ code: 'custom', path: ['host'], message: t('settings.err.required') })
        if (!v.from.trim()) ctx.addIssue({ code: 'custom', path: ['from'], message: t('settings.err.required') })
        if (!lines(v.to).length) ctx.addIssue({ code: 'custom', path: ['to'], message: t('settings.err.required') })
      }
    })
  return (
    <Modal open wide onClose={onClose} title={t('settings.notify.add')} description={t('settings.notify.addHelp')}>
      <SettingsForm
        schema={schema}
        values={{ kind: 'slack', name: '', url: '', host: '', port: 587, tls: 'starttls', user: '', password: '', from: '', to: '', events: [] }}
        okText={t('settings.notify.added')}
        onSave={async (v) => {
          const kind = v.kind as Schemas['ChannelInput']['kind']
          await add.mutateAsync(
            kind === 'email'
              ? { kind, name: v.name.trim(), events: v.events, password: v.password, config: { host: v.host.trim(), port: v.port, tls: v.tls as 'tls', user: v.user.trim(), from: v.from.trim(), to: lines(v.to) } }
              : { kind, name: v.name.trim(), events: v.events, url: v.url.trim() },
          )
          onClose()
        }}
      >
        {(f) => {
          const kind = f.watch('kind')
          return (
            <div className="flex flex-col gap-4">
              <fieldset>
                <legend className="mb-2 text-[13px] font-medium">{t('settings.notify.kind')}</legend>
                <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                  {(['slack', 'discord', 'email', 'webhook'] as const).map((k) => (
                    <label key={k} className="flex cursor-pointer flex-col rounded-md border border-line p-2.5 text-[13px] has-[:checked]:border-accent has-[:checked]:bg-accent-soft">
                      <span className="flex items-center gap-2 font-medium">
                        <input type="radio" value={k} {...f.register('kind')} /> {t(`settings.notify.k.${k}` as MessageKey)}
                      </span>
                      <span className="text-[12px] text-muted">{t(`settings.notify.kh.${k}` as MessageKey)}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
              <TextField form={f} name="name" label={t('settings.tokens.name')} placeholder={t('settings.notify.namePh')} required />
              {kind !== 'email' ? (
                <TextField form={f} name="url" type="url" label={t('settings.notify.url')} help={t('settings.notify.urlHelp')} placeholder="https://…" mono required />
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  <TextField form={f} name="host" label={t('settings.notify.smtp')} placeholder="smtp.example.com" mono required />
                  <div className="grid grid-cols-2 gap-3">
                    <TextField form={f} name="port" type="number" label={t('settings.notify.port')} />
                    <SelectField form={f} name="tls" label={t('settings.notify.tls')} options={[{ value: 'starttls', label: 'STARTTLS' }, { value: 'tls', label: 'TLS' }]} />
                  </div>
                  <TextField form={f} name="user" label={t('settings.notify.user')} />
                  <TextField form={f} name="password" type="password" autoComplete="new-password" label={t('settings.notify.password')} help={t('settings.notify.sealed')} />
                  <TextField form={f} name="from" label={t('settings.notify.from')} placeholder="LiMDM <mdm@example.com>" required />
                  <TextField form={f} name="to" label={t('settings.notify.to')} help={t('settings.notify.toHelp')} placeholder="it@example.com, security@example.com" required />
                </div>
              )}
              <fieldset className="flex flex-col gap-1.5">
                <legend className="text-[13px] font-medium">{t('settings.notify.events')}</legend>
                <p className="text-[12.5px] text-muted">{t('settings.notify.eventsHelp')}</p>
                <div className="grid gap-1.5 md:grid-cols-2">
                  {events.map((e) => (
                    <label key={e.type} className="flex items-start gap-2 text-[13px]">
                      <input type="checkbox" className="mt-1" value={e.type} {...f.register('events')} />
                      <span>
                        {t(`settings.notify.e.${e.type}` as MessageKey) || e.label} <code className="font-mono text-[11px] text-muted">{e.type}</code>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>
          )
        }}
      </SettingsForm>
    </Modal>
  )
}

// ---- backup ----

type Backup = Schemas['Backup']
type Target = Schemas['BackupTarget']

const keepKeys = ['last', 'days', 'daily', 'weekly', 'monthly', 'yearly'] as const

function KeepFields<T extends FieldValues>({ form, prefix }: { form: UseFormReturn<T>; prefix: string }) {
  const t = useT()
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
      {keepKeys.map((k) => (
        <TextField key={k} form={form} name={`${prefix}.${k}` as Path<T>} type="number" label={t(`settings.backup.keep.${k}` as MessageKey)} />
      ))}
    </div>
  )
}

const keepSchema = z.object(Object.fromEntries(keepKeys.map((k) => [k, z.union([z.nan(), z.number().int().min(0).max(3660)])])))
const keepIn = (k: Keep) => Object.fromEntries(keepKeys.map((x) => [x, k[x] || NaN]))
const keepOut = (k: Record<string, number>): Keep => Object.fromEntries(keepKeys.map((x) => [x, Number.isNaN(k[x]) ? 0 : k[x]]))

export function Backup() {
  const t = useT()
  const q = useBackup()
  const [target, setTarget] = useState<Target | 'new' | null>(null)
  const [sched, setSched] = useState<Schedule | 'new' | null>(null)
  const [delTarget, setDelTarget] = useState('')
  const [delSched, setDelSched] = useState('')
  const key = ['settings', 'backup']
  const run = useAction(key, () => unwrap(api.POST('/api/v1/backup/run')), t('settings.backup.started'))
  const general = useAction(key, (body: Schemas['BackupInput']) => unwrap(api.PUT('/api/v1/backup', { body })))
  const test = useAction(key, (name: string) => unwrap(api.POST('/api/v1/backup/targets/{name}/test', { params: { path: { name } } })), (r) => r.message)
  const removeT = useAction(key, (name: string) => unwrap(api.DELETE('/api/v1/backup/targets/{name}', { params: { path: { name } } })), t('settings.backup.targetRemoved'))
  const removeS = useAction(key, (name: string) => unwrap(api.DELETE('/api/v1/backup/schedules/{name}', { params: { path: { name } } })), t('settings.backup.scheduleRemoved'))
  const op = useAction(key, (v: { name: string; op: 'run' | 'pause' | 'resume' }) => unwrap(api.POST('/api/v1/backup/schedules/{name}/{op}', { params: { path: v } })))
  const verify = useAction(key, (id: number) => unwrap(api.POST('/api/v1/backup/{id}/verify', { params: { path: { id } } })), t('settings.backup.verified'))
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const b: Backup = q.data
  return (
    <>
      <SectionHead
        title={t('settings.nav.backup')}
        sub={t('settings.backup.sub')}
        actions={
          <button type="button" className="btn btn-primary" disabled={run.isPending || !b.targets.length} onClick={() => void run.mutate(undefined)}>
            <DatabaseBackup size={14} aria-hidden /> {t('settings.backup.now')}
          </button>
        }
      />
      <FormSection title={t('settings.backup.state')} description={t('settings.backup.stateHelp')}>
        <Facts
          rows={[
            [t('settings.backup.schedules'), fmt(b.schedules.length)],
            [t('settings.backup.zone'), <span className="font-mono">{b.zone}</span>],
            [
              t('settings.backup.rule'),
              b.rule_321 ? (
                <Badge tone="ok">{t('settings.backup.ruleMet')}</Badge>
              ) : (
                <span className="flex flex-wrap items-center gap-1.5">
                  <Badge tone="warn">{t('settings.backup.ruleNot')}</Badge> <span className="text-[12.5px] text-muted">{t('settings.backup.ruleHelp')}</span>
                </span>
              ),
            ],
          ]}
        />
      </FormSection>
      <SettingsForm
        schema={z.object({ recipients: z.string().refine((v) => lines(v).every((x) => /^age1[0-9a-z]{58}$/.test(x)), t('settings.backup.ageBad')), time_zone: z.string(), keep: keepSchema })}
        values={{ recipients: unlines(b.recipients), time_zone: b.time_zone, keep: keepIn(b.keep) }}
        onSave={(v) => general.mutateAsync({ recipients: lines(v.recipients), time_zone: v.time_zone.trim(), keep: keepOut(v.keep) })}
      >
        {(f) => (
          <FormSection title={t('settings.backup.general')} description={t('settings.backup.generalHelp')}>
            <ListField form={f} name="recipients" label={t('settings.backup.recipients')} help={t('settings.backup.recipientsHelp')} placeholder="age1…" />
            <TextField form={f} name="time_zone" label={t('settings.backup.tz')} help={t('settings.backup.tzHelp')} placeholder="Europe/Berlin" />
            <fieldset className="flex flex-col gap-2">
              <legend className="text-[13px] font-medium">{t('settings.backup.keepOutside')}</legend>
              <KeepFields form={f} prefix="keep" />
              <p className="text-[12.5px] text-muted">{t('settings.backup.keepHelp')}</p>
            </fieldset>
          </FormSection>
        )}
      </SettingsForm>

      <FormSection title={t('settings.backup.targets')} description={t('settings.backup.targetsHelp')}>
        {b.targets.length === 0 && <p className="text-muted">{t('settings.backup.noTarget')}</p>}
        <ul className="flex flex-col divide-y divide-line">
          {b.targets.map((x) => (
            <li key={x.name} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <span className="min-w-0">
                <span className="font-mono font-medium">{x.name}</span> <Badge>{t(`settings.backup.kind.${x.kind}` as MessageKey)}</Badge> {x.lock_mode && <Badge tone="ok">Object Lock {x.lock_mode}, {x.lock_days} d</Badge>}
                <span className="block truncate font-mono text-[12px] text-muted">{where(x)}</span>
              </span>
              <span className="flex gap-1">
                <button type="button" className="btn" disabled={test.isPending} onClick={() => void test.mutate(x.name)}>
                  <CircleCheck size={14} aria-hidden /> {t('settings.backup.test')}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setTarget(x)} aria-label={`${t('settings.backup.edit')} ${x.name}`}>
                  <Pencil size={14} aria-hidden />
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setDelTarget(x.name)} aria-label={`${t('settings.backup.remove')} ${x.name}`}>
                  <Trash2 size={14} aria-hidden />
                </button>
              </span>
            </li>
          ))}
        </ul>
        <button type="button" className="btn self-start" onClick={() => setTarget('new')}>
          <Plus size={14} aria-hidden /> {t('settings.backup.addTarget')}
        </button>
      </FormSection>

      <FormSection title={t('settings.backup.schedules')} description={t('settings.backup.schedulesHelp')}>
        {b.schedules.length === 0 && <p className="text-muted">{t('settings.backup.noSchedule')}</p>}
        <ul className="flex flex-col divide-y divide-line">
          {b.schedules.map((s) => (
            <li key={s.name} className="flex flex-wrap items-start justify-between gap-2 py-2">
              <span className="min-w-0">
                <span className="font-mono font-medium">{s.name}</span> {s.paused && <Badge tone="off">{t('settings.backup.paused')}</Badge>}
                <span className="block text-[12.5px]">{describe(t, s as Schedule)}</span>
                <span className="block text-[12px] text-muted">
                  {s.next.length ? `${t('settings.backup.next')} ${dateTime(s.next[0])}` : ''} · {t('settings.backup.keeps', { kept: s.preview.kept, runs: s.preview.runs })} · {s.targets.join(', ')}
                </span>
              </span>
              <span className="flex gap-1">
                <button type="button" className="btn" onClick={() => void op.mutate({ name: s.name, op: 'run' })}>
                  <CirclePlay size={14} aria-hidden /> {t('settings.backup.runOne')}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => void op.mutate({ name: s.name, op: s.paused ? 'resume' : 'pause' })} aria-label={`${s.paused ? t('settings.backup.resume') : t('settings.backup.pause')} ${s.name}`}>
                  {s.paused ? <Play size={14} aria-hidden /> : <Pause size={14} aria-hidden />}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setSched(s as Schedule)} aria-label={`${t('settings.backup.edit')} ${s.name}`}>
                  <Pencil size={14} aria-hidden />
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setDelSched(s.name)} aria-label={`${t('common.delete')} ${s.name}`}>
                  <Trash2 size={14} aria-hidden />
                </button>
              </span>
            </li>
          ))}
        </ul>
        <button type="button" className="btn self-start" disabled={!b.targets.length} onClick={() => setSched('new')}>
          <Plus size={14} aria-hidden /> {t('settings.backup.addSchedule')}
        </button>
      </FormSection>

      <History rows={b.history} onVerify={(id) => void verify.mutate(id)} />

      {target && <TargetForm target={target === 'new' ? null : target} onClose={() => setTarget(null)} />}
      {sched && <ScheduleForm schedule={sched === 'new' ? null : sched} targets={b.targets.map((x) => x.name)} onClose={() => setSched(null)} />}
      <Confirm open={!!delTarget} onClose={() => setDelTarget('')} title={t('settings.backup.remove')} body={t('settings.backup.removeBody')} confirm={t('settings.backup.remove')} danger busy={removeT.isPending} onConfirm={() => void removeT.mutateAsync(delTarget).finally(() => setDelTarget(''))} />
      <Confirm open={!!delSched} onClose={() => setDelSched('')} title={t('common.delete')} body={t('settings.backup.deleteSchedule')} confirm={t('common.delete')} danger busy={removeS.isPending} onConfirm={() => void removeS.mutateAsync(delSched).finally(() => setDelSched(''))} />
    </>
  )
}

function where(x: Target) {
  switch (x.kind) {
    case 's3':
      return `${x.endpoint}/${x.bucket}${x.prefix ? `/${x.prefix}` : ''}`
    case 'b2':
      return `b2 ${x.region}/${x.bucket}${x.prefix ? `/${x.prefix}` : ''}`
    case 'webdav':
      return x.endpoint ?? ''
    case 'sftp':
      return `${x.user}@${x.host}:${x.dir}`
    default:
      return x.dir ?? ''
  }
}

const dayKey = (d: number) => `settings.backup.day.${d}` as MessageKey

function describe(t: ReturnType<typeof useT>, s: Schedule) {
  switch (s.kind) {
    case 'interval':
      return t('settings.backup.desc.interval', { n: s.every ?? 0, offset: s.offset ?? 0 })
    case 'weekly':
      return t('settings.backup.desc.weekly', { days: weekOrder.filter((d) => s.days?.includes(d)).map((d) => t(dayKey(d))).join(', '), times: (s.times ?? []).join(', ') })
    case 'monthly':
      return t('settings.backup.desc.monthly', { day: s.day ?? 1, times: (s.times ?? []).join(', ') })
    case 'cron':
      return `cron ${s.cron}`
  }
}

function History({ rows, onVerify }: { rows: Schemas['BackupRun'][]; onVerify: (id: number) => void }) {
  const t = useT()
  type R = Schemas['BackupRun']
  const columns: GridColumn<R>[] = [
    { id: 'at', header: t('settings.backup.started'), cell: (c) => dateTime(c.row.original.started_at) },
    { id: 'reason', header: t('settings.backup.reason'), cell: (c) => <span className="flex flex-col"><span>{c.row.original.reason}</span><span className="text-[12px] text-muted">{c.row.original.actor}</span></span> },
    { id: 'size', header: t('settings.backup.size'), cell: (c) => <span className="num">{bytes(c.row.original.size)}</span> },
    {
      id: 'status',
      header: t('settings.tokens.state'),
      cell: (c) => {
        const r = c.row.original
        return (
          <span className="flex flex-col gap-0.5">
            <span className="flex flex-wrap gap-1">
              <Badge tone={r.status === 'ok' ? 'ok' : r.status === 'running' ? 'info' : 'bad'}>{r.status}</Badge>
              {r.deleted_at && <Badge tone="off">{t('settings.backup.deleted')}</Badge>}
              {r.verified_at && !r.verify_error && <Badge tone="ok"><ShieldCheck size={12} aria-hidden /> {t('settings.backup.checked')}</Badge>}
              {r.restore_tested_at && !r.restore_test_error && <Badge tone="ok">{t('settings.backup.restoreTested')}</Badge>}
            </span>
            {(r.error || r.verify_error || r.restore_test_error) && (
              <span className="flex items-start gap-1 text-[12px] text-bad">
                <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden /> {r.error || r.verify_error || r.restore_test_error}
              </span>
            )}
          </span>
        )
      },
    },
    { id: 'targets', header: t('settings.backup.targets'), cell: (c) => c.row.original.targets.join(', ') },
    { id: 'act', header: '', cell: (c) => c.row.original.status === 'ok' && !c.row.original.deleted_at && <button type="button" className="btn btn-ghost" onClick={() => onVerify(c.row.original.id)}>{t('settings.backup.verify')}</button> },
  ]
  return (
    <section className="py-6">
      <h3 className="mb-1 font-semibold">{t('settings.backup.history')}</h3>
      <p className="mb-3 text-[13px] text-muted">{t('settings.backup.historyHelp')}</p>
      <DataGrid label={t('settings.backup.history')} data={rows} columns={columns} getRowId={(r) => String(r.id)} maxHeight="480px" empty={<EmptyState icon={DatabaseBackup} title={t('settings.backup.noHistory')} />} card={(r) => <span>{dateTime(r.started_at)} · {r.status}</span>} />
    </section>
  )
}

function TargetForm({ target, onClose }: { target: Target | null; onClose: () => void }) {
  const t = useT()
  const save = useAction(['settings', 'backup'], (v: { name: string; body: Schemas['BackupTargetInput'] }) => unwrap(api.PUT('/api/v1/backup/targets/{name}', { params: { path: { name: v.name } }, body: v.body })))
  const x = target
  const schema = z
    .object({
      name: z.string().trim().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/, t('settings.backup.nameBad')),
      kind: z.enum(['local', 's3', 'b2', 'sftp', 'webdav']),
      dir: z.string(),
      endpoint: z.string(),
      region: z.string(),
      bucket: z.string(),
      prefix: z.string(),
      access_key: z.string(),
      path_style: z.boolean(),
      lock_mode: z.enum(['', 'GOVERNANCE', 'COMPLIANCE']),
      lock_days: z.union([z.nan(), z.number().int().min(0)]),
      host: z.string(),
      port: z.union([z.nan(), z.number().int().min(1).max(65535)]),
      user: z.string(),
      host_key: z.string(),
      secret: z.string(),
      private_key: z.string(),
    })
    .superRefine((v, ctx) => {
      const need = (k: keyof typeof v) => !String(v[k]).trim() && ctx.addIssue({ code: 'custom', path: [k], message: t('settings.err.required') })
      if (v.kind === 'local' || v.kind === 'sftp') need('dir')
      if (v.kind === 's3' || v.kind === 'webdav') need('endpoint')
      if (v.kind === 's3' || v.kind === 'b2') need('bucket')
      if (v.kind === 'b2') need('region')
      if (v.kind === 'sftp') {
        need('host')
        need('user')
        need('host_key')
      }
      if ((v.kind === 's3' || v.kind === 'webdav') && v.endpoint.trim() && !v.endpoint.trim().startsWith('https://')) ctx.addIssue({ code: 'custom', path: ['endpoint'], message: t('settings.notify.urlBad') })
    })
  return (
    <Modal open wide onClose={onClose} title={x ? `${t('settings.backup.edit')} ${x.name}` : t('settings.backup.addTarget')} description={t('settings.backup.targetHelp')}>
      <SettingsForm
        schema={schema}
        values={{
          name: x?.name ?? '',
          kind: (x?.kind ?? 'local') as 'local',
          dir: x?.dir ?? '',
          endpoint: x?.endpoint ?? '',
          region: x?.region ?? '',
          bucket: x?.bucket ?? '',
          prefix: x?.prefix ?? '',
          access_key: x?.access_key ?? '',
          path_style: !!x?.path_style,
          lock_mode: (x?.lock_mode ?? '') as '',
          lock_days: x?.lock_days || NaN,
          host: x?.host ?? '',
          port: x?.port || NaN,
          user: x?.user ?? '',
          host_key: x?.host_key ?? '',
          secret: '',
          private_key: '',
        }}
        okText={t('settings.saved')}
        onSave={async (v) => {
          const { name, ...rest } = v
          await save.mutateAsync({ name: name.trim(), body: { ...rest, kind: rest.kind as 'local', lock_mode: rest.lock_mode as '', lock_days: rest.lock_days || 0, port: rest.port || 0 } })
          onClose()
        }}
      >
        {(f) => {
          const kind = f.watch('kind')
          const s3 = kind === 's3' || kind === 'b2'
          return (
            <div className="grid gap-4 md:grid-cols-2">
              <TextField form={f} name="name" label={t('settings.tokens.name')} placeholder="offsite" required mono />
              <SelectField form={f} name="kind" label={t('settings.notify.kind')} options={(['local', 's3', 'b2', 'sftp', 'webdav'] as const).map((k) => ({ value: k, label: t(`settings.backup.kind.${k}` as MessageKey) }))} />
              {(kind === 'local' || kind === 'sftp') && <TextField form={f} name="dir" label={t('settings.backup.dir')} placeholder="/srv/backup/limdm" mono required />}
              {(kind === 's3' || kind === 'webdav') && <TextField form={f} name="endpoint" label={t('settings.backup.endpoint')} placeholder={kind === 's3' ? 'https://s3.eu-central-1.amazonaws.com' : 'https://dav.example.com/limdm'} mono required />}
              {s3 && (
                <>
                  <TextField form={f} name="region" label={t('settings.backup.region')} placeholder={kind === 'b2' ? 'us-west-004' : 'eu-central-1'} required={kind === 'b2'} />
                  <TextField form={f} name="bucket" label={t('settings.backup.bucket')} required />
                  <TextField form={f} name="prefix" label={t('settings.backup.prefix')} placeholder="limdm" />
                  <TextField form={f} name="access_key" label={t('settings.backup.accessKey')} mono />
                </>
              )}
              {kind === 'sftp' && (
                <>
                  <TextField form={f} name="host" label={t('settings.backup.host')} mono required />
                  <TextField form={f} name="port" type="number" label={t('settings.notify.port')} placeholder="22" />
                  <TextField form={f} name="user" label={t('settings.notify.user')} required />
                  <TextField form={f} name="host_key" label={t('settings.backup.hostKey')} help={t('settings.backup.hostKeyHelp')} mono required />
                </>
              )}
              {kind === 'webdav' && <TextField form={f} name="user" label={t('settings.notify.user')} />}
              {kind !== 'local' && (
                <TextField form={f} name="secret" type="password" autoComplete="new-password" label={kind === 'sftp' || kind === 'webdav' ? t('settings.notify.password') : t('settings.backup.secretKey')} help={x?.has_secret ? t('settings.backup.secretKept') : t('settings.notify.sealed')} />
              )}
              {kind === 'sftp' && (
                <div className="md:col-span-2">
                  <ListField form={f} name="private_key" label={t('settings.backup.privateKey')} help={x?.has_key ? t('settings.backup.secretKept') : t('settings.notify.sealed')} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" rows={3} />
                </div>
              )}
              {s3 && (
                <>
                  {kind === 's3' && <Toggle form={f} name="path_style" label={t('settings.backup.pathStyle')} />}
                  <SelectField form={f} name="lock_mode" label={t('settings.backup.lock')} help={t('settings.backup.lockHelp')} options={[{ value: '', label: t('settings.none') }, { value: 'GOVERNANCE', label: 'GOVERNANCE' }, { value: 'COMPLIANCE', label: 'COMPLIANCE' }]} />
                  {f.watch('lock_mode') && <TextField form={f} name="lock_days" type="number" label={t('settings.backup.lockDays')} />}
                </>
              )}
            </div>
          )
        }}
      </SettingsForm>
    </Modal>
  )
}

/** Debounced preview of a schedule: next runs and what its retention keeps. */
function usePreview(s: Schedule, valid: boolean) {
  const [state, setState] = useState<{ data?: Schemas['BackupSchedule']; error?: string }>({})
  const key = JSON.stringify(s)
  useEffect(() => {
    if (!valid) return
    const id = setTimeout(() => {
      unwrap(api.POST('/api/v1/backup/schedules/preview', { body: cleanSchedule(s) as Schemas['BackupScheduleInput'] })).then(
        (data) => setState({ data }),
        (e: unknown) => setState({ error: errorText(e) }),
      )
    }, 350)
    return () => clearTimeout(id)
    // the key is the content of s
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, valid])
  return state
}

function ScheduleForm({ schedule, targets, onClose }: { schedule: Schedule | null; targets: string[]; onClose: () => void }) {
  const t = useT()
  const save = useAction(['settings', 'backup'], (s: Schedule) => unwrap(api.PUT('/api/v1/backup/schedules/{name}', { params: { path: { name: s.name } }, body: cleanSchedule(s) as Schemas['BackupScheduleInput'] })))
  const x = schedule
  const schema = z
    .object({
      name: z.string().trim().regex(/^[a-z0-9_]{1,32}$/, t('settings.backup.schedNameBad')),
      paused: z.boolean(),
      kind: z.enum(['interval', 'weekly', 'monthly', 'cron']),
      every: z.number({ message: t('settings.err.number') }).int().min(1).max(168),
      offset: z.number({ message: t('settings.err.number') }).int().min(0).max(1439),
      days: z.array(z.string()),
      times: z.string(),
      day: z.number({ message: t('settings.err.number') }).int().min(1).max(31),
      cron: z.string(),
      targets: z.array(z.string()).min(1, t('settings.backup.targetNeeded')),
      keep: keepSchema,
    })
    .superRefine((v, ctx) => {
      if ((v.kind === 'weekly' || v.kind === 'monthly') && (!parseTimes(v.times).length || badTime(v.times))) ctx.addIssue({ code: 'custom', path: ['times'], message: t('settings.backup.timesBad') })
      if (v.kind === 'weekly' && !v.days.length) ctx.addIssue({ code: 'custom', path: ['days'], message: t('settings.backup.daysNeeded') })
      if (v.kind === 'cron' && v.cron.trim().split(/\s+/).length !== 5) ctx.addIssue({ code: 'custom', path: ['cron'], message: t('settings.backup.cronBad') })
      if (keepEmpty(keepOut(v.keep))) ctx.addIssue({ code: 'custom', path: ['keep.daily'], message: t('settings.backup.keepNeeded') })
    })
  type V = z.infer<typeof schema>
  const toSchedule = (v: V): Schedule => ({
    name: v.name.trim(),
    paused: v.paused,
    kind: v.kind as Schedule['kind'],
    every: v.every,
    offset: v.offset,
    days: v.days.map(Number),
    times: parseTimes(v.times),
    day: v.day,
    cron: v.cron.trim(),
    targets: v.targets,
    keep: keepOut(v.keep),
  })
  return (
    <Modal open wide onClose={onClose} title={x ? `${t('settings.backup.edit')} ${x.name}` : t('settings.backup.addSchedule')}>
      <SettingsForm
        schema={schema}
        values={{
          name: x?.name ?? '',
          paused: !!x?.paused,
          kind: (x?.kind ?? 'weekly') as 'weekly',
          every: x?.every || 6,
          offset: x?.offset ?? 0,
          days: (x?.days ?? [1, 2, 3, 4, 5, 6, 0]).map(String),
          times: (x?.times ?? ['02:00']).join(', '),
          day: x?.day || 1,
          cron: x?.cron ?? '',
          targets: x?.targets ?? targets.slice(0, 1),
          keep: keepIn(x?.keep ?? { daily: 7, weekly: 4, monthly: 12 }),
        }}
        okText={t('settings.backup.scheduleSaved')}
        onSave={async (v) => {
          await save.mutateAsync(toSchedule(v))
          onClose()
        }}
      >
        {(f) => <ScheduleFields f={f} targets={targets} toSchedule={toSchedule} schema={schema} />}
      </SettingsForm>
    </Modal>
  )
}

type SV = { name: string; paused: boolean; kind: Schedule['kind']; every: number; offset: number; days: string[]; times: string; day: number; cron: string; targets: string[]; keep: Record<string, number> }

function ScheduleFields({ f, targets, toSchedule, schema }: { f: UseFormReturn<SV>; targets: string[]; toSchedule: (v: SV) => Schedule; schema: z.ZodTypeAny }) {
  const t = useT()
  const v = f.watch()
  const kind = v.kind
  const valid = schema.safeParse(v).success
  const preview = usePreview(toSchedule(v), valid)
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 md:grid-cols-2">
        <TextField form={f} name="name" label={t('settings.tokens.name')} placeholder="nightly" mono required />
        <SelectField form={f} name="kind" label={t('settings.backup.timing')} options={(['interval', 'weekly', 'monthly', 'cron'] as const).map((k) => ({ value: k, label: t(`settings.backup.timingKind.${k}` as MessageKey) }))} />
        {kind === 'interval' && (
          <>
            <TextField form={f} name="every" type="number" label={t('settings.backup.every')} help={t('settings.backup.everyHelp')} />
            <TextField form={f} name="offset" type="number" label={t('settings.backup.offset')} help={t('settings.backup.offsetHelp')} />
          </>
        )}
        {kind === 'monthly' && <TextField form={f} name="day" type="number" label={t('settings.backup.dayOfMonth')} help={t('settings.backup.dayHelp')} />}
        {(kind === 'weekly' || kind === 'monthly') && <TextField form={f} name="times" label={t('settings.backup.times')} help={t('settings.backup.timesHelp')} placeholder="02:00, 14:00" mono />}
        {kind === 'cron' && <TextField form={f} name="cron" label="Cron" help={t('settings.backup.cronHelp')} placeholder="0 2 * * 1-5" mono />}
      </div>
      {kind === 'weekly' && (
        <fieldset>
          <legend className="mb-1 text-[13px] font-medium">{t('settings.backup.days')}</legend>
          <div className="flex flex-wrap gap-3">
            {weekOrder.map((d) => (
              <label key={d} className="flex items-center gap-1.5 text-[13px]">
                <input type="checkbox" value={String(d)} {...f.register('days')} /> {t(dayKey(d))}
              </label>
            ))}
          </div>
          {f.formState.errors.days && <p className="mt-1 text-[12.5px] text-bad">{String(f.formState.errors.days.message)}</p>}
        </fieldset>
      )}
      <fieldset>
        <legend className="mb-1 text-[13px] font-medium">{t('settings.backup.targets')}</legend>
        <div className="flex flex-wrap gap-3">
          {targets.map((x) => (
            <label key={x} className="flex items-center gap-1.5 font-mono text-[13px]">
              <input type="checkbox" value={x} {...f.register('targets')} /> {x}
            </label>
          ))}
        </div>
        {f.formState.errors.targets && <p className="mt-1 text-[12.5px] text-bad">{String(f.formState.errors.targets.message)}</p>}
      </fieldset>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-[13px] font-medium">{t('settings.backup.keepSchedule')}</legend>
        <KeepFields form={f} prefix="keep" />
      </fieldset>
      <Toggle form={f} name="paused" label={t('settings.backup.paused')} />
      <section aria-live="polite" className="rounded-md bg-sunken p-3 text-[13px]">
        <h4 className="mb-1 font-semibold">{t('settings.backup.preview')}</h4>
        {!valid && <p className="text-muted">{t('settings.backup.previewWait')}</p>}
        {valid && preview.error && <p className="text-bad">{preview.error}</p>}
        {valid && preview.data && (
          <>
            <p>{t('settings.backup.nextRuns')}</p>
            <ul className="mb-2 list-disc pl-5 font-mono text-[12.5px]">
              {preview.data.next.map((n) => (
                <li key={n}>{dateTime(n)}</li>
              ))}
            </ul>
            <p>
              {t('settings.backup.keeps', { kept: preview.data.preview.kept, runs: preview.data.preview.runs })}
              {preview.data.preview.oldest && ` ${t('settings.backup.oldest', { date: dateTime(preview.data.preview.oldest) })}`}
            </p>
          </>
        )}
      </section>
    </div>
  )
}

