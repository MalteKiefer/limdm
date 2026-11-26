// People sections: console users and roles, tenants with branding and
// shared objects, API tokens. Lists in a DataGrid, details in a side sheet,
// secrets (credentials, tokens) shown once.
import { useNavigate, useSearch } from '@tanstack/react-router'
import { ArrowRightLeft, KeyRound, Plus, RotateCcw, ShieldOff } from 'lucide-react'
import { useState } from 'react'
import { z } from '../../lib/zod'
import { api, unwrap } from '../../api/client'
import { useCan, useMe } from '../../api/me'
import { switchTenant } from '../../app/tenants'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { Field, FormSection } from '../../components/form'
import { SideSheet, SplitView } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Modal } from '../../components/ui'
import { ago, dateTime, fmt } from '../../i18n/format'
import { useT, type MessageKey } from '../../i18n'
import { useAction, useShared, useTenant, useTenantList, useTokens, useUsers } from './api'
import { Confirm, Facts, OnceSecret, SectionHead, SelectField, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { colorCheck, fileBase64, lines } from './logic'
import { blobURL } from '../../lib/blob'

type Pending = { approval_id?: number }
const isPending = (r: unknown): r is Pending => typeof r === 'object' && r !== null && 'approval_id' in r

/** The selected row of a section list, kept in the URL (?sel=). */
function useSel(): [string | undefined, (v?: string) => void] {
  const search = useSearch({ strict: false }) as { s?: string; sel?: string }
  const navigate = useNavigate()
  return [search.sel, (sel) => void navigate({ to: '/settings', search: { s: search.s, sel } })]
}

function pendingToast(t: ReturnType<typeof useT>) {
  toast(t('settings.pending'))
}

const roleKey = (r: string) => `role.${r}` as MessageKey

// ---- users ----

type User = { login: string; role: string; disabled: boolean; local: boolean; last_login: string | null; scope_tags: string[]; scope_groups: string[]; from_group: boolean; tenant: string; self: boolean }

export function Users() {
  const t = useT()
  const me = useMe()
  const admin = useCan('admin')
  const q = useUsers()
  const [sel, setSel] = useSel()
  const [adding, setAdding] = useState(false)
  const [secret, setSecret] = useState('')
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const users = q.data.items as User[]
  const current = users.find((u) => u.login === sel)
  const idx = current ? users.indexOf(current) : -1
  const columns: GridColumn<User>[] = [
    {
      id: 'login',
      header: t('settings.users.login'),
      cell: (c) => (
        <span className="flex min-w-0 flex-wrap items-center gap-1.5">
          <span className="truncate font-mono">{c.row.original.login.replace(/^local:/, '')}</span>
          {c.row.original.self && <Badge tone="accent">{t('settings.users.you')}</Badge>}
          {c.row.original.disabled && <Badge tone="off">{t('settings.users.disabled')}</Badge>}
          {c.row.original.from_group && <Badge tone="info">{t('settings.users.fromGroup')}</Badge>}
        </span>
      ),
    },
    { id: 'type', header: t('settings.users.type'), cell: (c) => (c.row.original.local ? t('settings.users.local') : 'OIDC') },
    { id: 'role', header: t('settings.users.role'), cell: (c) => t(roleKey(c.row.original.role)) },
    { id: 'scope', header: t('settings.users.scope'), cell: (c) => [...c.row.original.scope_tags, ...c.row.original.scope_groups].join(', ') || <span className="text-muted">{t('settings.users.allDevices')}</span> },
    ...(me.multi_tenant ? [{ id: 'tenant', header: t('settings.users.tenant'), cell: (c: { row: { original: User } }) => c.row.original.tenant || t('settings.users.global') } as GridColumn<User>] : []),
    { id: 'last', header: t('settings.users.last'), cell: (c) => (c.row.original.last_login ? ago(c.row.original.last_login) : t('settings.never')) },
  ]
  return (
    <>
      <SectionHead
        title={t('settings.nav.users')}
        sub={q.data.four_eyes ? `${t('settings.users.sub')} ${t('settings.users.fourEyes')}` : t('settings.users.sub')}
        actions={
          admin && (
            <button type="button" className="btn btn-primary" onClick={() => setAdding(true)}>
              <Plus size={14} aria-hidden /> {t('settings.users.add')}
            </button>
          )
        }
      />
      <div className="py-4">
        <SplitView
          list={
            <DataGrid
              label={t('settings.nav.users')}
              data={users}
              columns={columns}
              getRowId={(u) => u.login}
              activeId={sel}
              onRowClick={(u) => setSel(u.login)}
              maxHeight="calc(100dvh - 300px)"
              card={(u) => (
                <span className="flex flex-col">
                  <span className="font-mono">{u.login.replace(/^local:/, '')}</span>
                  <span className="text-[12px] text-muted">
                    {t(roleKey(u.role))} · {u.local ? t('settings.users.local') : 'OIDC'}
                  </span>
                </span>
              )}
            />
          }
          detail={
            current && (
              <UserSheet
                key={current.login}
                user={current}
                fourEyes={!!q.data.four_eyes}
                onClose={() => setSel()}
                onPrev={idx > 0 ? () => setSel(users[idx - 1].login) : undefined}
                onNext={idx < users.length - 1 ? () => setSel(users[idx + 1].login) : undefined}
                onSecret={setSecret}
              />
            )
          }
        />
        <p className="mt-3 text-[12.5px] text-muted">
          {t('settings.users.rolesHelp')}{' '}
          <a className="text-accent underline-offset-2 hover:underline" href="/app/help#roles">
            {t('settings.users.rolesLink')}
          </a>
        </p>
      </div>
      {adding && <AddUser oidc={!!q.data.oidc} localLogin={!!q.data.local_login} fourEyes={!!q.data.four_eyes} onClose={() => setAdding(false)} onSecret={setSecret} />}
      {secret && <OnceSecret title={t('settings.users.credsTitle')} note={t('settings.users.credsNote')} value={secret} onClose={() => setSecret('')} />}
    </>
  )
}

const roleOptions = (t: ReturnType<typeof useT>) => ['admin', 'helpdesk', 'auditor'].map((r) => ({ value: r, label: t(roleKey(r)) }))

function AddUser({ oidc, localLogin, fourEyes, onClose, onSecret }: { oidc: boolean; localLogin: boolean; fourEyes: boolean; onClose: () => void; onSecret: (s: string) => void }) {
  const t = useT()
  const add = useAction(['settings', 'users'], (body: { kind: 'oidc' | 'local'; login: string; role: 'admin' | 'helpdesk' | 'auditor'; reason?: string }) => unwrap(api.POST('/api/v1/users', { body })))
  const schema = z
    .object({ kind: z.enum(['oidc', 'local']), login: z.string().trim().min(1, t('settings.err.required')), role: z.enum(['admin', 'helpdesk', 'auditor']), reason: z.string().max(500) })
    .superRefine((v, ctx) => {
      if (v.kind === 'oidc' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v.login.trim())) ctx.addIssue({ code: 'custom', path: ['login'], message: t('settings.users.emailBad') })
      if (v.kind === 'local' && !/^[a-z0-9][a-z0-9._-]{1,31}$/.test(v.login.trim().toLowerCase())) ctx.addIssue({ code: 'custom', path: ['login'], message: t('settings.users.nameBad') })
    })
  return (
    <Modal open onClose={onClose} title={t('settings.users.add')} description={t('settings.users.addHelp')} wide>
      <SettingsForm
        schema={schema}
        values={{ kind: oidc ? 'oidc' : 'local', login: '', role: 'helpdesk', reason: '' }}
        okText={t('settings.users.added')}
        onSave={async (v) => {
          const r = await add.mutateAsync({ kind: v.kind as 'oidc' | 'local', login: v.login.trim(), role: v.role as 'admin' | 'helpdesk' | 'auditor', ...(v.reason ? { reason: v.reason } : {}) })
          if (isPending(r)) pendingToast(t)
          else if (r.credentials) onSecret(r.credentials)
          onClose()
        }}
      >
        {(f) => (
          <div className="flex flex-col gap-4">
            <SelectField
              form={f}
              name="kind"
              label={t('settings.users.type')}
              options={[...(oidc ? [{ value: 'oidc', label: t('settings.users.oidcEmail') }] : []), { value: 'local', label: t('settings.users.localAccount') }]}
            />
            <TextField form={f} name="login" label={f.watch('kind') === 'oidc' ? t('settings.users.email') : t('settings.users.name')} required />
            <SelectField form={f} name="role" label={t('settings.users.role')} help={t(`settings.users.roleHelp.${f.watch('role')}` as MessageKey)} options={roleOptions(t)} />
            {fourEyes && f.watch('role') === 'admin' && <TextField form={f} name="reason" label={t('settings.reason')} help={t('settings.reasonHelp')} />}
            <p className="text-[12.5px] text-muted">
              {t('settings.users.localNote')} {!localLogin && t('settings.users.localOff')}
            </p>
          </div>
        )}
      </SettingsForm>
    </Modal>
  )
}

function UserSheet({ user, fourEyes, onClose, onPrev, onNext, onSecret }: { user: User; fourEyes: boolean; onClose: () => void; onPrev?: () => void; onNext?: () => void; onSecret: (s: string) => void }) {
  const t = useT()
  const admin = useCan('admin')
  const [reset, setReset] = useState(false)
  const path = { params: { path: { login: user.login } } }
  const update = useAction(['settings', 'users'], (body: { role: 'admin' | 'helpdesk' | 'auditor'; disabled: boolean; scope_tags: string[]; scope_groups: string[]; reason?: string }) => unwrap(api.PATCH('/api/v1/users/{login}', { ...path, body })))
  const resetM = useAction(['settings', 'users'], (reason: string) => unwrap(api.POST('/api/v1/users/{login}/reset', { ...path, body: { reason } })))
  const ro = !admin || user.self
  return (
    <SideSheet
      title={<span className="font-mono">{user.login.replace(/^local:/, '')}</span>}
      sub={`${user.local ? t('settings.users.local') : 'OIDC'} · ${t(roleKey(user.role))}`}
      onClose={onClose}
      onPrev={onPrev}
      onNext={onNext}
      actions={
        admin &&
        user.local &&
        !user.self && (
          <button type="button" className="btn" onClick={() => setReset(true)}>
            <RotateCcw size={14} aria-hidden /> {t('settings.users.reset')}
          </button>
        )
      }
    >
      <Facts rows={[[t('settings.users.last'), user.last_login ? dateTime(user.last_login) : t('settings.never')]]} />
      {user.self && <p className="mt-3 rounded-md bg-info-soft p-3 text-[13px]">{t('settings.users.selfNote')}</p>}
      <SettingsForm
        readOnly={ro}
        schema={z.object({ role: z.enum(['admin', 'helpdesk', 'auditor']), disabled: z.boolean(), scope_tags: z.string(), scope_groups: z.string(), reason: z.string().max(500) })}
        values={{ role: user.role as 'admin', disabled: user.disabled, scope_tags: user.scope_tags.join(', '), scope_groups: user.scope_groups.join(', '), reason: '' }}
        okText={t('settings.saved')}
        onSave={async (v) => {
          const r = await update.mutateAsync({ role: v.role, disabled: v.disabled, scope_tags: lines(v.scope_tags), scope_groups: lines(v.scope_groups), ...(v.reason ? { reason: v.reason } : {}) })
          if (isPending(r)) pendingToast(t)
        }}
      >
        {(f) => {
          const role = f.watch('role')
          return (
            <div className="mt-4 flex flex-col gap-4">
              <SelectField form={f} name="role" label={t('settings.users.role')} help={t(`settings.users.roleHelp.${role}` as MessageKey)} options={roleOptions(t)} />
              <Toggle form={f} name="disabled" label={t('settings.users.disable')} help={t('settings.users.disableHelp')} />
              {role !== 'admin' && (
                <>
                  <TextField form={f} name="scope_tags" label={t('settings.users.scopeTags')} help={t('settings.users.scopeHelp')} mono />
                  <TextField form={f} name="scope_groups" label={t('settings.users.scopeGroups')} mono />
                </>
              )}
              {fourEyes && <TextField form={f} name="reason" label={t('settings.reason')} help={t('settings.users.reasonFourEyes')} />}
            </div>
          )
        }}
      </SettingsForm>
      <Confirm
        open={reset}
        onClose={() => setReset(false)}
        title={t('settings.users.reset')}
        body={t('settings.users.resetBody')}
        confirm={t('settings.users.reset')}
        danger
        reason={fourEyes && user.role === 'admin'}
        busy={resetM.isPending}
        onConfirm={(reason) =>
          void resetM.mutateAsync(reason).then((r) => {
            setReset(false)
            if (isPending(r)) pendingToast(t)
            else if (r.credentials) onSecret(r.credentials)
          })
        }
      />
    </SideSheet>
  )
}

// ---- API tokens ----

type Token = { id?: number; name?: string; prefix?: string; role?: string; read_only?: boolean; created_by?: string; created_at?: string; expires_at?: string; last_used_at?: string | null; revoked_at?: string | null; scope_tags?: string[]; scopes?: string[] }
const scopeList = ['read', 'commands', 'library', 'audit', 'admin'] as const

function tokenState(x: Token): 'active' | 'expired' | 'revoked' {
  if (x.revoked_at) return 'revoked'
  if (x.expires_at && new Date(x.expires_at).getTime() < Date.now()) return 'expired'
  return 'active'
}

export function Tokens() {
  const t = useT()
  const admin = useCan('admin')
  const me = useMe()
  const q = useTokens()
  const [adding, setAdding] = useState(false)
  const [secret, setSecret] = useState('')
  const [revoke, setRevoke] = useState<Token | null>(null)
  const del = useAction(['settings', 'tokens'], (id: number) => unwrap(api.DELETE('/api/v1/tokens/{id}', { params: { path: { id } } })), t('settings.tokens.revoked'))
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const tokens = (q.data.items ?? []) as Token[]
  const columns: GridColumn<Token>[] = [
    { id: 'name', header: t('settings.tokens.name'), cell: (c) => <span className="font-medium">{c.row.original.name}</span> },
    { id: 'prefix', header: t('settings.tokens.prefix'), cell: (c) => <code className="font-mono text-[12px]">{c.row.original.prefix}…</code> },
    {
      id: 'role',
      header: t('settings.users.role'),
      cell: (c) => (
        <span className="flex flex-wrap gap-1">
          {t(roleKey(c.row.original.role ?? ''))}
          {c.row.original.read_only && <Badge>{t('settings.tokens.readOnly')}</Badge>}
        </span>
      ),
    },
    { id: 'scopes', header: t('settings.tokens.scopes'), cell: (c) => [...(c.row.original.scopes ?? []), ...(c.row.original.scope_tags ?? []).map((x) => `#${x}`)].join(', ') || <span className="text-muted">{t('settings.tokens.allScopes')}</span> },
    { id: 'used', header: t('settings.tokens.used'), cell: (c) => (c.row.original.last_used_at ? ago(c.row.original.last_used_at) : t('settings.never')) },
    {
      id: 'state',
      header: t('settings.tokens.state'),
      cell: (c) => {
        const s = tokenState(c.row.original)
        return <Badge tone={s === 'active' ? 'ok' : 'off'}>{s === 'active' ? `${t('settings.tokens.until')} ${dateTime(c.row.original.expires_at ?? '')}` : t(`settings.tokens.${s}` as MessageKey)}</Badge>
      },
    },
    ...(admin
      ? [
          {
            id: 'act',
            header: '',
            cell: (c: { row: { original: Token } }) =>
              tokenState(c.row.original) === 'active' && (
                <button type="button" className="btn btn-ghost" onClick={() => setRevoke(c.row.original)} aria-label={`${t('settings.tokens.revoke')} ${c.row.original.name}`}>
                  <ShieldOff size={14} aria-hidden /> {t('settings.tokens.revoke')}
                </button>
              ),
          } as GridColumn<Token>,
        ]
      : []),
  ]
  return (
    <>
      <SectionHead
        title={t('settings.nav.tokens')}
        sub={me.four_eyes ? `${t('settings.tokens.sub')} ${t('settings.tokens.fourEyes')}` : t('settings.tokens.sub')}
        actions={
          <>
            <a className="btn" href="/api/v1/docs">
              {t('settings.tokens.docs')}
            </a>
            {admin && (
              <button type="button" className="btn btn-primary" onClick={() => setAdding(true)}>
                <Plus size={14} aria-hidden /> {t('settings.tokens.add')}
              </button>
            )}
          </>
        }
      />
      <div className="py-4">
        <DataGrid
          label={t('settings.nav.tokens')}
          data={tokens}
          columns={columns}
          getRowId={(x) => String(x.id)}
          maxHeight="calc(100dvh - 300px)"
          empty={<EmptyState icon={KeyRound} title={t('settings.tokens.none')}>{t('settings.tokens.noneBody')}</EmptyState>}
          card={(x) => (
            <span className="flex flex-col">
              <span className="font-medium">{x.name}</span>
              <span className="text-[12px] text-muted">
                {t(roleKey(x.role ?? ''))} · {t(`settings.tokens.${tokenState(x)}` as MessageKey)}
              </span>
            </span>
          )}
        />
      </div>
      {adding && <AddToken onClose={() => setAdding(false)} onSecret={setSecret} />}
      {secret && <OnceSecret title={t('settings.tokens.created')} value={secret} onClose={() => setSecret('')} />}
      <Confirm
        open={!!revoke}
        onClose={() => setRevoke(null)}
        title={t('settings.tokens.revoke')}
        body={t('settings.tokens.revokeBody', { name: revoke?.name ?? '' })}
        confirm={t('settings.tokens.revoke')}
        danger
        busy={del.isPending}
        onConfirm={() => revoke?.id && void del.mutateAsync(revoke.id).then(() => setRevoke(null))}
      />
    </>
  )
}

function AddToken({ onClose, onSecret }: { onClose: () => void; onSecret: (s: string) => void }) {
  const t = useT()
  const add = useAction(['settings', 'tokens'], (body: { name: string; role: 'admin' | 'helpdesk' | 'auditor' | 'metrics'; days: number; read_only: boolean; scope_tags: string[]; scopes: (typeof scopeList)[number][] }) =>
    unwrap(api.POST('/api/v1/tokens', { body })),
  )
  return (
    <Modal open onClose={onClose} title={t('settings.tokens.add')} description={t('settings.tokens.addHelp')} wide>
      <SettingsForm
        schema={z.object({
          name: z.string().trim().min(1, t('settings.err.required')).max(80),
          role: z.enum(['admin', 'helpdesk', 'auditor', 'metrics']),
          days: z.number({ message: t('settings.err.number') }).int().min(1, t('settings.tokens.daysRange')).max(365, t('settings.tokens.daysRange')),
          read_only: z.boolean(),
          scope_tags: z.string(),
          scopes: z.array(z.enum(scopeList)),
        })}
        values={{ name: '', role: 'auditor', days: 90, read_only: false, scope_tags: '', scopes: [] }}
        okText={t('settings.tokens.createdToast')}
        onSave={async (v) => {
          const r = await add.mutateAsync({ ...v, name: v.name.trim(), scope_tags: lines(v.scope_tags) })
          if (isPending(r)) pendingToast(t)
          else if (r.token) onSecret(r.token)
          onClose()
        }}
      >
        {(f) => {
          const role = f.watch('role')
          return (
            <div className="flex flex-col gap-4">
              <TextField form={f} name="name" label={t('settings.tokens.name')} placeholder="ci-deploy" required />
              <SelectField form={f} name="role" label={t('settings.users.role')} help={t(`settings.tokens.roleHelp.${role}` as MessageKey)} options={[...roleOptions(t), { value: 'metrics', label: t('settings.tokens.metrics') }]} />
              <TextField form={f} name="days" type="number" label={t('settings.tokens.days')} help={t('settings.tokens.daysRange')} required />
              {role !== 'metrics' && (
                <>
                  <Toggle form={f} name="read_only" label={t('settings.tokens.readOnly')} help={t('settings.tokens.readOnlyHelp')} />
                  <fieldset className="flex flex-col gap-2">
                    <legend className="text-[13px] font-medium">{t('settings.tokens.scopes')}</legend>
                    <p className="text-[12.5px] text-muted">{t('settings.tokens.scopesHelp')}</p>
                    <div className="flex flex-wrap gap-x-4 gap-y-2">
                      {scopeList.map((sc) => (
                        <label key={sc} className="flex items-center gap-1.5 text-[13px]">
                          <input type="checkbox" value={sc} {...f.register('scopes')} /> {t(`settings.tokens.scope.${sc}` as MessageKey)}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                  {role !== 'admin' && <TextField form={f} name="scope_tags" label={t('settings.users.scopeTags')} help={t('settings.tokens.tagsHelp')} mono />}
                </>
              )}
            </div>
          )
        }}
      </SettingsForm>
    </Modal>
  )
}

// ---- tenants ----

type TenantRow = { id?: number; name?: string; disabled?: boolean; company_name?: string; devices?: number; created_at?: string }

export function Tenants() {
  const me = useMe()
  const supr = me.permissions.includes('tenants')
  if (!supr) return me.tenant ? <TenantEdit id={me.tenant.id} /> : null
  return <TenantList />
}

function TenantList() {
  const t = useT()
  const q = useTenantList()
  const [sel, setSel] = useSel()
  const [adding, setAdding] = useState(false)
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const list = (q.data.items ?? []) as TenantRow[]
  const columns: GridColumn<TenantRow>[] = [
    { id: 'name', header: t('settings.tenants.name'), cell: (c) => <span className="font-medium">{c.row.original.name}</span> },
    { id: 'company', header: t('settings.tenants.company'), cell: (c) => c.row.original.company_name || <span className="text-muted">{t('settings.tenants.inherit')}</span> },
    { id: 'devices', header: t('settings.tenants.devices'), cell: (c) => <span className="num">{fmt(c.row.original.devices ?? 0)}</span> },
    { id: 'state', header: t('settings.tokens.state'), cell: (c) => (c.row.original.disabled ? <Badge tone="off">{t('settings.tenants.disabled')}</Badge> : <Badge tone="ok">{t('settings.tenants.active')}</Badge>) },
  ]
  return (
    <>
      <SectionHead
        title={t('settings.nav.tenants')}
        sub={t('settings.tenants.sub')}
        actions={
          <button type="button" className="btn btn-primary" onClick={() => setAdding(true)}>
            <Plus size={14} aria-hidden /> {t('settings.tenants.add')}
          </button>
        }
      />
      <div className="py-4">
        <SplitView
          list={<DataGrid label={t('settings.nav.tenants')} data={list} columns={columns} getRowId={(x) => String(x.id)} activeId={sel} onRowClick={(x) => setSel(String(x.id))} maxHeight="calc(100dvh - 300px)" card={(x) => <span className="font-medium">{x.name}</span>} />}
          detail={
            sel && (
              <SideSheet title={list.find((x) => String(x.id) === sel)?.name ?? ''} onClose={() => setSel()}
                actions={
                  <button type="button" className="btn" onClick={() => void switchTenant(Number(sel))}>
                    <ArrowRightLeft size={14} aria-hidden /> {t('settings.tenants.open')}
                  </button>
                }
              >
                <TenantEdit key={sel} id={Number(sel)} embedded />
              </SideSheet>
            )
          }
        />
      </div>
      <SharedObjects />
      {adding && <AddTenant onClose={() => setAdding(false)} onCreated={(id) => setSel(String(id))} />}
    </>
  )
}

function AddTenant({ onClose, onCreated }: { onClose: () => void; onCreated: (id: number) => void }) {
  const t = useT()
  const add = useAction(['settings', 'tenants'], (name: string) => unwrap(api.POST('/api/v1/tenants', { body: { name } })))
  return (
    <Modal open onClose={onClose} title={t('settings.tenants.add')}>
      <SettingsForm
        schema={z.object({ name: z.string().trim().min(1, t('settings.err.required')).max(100, t('settings.tenants.nameLong')) })}
        values={{ name: '' }}
        okText={t('settings.tenants.created')}
        onSave={async (v) => {
          const r = await add.mutateAsync(v.name.trim())
          onClose()
          if (r.id) onCreated(r.id)
        }}
      >
        {(f) => <TextField form={f} name="name" label={t('settings.tenants.name')} required />}
      </SettingsForm>
    </Modal>
  )
}

/** Name, state and branding of a tenant (super admins), or the branding of the own tenant. */
function TenantEdit({ id, embedded }: { id: number; embedded?: boolean }) {
  const t = useT()
  const me = useMe()
  const admin = useCan('admin')
  const q = useTenant(id)
  const [logo, setLogo] = useState<{ b64: string; url: string } | null>(null)
  const [remove, setRemove] = useState(false)
  const save = useAction(['settings', 'tenants'], (body: { name?: string; disabled?: boolean; company_name: string; color: string; logo_png?: string; remove_logo?: boolean }) =>
    unwrap(api.PATCH('/api/v1/tenants/{id}', { params: { path: { id } }, body })),
  )
  if (q.isPending) return <LoadingState rows={4} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const x = q.data
  const supr = me.super
  const body = (
    <SettingsForm
      readOnly={!admin}
      schema={z.object({
        name: z.string().trim().min(1, t('settings.err.required')).max(100, t('settings.tenants.nameLong')),
        disabled: z.boolean(),
        company_name: z.string().max(100, t('settings.tenants.companyLong')),
        color: z.string().refine((v) => !v || /^#[0-9a-fA-F]{6}$/.test(v), t('settings.tenants.colorBad')),
        logo: z.string(),
      })}
      values={{ name: x.name, disabled: x.disabled, company_name: x.company_name, color: x.color, logo: '' }}
      onSave={async (v) => {
        await save.mutateAsync({ ...(supr ? { name: v.name, disabled: v.disabled } : {}), company_name: v.company_name, color: v.color, ...(logo ? { logo_png: logo.b64 } : {}), ...(remove ? { remove_logo: true } : {}) })
        setLogo(null)
        setRemove(false)
        void q.refetch()
      }}
    >
      {(f) => {
        const color = f.watch('color')
        const check = colorCheck(color)
        return (
          <div className="flex flex-col gap-4">
            {supr && (
              <>
                <TextField form={f} name="name" label={t('settings.tenants.name')} required />
                {x.id !== 1 && <Toggle form={f} name="disabled" label={t('settings.tenants.disable')} help={t('settings.tenants.disableHelp')} />}
              </>
            )}
            <TextField form={f} name="company_name" label={t('settings.tenants.company')} help={t('settings.tenants.companyHelp')} />
            <Field label={t('settings.tenants.color')} help={t('settings.tenants.colorHelp')} error={f.formState.errors.color?.message}>
              {({ id: fid, describedBy, invalid }) => (
                <div className="flex flex-wrap items-center gap-2">
                  <input type="color" aria-label={t('settings.tenants.picker')} className="h-9 w-12 cursor-pointer rounded-md border border-line bg-field" value={color || '#0f6e6e'} onChange={(e) => f.setValue('color', e.target.value, { shouldDirty: true, shouldValidate: true })} />
                  <input id={fid} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field w-32 font-mono" placeholder="#0f6e6e" {...f.register('color')} />
                  {color && (
                    <button type="button" className="btn btn-ghost" onClick={() => f.setValue('color', '', { shouldDirty: true })}>
                      {t('settings.tenants.colorReset')}
                    </button>
                  )}
                </div>
              )}
            </Field>
            {check && (
              <p role="status" className={check.ok ? 'text-[12.5px] text-muted' : 'rounded-md bg-warn-soft p-2 text-[12.5px]'}>
                {t('settings.tenants.contrast', { light: check.light.toFixed(1), dark: check.dark.toFixed(1) })} {check.ok ? t('settings.tenants.contrastOk') : t('settings.tenants.contrastLow')}
              </p>
            )}
            <Field label={t('settings.branding.logo')} help={t('settings.branding.logoHelp')}>
              {({ id: fid, describedBy }) => (
                <div className="flex flex-wrap items-center gap-3">
                  {(logo || (x.has_logo && !remove)) && <img src={blobURL(logo?.url) ?? `/tenants/${x.id}/logo.png?v=${encodeURIComponent(x.created_at)}${q.dataUpdatedAt}`} alt={t('settings.branding.preview')} className="size-14 rounded-md border border-line object-contain" />}
                  <label className="btn cursor-pointer">
                    {t('settings.branding.choose')}
                    <input
                      id={fid}
                      aria-describedby={describedBy}
                      type="file"
                      accept="image/png"
                      className="sr-only"
                      onChange={(e) => {
                        const file = e.target.files?.[0]
                        if (file)
                          void fileBase64(file).then((b64) => {
                            setLogo({ b64, url: URL.createObjectURL(file) })
                            f.setValue('logo', file.name, { shouldDirty: true })
                          })
                      }}
                    />
                  </label>
                  {x.has_logo && !remove && !logo && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => {
                        setRemove(true)
                        f.setValue('logo', 'remove', { shouldDirty: true })
                      }}
                    >
                      {t('settings.branding.remove')}
                    </button>
                  )}
                </div>
              )}
            </Field>
          </div>
        )
      }}
    </SettingsForm>
  )
  if (embedded) return body
  return (
    <>
      <SectionHead title={t('settings.tenants.own')} sub={t('settings.tenants.ownSub')} />
      <div className="py-4">{body}</div>
    </>
  )
}

function SharedObjects() {
  const t = useT()
  const q = useShared(true)
  const save = useAction(['settings', 'shared'], (body: { blueprints: number[]; items: number[] }) => unwrap(api.PUT('/api/v1/tenants/shared', { body })), t('settings.saved'))
  if (q.isPending) return <LoadingState rows={3} />
  if (q.isError) return <ErrorState error={q.error} />
  const all = [...q.data.blueprints.map((b) => ({ ...b, key: `b${b.id}` })), ...q.data.items.map((i) => ({ ...i, key: `i${i.id}` }))]
  return (
    <SettingsForm
      schema={z.object({ shared: z.array(z.string()) })}
      values={{ shared: all.filter((x) => x.shared).map((x) => x.key) }}
      onSave={(v) =>
        save.mutateAsync({
          blueprints: v.shared.filter((k) => k.startsWith('b')).map((k) => Number(k.slice(1))),
          items: v.shared.filter((k) => k.startsWith('i')).map((k) => Number(k.slice(1))),
        })
      }
    >
      {(f) => (
        <FormSection title={t('settings.tenants.shared')} description={t('settings.tenants.sharedHelp')}>
          {all.length === 0 && <p className="text-muted">{t('settings.tenants.sharedNone')}</p>}
          {(
            [
              ['blueprints', q.data.blueprints, 'b'],
              ['items', q.data.items, 'i'],
            ] as const
          ).map(
            ([k, list, p]) =>
              list.length > 0 && (
                <fieldset key={k} className="flex flex-col gap-1.5">
                  <legend className="mb-1 text-[13px] font-medium">{t(`settings.tenants.shared.${k}` as MessageKey)}</legend>
                  {list.map((o) => (
                    <label key={o.id} className="flex items-center gap-2 text-[13px]">
                      <input type="checkbox" value={`${p}${o.id}`} {...f.register('shared')} />
                      {o.name}
                      {o.type && <span className="font-mono text-[11.5px] text-muted">{o.type}</span>}
                    </label>
                  ))}
                </fieldset>
              ),
          )}
        </FormSection>
      )}
    </SettingsForm>
  )
}

