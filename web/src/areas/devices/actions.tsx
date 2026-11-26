// Every device action of the console as a dialog: commands with their
// parameters, protective actions confirmed by the host name, details,
// agent update, retire, delete, recovery keys, remote shell. One component
// renders the open dialog; useDeviceMenu builds the action menu.
import { useNavigate } from '@tanstack/react-router'
import {
  Bot,
  Download,
  FileCode2,
  KeyRound,
  Lock,
  LockOpen,
  MapPinOff,
  MessageSquare,
  Pencil,
  Power,
  PowerOff,
  RefreshCw,
  Search,
  Terminal,
  Trash2,
  Unplug,
  type LucideIcon,
} from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Modal, type MenuEntry } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ApiError } from '../../api/client'
import {
  useAgentUpdate,
  useBlueprintList,
  useCommand,
  useDelete,
  usePatch,
  usePeople,
  useRecoveryView,
  useRetire,
  useShellStart,
  type DeviceDetail,
  type Params,
} from './api'
import { badParamLine, formatUsers, mayCommand, parseTags, parseUsers } from './logic'

export type Dialog =
  | { kind: 'confirm'; type: string; params?: Params; title: MessageKey; body: MessageKey; danger?: boolean }
  | { kind: 'later'; type: 'reboot' | 'shutdown' }
  | { kind: 'message' | 'lost' | 'wipe' | 'script' | 'user-create' | 'agent' | 'edit' | 'retire' | 'delete' | 'shell' }
  | { kind: 'user-password'; user: string }
  | { kind: 'recovery'; uuid: string; path: string }

export type Target = { id: string; hostname: string; retired?: boolean; detail?: DeviceDetail }

/** Whether a command needs a second admin under four eyes. */
const fourEyes = (d: DeviceDetail | undefined, type: string) => !!d?.four_eyes_commands.includes(type)

/** Runs a command and tells how it went. */
export function useRun(target: Target) {
  const t = useT()
  const cmd = useCommand(target.id)
  return {
    pending: cmd.isPending,
    run: (type: string, params?: Params, after?: () => void) =>
      cmd.mutate(
        { type, params },
        {
          onSuccess: (r) => {
            toast(r.approval ? t('devices.toast.approval') : t('devices.toast.queued', { name: target.hostname }))
            after?.()
          },
          onError: (e) => toast(errorText(e), 'error'),
        },
      ),
  }
}

/** The action menu of a device (header of the page and the side sheet). */
export function useDeviceMenu(target: Target, open: (d: Dialog) => void): MenuEntry[] {
  const t = useT()
  const admin = useCan('admin')
  const commands = useCan('commands')
  const nav = useNavigate()
  const { run } = useRun(target)
  if (target.retired || !commands) return []
  const can = (type: string) => mayCommand(type, { admin, commands })
  const confirm = (type: string, title: MessageKey, body: MessageKey, icon: LucideIcon, danger = false): MenuEntry => ({
    label: t(title),
    icon,
    danger,
    onClick: () => open({ kind: 'confirm', type, title, body, danger }),
  })
  const shell = target.detail?.shell
  const items: (MenuEntry | false)[] = [
    { group: t('devices.menu.updates') },
    { label: t('devices.cmd.sync'), icon: RefreshCw, onClick: () => run('sync') },
    { label: t('devices.cmd.update'), icon: Download, onClick: () => run('update') },
    admin && { label: t('devices.cmd.agentUpdate'), icon: Bot, onClick: () => open({ kind: 'agent' }) },
    { label: t('devices.cmd.message'), icon: MessageSquare, onClick: () => open({ kind: 'message' }) },
    { group: t('devices.menu.power') },
    confirm('reboot', 'devices.cmd.rebootNow', 'devices.confirm.reboot', Power),
    { label: t('devices.cmd.rebootLater'), icon: Power, onClick: () => open({ kind: 'later', type: 'reboot' }) },
    confirm('shutdown', 'devices.cmd.shutdownNow', 'devices.confirm.shutdown', PowerOff),
    { label: t('devices.cmd.shutdownLater'), icon: PowerOff, onClick: () => open({ kind: 'later', type: 'shutdown' }) },
    { group: t('devices.menu.security') },
    confirm('lock', 'devices.cmd.lock', 'devices.confirm.lock', Lock),
    { label: t('devices.cmd.unlock'), icon: LockOpen, onClick: () => run('unlock') },
    admin && { label: t('devices.cmd.lost'), icon: MapPinOff, danger: true, onClick: () => open({ kind: 'lost' }) },
    admin && { label: t('devices.cmd.found'), icon: Search, onClick: () => run('found') },
    admin && { label: t('devices.cmd.retire'), icon: Unplug, danger: true, onClick: () => open({ kind: 'retire' }) },
    admin && { label: t('devices.cmd.wipe'), icon: Trash2, danger: true, onClick: () => open({ kind: 'wipe' }) },
    { group: t('devices.menu.agent') },
    admin && { label: t('devices.cmd.script'), icon: FileCode2, onClick: () => open({ kind: 'script' }) },
    !!shell?.enabled && shell.allowed && { label: t('devices.cmd.shell'), icon: Terminal, onClick: () => open({ kind: 'shell' }) },
    can('diagnostics') && { label: t('devices.cmd.diagnostics'), icon: Download, onClick: () => run('diagnostics', undefined, () => void nav({ to: '/devices/$id', params: { id: target.id }, search: { tab: 'activity' } })) },
    admin && confirm('allow_uninstall', 'devices.cmd.allowUninstall', 'devices.confirm.allowUninstall', KeyRound),
    admin && { group: t('devices.menu.details') },
    admin && { label: t('devices.cmd.edit'), icon: Pencil, onClick: () => open({ kind: 'edit' }) },
  ]
  return items.filter((x): x is MenuEntry => !!x)
}

function Foot({ onClose, label, busy, danger, disabled, form }: { onClose: () => void; label: string; busy?: boolean; danger?: boolean; disabled?: boolean; form: string }) {
  const t = useT()
  return (
    <>
      <button type="button" className="btn" onClick={onClose}>
        {t('common.cancel')}
      </button>
      <button type="submit" form={form} className={danger ? 'btn btn-danger' : 'btn btn-primary'} disabled={busy || disabled}>
        {label}
      </button>
    </>
  )
}

function Text({ label, value, onChange, help, required, error, type = 'text', mono, area, max, autoFocus, name }: { label: ReactNode; value: string; onChange: (v: string) => void; help?: ReactNode; required?: boolean; error?: string; type?: string; mono?: boolean; area?: number; max?: number; autoFocus?: boolean; name?: string }) {
  return (
    <Field label={label} help={help} required={required} error={error}>
      {({ id, describedBy, invalid }) =>
        area ? (
          <textarea id={id} name={name} rows={area} className={mono ? 'field font-mono text-[12.5px]' : 'field'} aria-describedby={describedBy} aria-invalid={invalid || undefined} value={value} maxLength={max} required={required} spellCheck={!mono} onChange={(e) => onChange(e.target.value)} autoFocus={autoFocus} />
        ) : (
          <input id={id} name={name} type={type} className={mono ? 'field font-mono' : 'field'} aria-describedby={describedBy} aria-invalid={invalid || undefined} value={value} maxLength={max} required={required} autoComplete="off" spellCheck={false} onChange={(e) => onChange(e.target.value)} autoFocus={autoFocus} />
        )
      }
    </Field>
  )
}

/** The reason of a four eyes request, shown only when the action needs one. */
function Reason({ show, value, onChange }: { show: boolean; value: string; onChange: (v: string) => void }) {
  const t = useT()
  if (!show) return null
  return <Text label={t('devices.f.reason')} help={t('devices.f.reasonHelp')} value={value} onChange={onChange} max={500} />
}

/** The problem detail of a refused request, for the field it names. */
const fieldError = (e: unknown) => (e instanceof ApiError ? e.problem.detail || e.message : e ? errorText(e) : undefined)

export function DeviceDialog({ dialog, target, onClose }: { dialog: Dialog | null; target: Target; onClose: () => void }) {
  if (!dialog) return null
  switch (dialog.kind) {
    case 'confirm':
      return <ConfirmDialog d={dialog} target={target} onClose={onClose} />
    case 'later':
      return <LaterDialog type={dialog.type} target={target} onClose={onClose} />
    case 'message':
      return <MessageDialog target={target} onClose={onClose} />
    case 'lost':
    case 'wipe':
      return <ProtectDialog type={dialog.kind} target={target} onClose={onClose} />
    case 'script':
      return <ScriptDialog target={target} onClose={onClose} />
    case 'user-create':
      return <UserDialog target={target} onClose={onClose} />
    case 'user-password':
      return <UserDialog target={target} user={dialog.user} onClose={onClose} />
    case 'agent':
      return <AgentDialog target={target} onClose={onClose} />
    case 'edit':
      return <EditDialog target={target} onClose={onClose} />
    case 'retire':
      return <RetireDialog target={target} onClose={onClose} />
    case 'delete':
      return <DeleteDialog target={target} onClose={onClose} />
    case 'recovery':
      return <RecoveryDialog uuid={dialog.uuid} path={dialog.path} target={target} onClose={onClose} />
    case 'shell':
      return <ShellDialog target={target} onClose={onClose} />
  }
}

function ConfirmDialog({ d, target, onClose }: { d: Extract<Dialog, { kind: 'confirm' }>; target: Target; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  return (
    <Modal
      open
      onClose={onClose}
      title={t(d.title)}
      description={target.hostname}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className={d.danger ? 'btn btn-danger' : 'btn btn-primary'} disabled={pending} onClick={() => run(d.type, d.params, onClose)}>
            {t(d.title)}
          </button>
        </>
      }
    >
      <p>{t(d.body)}</p>
    </Modal>
  )
}

function LaterDialog({ type, target, onClose }: { type: 'reboot' | 'shutdown'; target: Target; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  const [minutes, setMinutes] = useState('5')
  const n = Number(minutes)
  const bad = !Number.isInteger(n) || n < 1 || n > 1440
  return (
    <Modal open onClose={onClose} title={t(type === 'reboot' ? 'devices.cmd.rebootLater' : 'devices.cmd.shutdownLater')} description={target.hostname} footer={<Foot form="dlg-later" onClose={onClose} label={t('devices.f.schedule')} busy={pending} disabled={bad} />}>
      <form id="dlg-later" onSubmit={(e) => (e.preventDefault(), run(type, { minutes: n }, onClose))}>
        <Text label={t('devices.f.minutes')} help={t('devices.f.minutesHelp')} type="number" value={minutes} onChange={setMinutes} required error={bad ? t('devices.f.minutesRange') : undefined} autoFocus />
      </form>
    </Modal>
  )
}

function MessageDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  const [title, setTitle] = useState('')
  const [text, setText] = useState('')
  return (
    <Modal open onClose={onClose} title={t('devices.cmd.message')} description={t('devices.f.messageHelp')} footer={<Foot form="dlg-msg" onClose={onClose} label={t('devices.f.send')} busy={pending} disabled={!text.trim()} />}>
      <form id="dlg-msg" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), run('message', { title, text }, onClose))}>
        <Text label={t('devices.f.title')} help={t('devices.f.optional')} value={title} onChange={setTitle} max={100} />
        <Text label={t('devices.f.message')} value={text} onChange={setText} area={4} max={1000} required autoFocus />
      </form>
    </Modal>
  )
}

function ProtectDialog({ type, target, onClose }: { type: 'lost' | 'wipe'; target: Target; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  const [message, setMessage] = useState('')
  const [confirm, setConfirm] = useState('')
  const [reason, setReason] = useState('')
  const ok = confirm.trim().toLowerCase() === target.hostname.toLowerCase()
  const params: Params = { confirm }
  if (type === 'lost') params.message = message
  if (reason) params.reason = reason
  return (
    <Modal
      open
      onClose={onClose}
      title={t(type === 'lost' ? 'devices.cmd.lost' : 'devices.cmd.wipe')}
      footer={<Foot form="dlg-protect" onClose={onClose} label={t(type === 'lost' ? 'devices.f.lostGo' : 'devices.cmd.wipe')} danger busy={pending} disabled={!ok} />}
    >
      <form id="dlg-protect" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), run(type, params, onClose))}>
        <p className="rounded-lg bg-bad-soft p-3 text-[13px] text-bad">{t(type === 'lost' ? 'devices.f.lostHelp' : 'devices.f.wipeHelp')}</p>
        {type === 'lost' && <Text label={t('devices.f.lostMessage')} help={t('devices.f.lostMessageHelp')} value={message} onChange={setMessage} area={3} max={500} />}
        <Text label={t('devices.f.confirmHost', { host: target.hostname })} value={confirm} onChange={setConfirm} required mono autoFocus />
        <Reason show={fourEyes(target.detail, type)} value={reason} onChange={setReason} />
      </form>
    </Modal>
  )
}

/** The script fields; the bulk bar uses them too. */
export function ScriptFields({ v, set }: { v: { payload: string; params: string; timeout: string }; set: (v: { payload: string; params: string; timeout: string }) => void }) {
  const t = useT()
  const bad = badParamLine(v.params)
  return (
    <>
      <Text label={t('devices.f.script')} help={t('devices.f.scriptHelp')} value={v.payload} onChange={(payload) => set({ ...v, payload })} area={8} mono required autoFocus />
      <Text label={t('devices.f.params')} help={t('devices.f.paramsHelp')} value={v.params} onChange={(params) => set({ ...v, params })} area={3} mono error={bad ? t('devices.f.paramsBad', { line: bad }) : undefined} />
      <Text label={t('devices.f.timeout')} type="number" value={v.timeout} onChange={(timeout) => set({ ...v, timeout })} />
    </>
  )
}

export const scriptParams = (v: { payload: string; params: string; timeout: string }): Params => ({ payload: v.payload, params: v.params, ...(v.timeout ? { timeout_minutes: v.timeout } : {}) })
export const scriptValid = (v: { payload: string; params: string; timeout: string }) => !!v.payload.trim() && !badParamLine(v.params)

function ScriptDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  const [v, set] = useState({ payload: '#!/bin/sh\n', params: '', timeout: '' })
  const [reason, setReason] = useState('')
  return (
    <Modal open wide onClose={onClose} title={t('devices.cmd.script')} description={target.hostname} footer={<Foot form="dlg-script" onClose={onClose} label={t('devices.f.run')} busy={pending} disabled={!scriptValid(v)} />}>
      <form id="dlg-script" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), run('script', { ...scriptParams(v), ...(reason ? { reason } : {}) }, onClose))}>
        <ScriptFields v={v} set={set} />
        <Reason show={fourEyes(target.detail, 'script')} value={reason} onChange={setReason} />
        {fourEyes(target.detail, 'script') && <p className="text-[12.5px] text-muted">{t('devices.f.fourEyesNote')}</p>}
      </form>
    </Modal>
  )
}

function UserDialog({ target, user, onClose }: { target: Target; user?: string; onClose: () => void }) {
  const t = useT()
  const { run, pending } = useRun(target)
  const [username, setUsername] = useState(user ?? '')
  const [fullName, setFullName] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [admin, setAdmin] = useState(false)
  const min = target.detail?.password_min ?? 12
  const badUser = !!username && !/^[a-z_][a-z0-9_-]{0,31}$/.test(username)
  const mismatch = pw2 !== '' && pw !== pw2
  const short = pw !== '' && pw.length < min
  const ok = !!username && !badUser && pw.length >= min && pw === pw2
  const params: Params = user ? { username, password: pw, password2: pw2 } : { username, full_name: fullName, password: pw, password2: pw2, admin }
  return (
    <Modal open onClose={onClose} title={t(user ? 'devices.user.password' : 'devices.user.create')} description={user ?? target.hostname} footer={<Foot form="dlg-user" onClose={onClose} label={t(user ? 'devices.user.passwordGo' : 'devices.user.createGo')} busy={pending} disabled={!ok} />}>
      <form id="dlg-user" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), run(user ? 'user_password' : 'user_create', params, onClose))}>
        {!user && (
          <>
            <Text label={t('devices.user.name')} value={username} onChange={setUsername} required mono autoFocus error={badUser ? t('devices.user.nameBad') : undefined} />
            <Text label={t('devices.user.fullName')} value={fullName} onChange={setFullName} max={100} />
          </>
        )}
        <Text label={t(user ? 'devices.user.newPassword' : 'devices.user.initialPassword')} help={t('devices.user.passwordHelp', { min })} type="password" value={pw} onChange={setPw} required error={short ? t('devices.user.passwordShort', { min }) : undefined} autoFocus={!!user} />
        <Text label={t('devices.user.repeat')} type="password" value={pw2} onChange={setPw2} required error={mismatch ? t('devices.user.mismatch') : undefined} />
        {!user && (
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={admin} onChange={(e) => setAdmin(e.target.checked)} /> {t('devices.user.admin')}
          </label>
        )}
      </form>
    </Modal>
  )
}

function AgentDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const upd = useAgentUpdate(target.id)
  const [version, setVersion] = useState('')
  const d = target.detail
  return (
    <Modal open onClose={onClose} title={t('devices.cmd.agentUpdate')} description={t('devices.agent.help', { version: d?.agent_version ?? '' })} footer={<Foot form="dlg-agent" onClose={onClose} label={t('devices.agent.go')} busy={upd.isPending} />}>
      <form
        id="dlg-agent"
        onSubmit={(e) => {
          e.preventDefault()
          upd.mutate(version, { onSuccess: () => (toast(t('devices.agent.done')), onClose()), onError: (er) => toast(errorText(er), 'error') })
        }}
      >
        <Field label={t('devices.agent.version')}>
          {({ id }) => (
            <select id={id} className="field" value={version} onChange={(e) => setVersion(e.target.value)}>
              <option value="">{t('devices.agent.newest')}</option>
              {(d?.agent_versions ?? []).map((v) => (
                <option key={v} value={v}>
                  {v}
                  {v === d?.agent_version ? ` (${t('devices.agent.installed')})` : ''}
                </option>
              ))}
            </select>
          )}
        </Field>
      </form>
    </Modal>
  )
}

function EditDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const d = target.detail
  const patch = usePatch()
  const bps = useBlueprintList(true)
  const assigned = d?.blueprints.find((b) => b.assigned)
  const [bp, setBp] = useState(String(assigned?.id ?? 0))
  const [primary, setPrimary] = useState(d?.primary_user ?? '')
  const [tags, setTags] = useState((d?.tags ?? []).join(', '))
  const [users, setUsers] = useState(formatUsers(d?.desktop_users ?? []))
  const people = usePeople(primary, primary.length >= 2)
  const pu = parseUsers(users)
  const pt = parseTags(tags)
  const [err, setErr] = useState<string>()
  const list = d?.blueprints.length ? d.blueprints : (bps.data ?? []).map((b) => ({ id: b.id, name: b.name }))
  const submit = () =>
    patch.mutate(
      { id: target.id, body: { blueprint_id: Number(bp) > 0 ? Number(bp) : null, primary_user: primary.trim(), tags: pt.tags, users: pu.users } },
      { onSuccess: () => (toast(t('devices.edit.saved')), onClose()), onError: (e) => setErr(fieldError(e)) },
    )
  return (
    <Modal open wide onClose={onClose} title={t('devices.cmd.edit')} description={target.hostname} footer={<Foot form="dlg-edit" onClose={onClose} label={t('common.save')} busy={patch.isPending} disabled={!!pu.error || !!pt.error} />}>
      <form id="dlg-edit" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), submit())}>
        {err && (
          <p role="alert" className="text-[13px] font-medium text-bad">
            {err}
          </p>
        )}
        <Field label={t('devices.edit.blueprint')}>
          {({ id }) => (
            <select id={id} className="field" value={bp} onChange={(e) => setBp(e.target.value)}>
              {list.map((b) => (
                <option key={b.id} value={b.name === 'default' ? 0 : b.id}>
                  {b.name}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('devices.edit.primary')} help={t('devices.edit.primaryHelp')}>
          {({ id, describedBy }) => (
            <>
              <input id={id} className="field" list="dev-people" aria-describedby={describedBy} value={primary} onChange={(e) => setPrimary(e.target.value)} autoComplete="off" placeholder="jane.doe@example.com" />
              <datalist id="dev-people">
                {(people.data ?? []).map((p) => (
                  <option key={p} value={p} />
                ))}
              </datalist>
            </>
          )}
        </Field>
        <Text label={t('devices.edit.tags')} help={t('devices.edit.tagsHelp')} value={tags} onChange={setTags} error={pt.error ? t('devices.edit.tagBad', { tag: pt.error }) : undefined} />
        <Text label={t('devices.edit.users')} help={t('devices.edit.usersHelp')} value={users} onChange={setUsers} area={4} mono error={pu.error ? t('devices.edit.userBad', { line: pu.error }) : undefined} />
      </form>
    </Modal>
  )
}

function RetireDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const retire = useRetire(target.id)
  return (
    <Modal
      open
      onClose={onClose}
      title={t('devices.cmd.retire')}
      description={target.hostname}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn btn-danger" disabled={retire.isPending} onClick={() => retire.mutate(undefined, { onSuccess: () => (toast(t('devices.retire.done')), onClose()), onError: (e) => toast(errorText(e), 'error') })}>
            {t('devices.retire.go')}
          </button>
        </>
      }
    >
      <p>{t('devices.retire.help')}</p>
    </Modal>
  )
}

function DeleteDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const nav = useNavigate()
  const del = useDelete(target.id)
  const [confirm, setConfirm] = useState('')
  const ok = confirm.trim().toLowerCase() === target.hostname.toLowerCase()
  return (
    <Modal open onClose={onClose} title={t('devices.delete.title')} footer={<Foot form="dlg-del" onClose={onClose} label={t('devices.delete.title')} danger busy={del.isPending} disabled={!ok} />}>
      <form
        id="dlg-del"
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          del.mutate(confirm, { onSuccess: () => (toast(t('devices.delete.done')), void nav({ to: '/devices' })), onError: (er) => toast(errorText(er), 'error') })
        }}
      >
        <p className="text-[13px]">{t('devices.delete.help')}</p>
        <Text label={t('devices.f.confirmHost', { host: target.hostname })} value={confirm} onChange={setConfirm} required mono autoFocus />
      </form>
    </Modal>
  )
}

function RecoveryDialog({ uuid, path, target, onClose }: { uuid: string; path: string; target: Target; onClose: () => void }) {
  const t = useT()
  const view = useRecoveryView(target.id)
  const [reason, setReason] = useState('')
  const res = view.data
  const four = !!target.detail?.four_eyes_recovery
  const ask = () => view.mutate({ uuid, reason }, { onError: (e) => toast(errorText(e), 'error') })
  let body: ReactNode
  if (res?.key) {
    body = (
      <div className="flex flex-col gap-3">
        <p className="rounded-lg bg-surface-2 p-3 text-center font-mono text-[15px] tracking-wide break-all select-all" aria-label={t('devices.rec.key')}>
          {res.key}
        </p>
        <button type="button" className="btn w-fit" onClick={() => void navigator.clipboard?.writeText(res.key ?? '').then(() => toast(t('devices.copied')))}>
          {t('devices.copy')}
        </button>
        <p className="text-[12.5px] text-muted">{t('devices.rec.keyHelp')}</p>
        {res.rotate && <p className="text-[12.5px] text-warn">{t('devices.rec.rotate')}</p>}
      </div>
    )
  } else if (res?.state === 'pending') body = <p>{t('devices.rec.pending')}</p>
  else if (res?.state === 'requested') body = <p>{t('devices.rec.requested')}</p>
  else
    body = (
      <form id="dlg-rec" className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), ask())}>
        <p className="text-[13px] text-muted">{t(four ? 'devices.rec.fourEyes' : 'devices.rec.audited')}</p>
        <Text label={t('devices.rec.reason')} value={reason} onChange={setReason} required={four} max={500} autoFocus />
      </form>
    )
  return (
    <Modal
      open
      onClose={onClose}
      title={t('devices.rec.title')}
      description={<span className="font-mono">{path}</span>}
      footer={
        res ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            {t('common.close')}
          </button>
        ) : (
          <Foot form="dlg-rec" onClose={onClose} label={t(four ? 'devices.rec.request' : 'devices.rec.show')} busy={view.isPending} disabled={four && !reason.trim()} />
        )
      }
    >
      {body}
    </Modal>
  )
}

function ShellDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const t = useT()
  const nav = useNavigate()
  const start = useShellStart(target.id)
  const [user, setUser] = useState('')
  const s = target.detail?.shell
  const off = s ? !s.policy : false
  return (
    <Modal open onClose={onClose} title={t('devices.cmd.shell')} description={t('devices.shell.limits', { max: s?.max_minutes ?? 60, idle: s?.idle_minutes ?? 15 })} footer={<Foot form="dlg-shell" onClose={onClose} label={t('devices.shell.start')} busy={start.isPending} disabled={off} />}>
      <form
        id="dlg-shell"
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (off) return
          start.mutate(user, {
            onSuccess: (r) => {
              if (r.id) void nav({ to: '/devices/$id/shell/$sid', params: { id: target.id, sid: r.id } })
              else {
                toast(t('devices.shell.approval'))
                onClose()
              }
            },
            onError: (er) => toast(errorText(er), 'error'),
          })
        }}
      >
        {off && (
          <p role="alert" className="text-[13px] font-medium text-bad">
            {t('devices.shell.policyOff')}
          </p>
        )}
        <Text label={t('devices.shell.user')} help={t(s?.allow_root ? 'devices.shell.userHelpRoot' : 'devices.shell.userHelp')} value={user} onChange={setUser} mono autoFocus />
        {s?.four_eyes && <p className="text-[12.5px] text-muted">{t('devices.shell.fourEyes')}</p>}
      </form>
    </Modal>
  )
}
