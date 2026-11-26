// The inbox ("Eingang"): approvals, warnings and failed commands in one
// list by risk, the detail beside it with everything a decision needs.
// Approving or rejecting (with a reason) moves the selection to the next item.
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { BellOff, Bell, CheckCircle2, CircleAlert, Copy, DatabaseBackup, ShieldAlert, ShieldX, TerminalSquare, TriangleAlert, WifiOff, type LucideIcon } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { useMe, useCan } from '../../api/me'
import type { Schemas } from '../../api/client'
import { DiffViewer } from '../../components/diff'
import { Field } from '../../components/form'
import { SideSheet, SplitView, TabBar } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Modal, PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateTime } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { useApprovals, useAttention, useAuditStatus, useDecide, useFailedCommands, useLibraryItem } from './api'
import { actionLabel, byRisk, commandType, isMuted, mute, nextAfter, risk, type Approval, type Risk } from './risk'

type Group = 'all' | 'approvals' | 'warnings' | 'commands'
type Search = { group?: Group; item?: string; hist?: string; muted?: string }

type Row = {
  id: string
  group: Exclude<Group, 'all'>
  risk: Risk
  at: string
  expires?: string
  icon: LucideIcon
  title: string
  meta: string
  approval?: Approval
  command?: Schemas['FleetCommand']
  warning?: { text: string; to: string; search?: Record<string, string>; link: string }
}

const tone = (r: Risk) => (r === 3 ? 'bad' : r === 2 ? 'warn' : 'neutral')

export function InboxPage() {
  const t = useT()
  const me = useMe()
  const canAudit = useCan('audit')
  const search = useSearch({ strict: false }) as Search
  const nav = useNavigate()
  const group = search.group ?? 'all'
  const history = search.hist === '1'
  const approvals = useApprovals(history)
  const commands = useFailedCommands()
  const attention = useAttention()
  const audit = useAuditStatus(canAudit)
  const [, setTick] = useState(0) // re-render after muting
  // new credentials of an approved request, shown once; the request leaves the list
  const [creds, setCreds] = useState('')
  const set = (s: Partial<Search>) => void nav({ to: '/inbox', search: { ...search, ...s }, replace: true })

  const rows = useMemo(() => {
    const out: Row[] = []
    for (const a of approvals.data ?? []) {
      out.push({
        id: `a${a.id}`,
        group: 'approvals',
        risk: a.status === 'pending' ? risk(a) : 1,
        at: a.created_at,
        expires: a.status === 'pending' ? a.expires_at : undefined,
        icon: a.action === 'remote_shell' ? TerminalSquare : ShieldAlert,
        title: `${actionLabel(a, t)} · ${a.target}`,
        meta: `${a.requested_by} · ${ago(a.created_at)}`,
        approval: a,
      })
    }
    for (const c of commands.data ?? []) {
      out.push({ id: `c${c.id}`, group: 'commands', risk: c.type === 'wipe' || c.type === 'lock' || c.type === 'lost' ? 2 : 1, at: c.updated_at, icon: TriangleAlert, title: t('inbox.cmdFailed', { type: c.type, host: c.hostname }), meta: `${c.created_by} · ${ago(c.updated_at)}`, command: c })
    }
    const a = attention.data
    const now = new Date().toISOString()
    const warn = (id: string, r: Risk, icon: LucideIcon, title: string, text: string, to: string, link: string, s?: Record<string, string>) =>
      out.push({ id, group: 'warnings', risk: r, at: now, icon, title, meta: t('inbox.warning'), warning: { text, to, search: s, link } })
    if (audit.data?.broken_at) warn('w-audit', 3, ShieldX, t('inbox.w.audit', { id: audit.data.broken_at }), t('inbox.w.auditText'), '/activity', t('inbox.toActivity'))
    if (a?.last_backup && a.last_backup.status !== 'ok' && a.last_backup.status !== 'running')
      warn('w-backup', 3, DatabaseBackup, t('inbox.w.backup'), a.last_backup.error || dateTime(a.last_backup.started_at), '/settings', t('inbox.toSettings'), { s: 'backup' })
    if (a?.noncompliant) warn('w-nc', 2, CircleAlert, t('inbox.w.noncompliant', { count: a.noncompliant }), t('inbox.w.noncompliantText'), '/devices', t('inbox.toDevices'), { q: 'status:non-compliant' })
    if (a?.exceptions_expiring_7d) warn('w-exc', 2, CircleAlert, t('inbox.w.exceptions', { count: a.exceptions_expiring_7d }), t('inbox.w.exceptionsText'), '/compliance', t('inbox.toCompliance'))
    if (a?.stale) warn('w-stale', 1, WifiOff, t('inbox.w.stale', { count: a.stale }), t('inbox.w.staleText', { hours: me.stale_hours }), '/devices', t('inbox.toDevices'), { q: 'status:stale' })
    return out.sort(byRisk)
  }, [approvals.data, commands.data, attention.data, audit.data, t, me.stale_hours])

  const showMuted = search.muted === '1'
  const visible = rows.filter((r) => (group === 'all' || r.group === group) && (showMuted || !r.warning || !isMuted(r.id)))
  const mutedCount = rows.filter((r) => r.warning && isMuted(r.id)).length
  const count = (g: Exclude<Group, 'all'>) => rows.filter((r) => r.group === g && (r.group !== 'approvals' || r.approval?.status === 'pending') && !(r.warning && isMuted(r.id))).length
  const sel = rows.find((r) => r.id === search.item)
  const idx = sel ? visible.findIndex((r) => r.id === sel.id) : -1
  const err = approvals.error ?? commands.error ?? attention.error

  const list = (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-[var(--pad-card)] pt-2">
        <TabBar
          idBase="inbox"
          label={t('inbox.groups')}
          value={group}
          onChange={(g) => set({ group: g === 'all' ? undefined : g })}
          tabs={[
            { value: 'all', label: t('inbox.all') },
            { value: 'approvals', label: t('inbox.approvals'), count: count('approvals') },
            { value: 'warnings', label: t('inbox.warnings'), count: count('warnings') },
            { value: 'commands', label: t('inbox.commands'), count: count('commands') },
          ]}
        />
      </div>
      <div className="flex flex-wrap items-center gap-3 px-[var(--pad-card)] py-2 text-meta text-muted">
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={history} onChange={(e) => set({ hist: e.target.checked ? '1' : undefined })} /> {t('inbox.showDecided')}
        </label>
        {mutedCount > 0 && (
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={showMuted} onChange={(e) => set({ muted: e.target.checked ? '1' : undefined })} /> {t('inbox.showMuted', { count: mutedCount })}
          </label>
        )}
      </div>
      {err ? (
        <ErrorState error={err} onRetry={() => void Promise.all([approvals.refetch(), commands.refetch(), attention.refetch()])} />
      ) : approvals.isLoading || commands.isLoading || attention.isLoading ? (
        <LoadingState />
      ) : !visible.length ? (
        <EmptyState icon={CheckCircle2} title={t('inbox.emptyTitle')}>
          {t('inbox.emptyBody')}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line" aria-label={t('inbox.title')}>
          {visible.map((r) => (
            <li key={r.id}>
              <Link
                to="/inbox"
                search={{ ...search, item: r.id }}
                aria-current={r.id === search.item ? 'true' : undefined}
                className={cx('flex items-center gap-3 px-[var(--pad-card)] py-2.5 hover:bg-surface-2', r.id === search.item && 'bg-surface-2')}
              >
                <span className={cx('grid size-8 shrink-0 place-items-center rounded-lg', r.risk === 3 ? 'bg-bad-soft text-bad' : r.risk === 2 ? 'bg-warn-soft text-warn' : 'bg-surface-2 text-muted')}>
                  <r.icon size={16} aria-hidden />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{r.title}</span>
                  <span className="block truncate text-meta text-muted">{r.meta}</span>
                </span>
                {r.approval && r.approval.status !== 'pending' ? <StatusBadge status={r.approval.status} /> : <Badge tone={tone(r.risk)}>{t(`inbox.risk.${r.risk}` as MessageKey)}</Badge>}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )

  const close = () => set({ item: undefined })
  const step = (d: number) => (idx >= 0 && visible[idx + d] ? () => set({ item: visible[idx + d].id }) : undefined)
  const detail = sel && (
    <SideSheet title={sel.title} sub={sel.meta} onClose={close} onPrev={step(-1)} onNext={step(1)}>
      {sel.approval ? (
        <ApprovalDetail
          a={sel.approval}
          onDone={(c) => {
            if (c) setCreds(c)
            set({ item: nextAfter(visible.filter((r) => r.approval?.status === 'pending' || !r.approval), sel.id) })
          }}
        />
      ) : sel.command ? (
        <CommandDetail c={sel.command} />
      ) : (
        sel.warning && (
          <div className="flex flex-col gap-4">
            <p>{sel.warning.text}</p>
            <div className="flex flex-wrap gap-2">
              <Link to={sel.warning.to} search={sel.warning.search} className="btn btn-primary">
                {sel.warning.link}
              </Link>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  const on = !isMuted(sel.id)
                  mute(sel.id, on)
                  toast(on ? t('inbox.mutedToast') : t('inbox.unmutedToast'))
                  setTick((n) => n + 1)
                }}
              >
                {isMuted(sel.id) ? <Bell size={14} aria-hidden /> : <BellOff size={14} aria-hidden />} {isMuted(sel.id) ? t('inbox.unmute') : t('inbox.mute')}
              </button>
            </div>
          </div>
        )
      )}
    </SideSheet>
  )

  return (
    <div>
      <PageHeader title={t('inbox.title')} sub={t('inbox.sub')} />
      {!me.four_eyes && <p className="mb-3 rounded-lg bg-surface-2 p-3 text-body text-muted">{t('inbox.fourEyesOff')}</p>}
      <SplitView list={list} detail={detail || undefined} />
      <Modal
        open={!!creds}
        onClose={() => setCreds('')}
        title={t('inbox.credsTitle')}
        description={t('inbox.credsBody')}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => void navigator.clipboard?.writeText(creds).then(() => toast(t('inbox.copied')))}>
            <Copy size={14} aria-hidden /> {t('inbox.copy')}
          </button>
        }
      >
        <pre className="overflow-x-auto rounded-lg bg-surface-2 p-3 font-mono text-meta whitespace-pre-wrap">{creds}</pre>
      </Modal>
    </div>
  )
}

function StatusBadge({ status }: { status: Approval['status'] }) {
  const t = useT()
  return <Badge tone={status === 'pending' ? 'warn' : status === 'rejected' ? 'bad' : status === 'expired' ? 'neutral' : 'ok'}>{t(`inbox.status.${status}` as MessageKey)}</Badge>
}

function Prop({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-2 py-1.5 text-body max-sm:grid-cols-1">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

const deviceAction = (a: Approval) => a.action === 'command' || a.action === 'recovery.view' || a.action === 'remote_shell'

function ApprovalDetail({ a, onDone }: { a: Approval; onDone: (credentials?: string) => void }) {
  const t = useT()
  const me = useMe()
  const isAdmin = useCan('admin')
  const decide = useDecide()
  const [op, setOp] = useState<'approve' | 'reject' | null>(null)
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')
  const own = a.requested_by === me.login
  const cmd = commandType(a)
  const destructive = cmd === 'wipe' || a.action === 'remote_shell'
  const submit = () => {
    if (op === 'reject' && !reason.trim()) {
      setError(t('inbox.reasonRequired'))
      return
    }
    decide.mutate(
      { id: a.id, op: op!, reason: reason.trim() },
      {
        onSuccess: (r) => {
          toast(op === 'approve' ? t('inbox.approved') : t('inbox.rejected'))
          setOp(null)
          setReason('')
          onDone(r.credentials)
        },
        onError: (e) => {
          setOp(null)
          toast(errorText(e), 'error')
        },
      },
    )
  }
  return (
    <div className="flex flex-col gap-4">
      {destructive && a.status === 'pending' && (
        <p role="note" className="flex gap-2 rounded-lg bg-bad-soft p-3 text-body text-bad">
          <TriangleAlert size={16} className="mt-0.5 shrink-0" aria-hidden /> {cmd === 'wipe' ? t('inbox.wipeWarning') : t('inbox.shellWarning')}
        </p>
      )}
      <dl className="divide-y divide-line">
        <Prop label={t('inbox.request')}>{actionLabel(a, t)}</Prop>
        <Prop label={t('inbox.target')}>
          {deviceAction(a) ? (
            <Link to="/devices/$id" params={{ id: a.target }} className="font-mono text-accent hover:underline">
              {a.target}
            </Link>
          ) : (
            <span className="font-mono">{a.target}</span>
          )}
        </Prop>
        <Prop label={t('inbox.requestedBy')}>
          {a.requested_by} · {dateTime(a.created_at)}
        </Prop>
        <Prop label={t('inbox.reason')}>{a.reason || <span className="text-muted">{t('inbox.noReason')}</span>}</Prop>
        <Prop label={t('inbox.statusLabel')}>
          <StatusBadge status={a.status} />
          {a.status === 'pending' && <span className="ml-2 text-muted">{t('inbox.expires', { at: dateTime(a.expires_at) })}</span>}
          {a.decided_by && (
            <span className="ml-2 text-muted">
              {a.decided_by}
              {a.decided_at && ` · ${dateTime(a.decided_at)}`}
            </span>
          )}
        </Prop>
        {a.decision_reason && <Prop label={t('inbox.decisionReason')}>{a.decision_reason}</Prop>}
      </dl>
      <Payload a={a} />
      {a.status === 'pending' && isAdmin && (
        <div className="flex flex-wrap gap-2 border-t border-line pt-4">
          {own ? (
            <p className="text-body text-muted">{t('inbox.ownRequest')}</p>
          ) : (
            <>
              <button type="button" className="btn btn-primary" onClick={() => setOp('approve')}>
                {t('inbox.approve')}
              </button>
              <button type="button" className="btn btn-danger" onClick={() => setOp('reject')}>
                {t('inbox.reject')}
              </button>
            </>
          )}
        </div>
      )}
      <Modal
        open={op !== null}
        onClose={() => setOp(null)}
        title={op === 'approve' ? t('inbox.approveTitle') : t('inbox.rejectTitle')}
        description={op === 'approve' ? t('inbox.approveBody') : t('inbox.rejectBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setOp(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className={cx('btn', op === 'approve' ? 'btn-primary' : 'btn-danger')} disabled={decide.isPending} onClick={submit}>
              {op === 'approve' ? t('inbox.approve') : t('inbox.reject')}
            </button>
          </>
        }
      >
        <Field label={t('inbox.decisionReason')} required={op === 'reject'} error={error} help={t('inbox.reasonHelp')}>
          {({ id, describedBy, invalid }) => (
            <textarea
              id={id}
              className="field"
              rows={3}
              maxLength={500}
              value={reason}
              aria-describedby={describedBy}
              aria-invalid={invalid || undefined}
              aria-required={op === 'reject' || undefined}
              onChange={(e) => {
                setReason(e.target.value)
                setError('')
              }}
            />
          )}
        </Field>
      </Modal>
    </div>
  )
}

const pretty = (v: unknown) => JSON.stringify(v, null, 2)

/** What the request would do, per action type. */
function Payload({ a }: { a: Approval }) {
  const t = useT()
  const p = (a.payload ?? {}) as Record<string, unknown>
  const item = a.action === 'library.save' ? (p.item as { id?: number } | undefined) : undefined
  const current = useLibraryItem(item?.id || undefined)
  let body: ReactNode
  if (a.action === 'command') {
    body = <pre className="max-h-[50vh] overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-meta whitespace-pre-wrap">{typeof p.payload === 'string' && p.payload ? p.payload : t('inbox.noPayload')}</pre>
  } else if (a.action === 'recovery.view' || a.action === 'remote_shell') {
    body = <p className="text-body text-muted">{a.action === 'remote_shell' ? t('inbox.shellBody') : t('inbox.recoveryBody')}</p>
  } else if (item) {
    body = current.data ? <DiffViewer before={pretty(current.data)} after={pretty({ ...current.data, ...item })} label={t('inbox.diff')} /> : <pre className="max-h-[50vh] overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-meta">{pretty(p)}</pre>
  } else {
    body = <pre className="max-h-[50vh] overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-meta">{pretty(p)}</pre>
  }
  return (
    <section aria-label={t('inbox.payload')}>
      <h3 className="mb-2 text-meta font-semibold text-muted">{t('inbox.payload')}</h3>
      {body}
    </section>
  )
}

function CommandDetail({ c }: { c: Schemas['FleetCommand'] }) {
  const t = useT()
  return (
    <div className="flex flex-col gap-4">
      <dl className="divide-y divide-line">
        <Prop label={t('inbox.device')}>
          <Link to="/devices/$id" params={{ id: c.device_id }} className="text-accent hover:underline">
            {c.hostname}
          </Link>
        </Prop>
        <Prop label={t('inbox.cmdType')}>{c.type}</Prop>
        <Prop label={t('inbox.requestedBy')}>
          {c.created_by} · {dateTime(c.created_at)}
        </Prop>
        <Prop label={t('inbox.failedAt')}>{dateTime(c.updated_at)}</Prop>
      </dl>
      <section aria-label={t('inbox.output')}>
        <h3 className="mb-2 text-meta font-semibold text-muted">{t('inbox.output')}</h3>
        <pre className="max-h-[50vh] overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-meta whitespace-pre-wrap">{c.output || t('inbox.noOutput')}</pre>
      </section>
      <Link to="/activity" search={{ target: c.device_id }} className="btn self-start">
        {t('inbox.deviceActivity')}
      </Link>
    </div>
  )
}
