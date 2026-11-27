// The "Containers and VMs" tab of the device page: tool versions, one table
// per kind (Docker, Podman, LXC, LXD, Incus, Proxmox, libvirt) and start,
// stop and restart with a confirmation, allowed by the device's policy.
// A sent action shows a spinner in its row and the tab follows the command
// (with backoff, at most WAIT_LIMIT) until the agent reports the new state.
import { Boxes, Loader2, Play, RefreshCw, RotateCw, Square } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useCan } from '../../api/me'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateTime } from '../../i18n/format'
import { useRun } from '../devices/actions'
import { useCommand, type DeviceDetail } from '../devices/api'
import { mono, Table } from '../updates/parts'
import { useCommands, useDeviceWorkloads } from './api'
import { byKind, isRunning, outcome, pollDelay, resultError, resultState, shortImage, stateTone, WAIT_LIMIT, type Workload } from './logic'

type Action = 'start' | 'stop' | 'restart'

/** A sent command the tab follows; key names the workload ('' for sync). */
type Pending = { cmd: number; key: string; action: Action | 'sync'; name: string; since: number }

const keyOf = (w: Workload) => `${w.kind}/${w.id}`

export function WorkloadsTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const [pending, setPending] = useState<Pending[]>([])
  const active = useRef(new Map<number, ReturnType<typeof setTimeout>>())
  const oldest = Math.min(...pending.map((p) => p.since))
  const q = useDeviceWorkloads(d.id, () => (pending.length ? pollDelay(Date.now() - oldest) : false))
  const run = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const sync = useCommand(d.id)
  const canSync = useCan('commands') && !d.retired
  const [act, setAct] = useState<{ w: Workload; action: Action } | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const syncUntil = q.data ? q.dataUpdatedAt + (q.data.sync_wait ?? 0) * 1000 : 0
  const ticking = pending.length > 0 || syncUntil > now
  useEffect(() => {
    if (!ticking) return
    const h = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(h)
  }, [ticking])
  useEffect(() => {
    const timers = active.current
    return () => timers.forEach((h) => clearTimeout(h))
  }, [])

  const label = (a: Pending['action']) => t(a === 'sync' ? 'workloads.sync' : (`workloads.${a}` as MessageKey))
  // ends following a command once: with its result or after WAIT_LIMIT
  const finish = (p: Pending, how: 'ok' | 'failed' | 'timeout', output = '') => {
    const h = active.current.get(p.cmd)
    if (h === undefined) return
    clearTimeout(h)
    active.current.delete(p.cmd)
    setPending((l) => l.filter((x) => x.cmd !== p.cmd))
    void q.refetch()
    const vars = { action: label(p.action), name: p.name }
    if (how === 'timeout') toast(t('workloads.timeout', vars), 'error')
    else if (how === 'failed') toast(t('workloads.failed', { ...vars, error: resultError(output) }), 'error')
    else if (p.action === 'sync') toast(t('workloads.synced', { name: p.name }))
    else toast(t('workloads.done', { ...vars, state: resultState(output) || t('workloads.unknown') }))
  }
  const follow = (p: Pending) => {
    active.current.set(
      p.cmd,
      setTimeout(() => finish(p, 'timeout'), WAIT_LIMIT),
    )
    setPending((l) => [...l, p])
  }
  useCommands(
    pending.map((p) => ({
      cmd: p.cmd,
      interval: () => pollDelay(Date.now() - p.since),
      onStatus: (status?: string, output?: string) => {
        const o = outcome(status, Date.now() - p.since)
        if (o !== 'wait') finish(p, o, output)
      },
    })),
  )

  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <LoadingState rows={6} />
  const { inventory, control, reports, updated_at, checked_at } = q.data
  const tools = inventory?.tools ?? []
  const items = inventory?.items ?? []
  const canAct = !!control?.allowed && !d.retired
  const enabled = canAct && !!control?.policy
  if (!reports || (!tools.length && !items.length))
    return (
      <EmptyState icon={Boxes} title={t('workloads.none')}>
        {t('workloads.noneBody')}
      </EmptyState>
    )

  const wait = canSync ? Math.max(0, Math.ceil((syncUntil - now) / 1000)) : 0
  const syncing = pending.some((p) => p.action === 'sync')
  const refresh = () => {
    void q.refetch()
    if (!canSync || wait > 0 || syncing) return
    sync.mutate(
      { type: 'sync' },
      {
        onSuccess: (r) => {
          if (r.id) follow({ cmd: r.id, key: '', action: 'sync', name: d.hostname, since: Date.now() })
          void q.refetch() // the new cooldown
        },
        onError: (e) => {
          toast(errorText(e), 'error')
          void q.refetch()
        },
      },
    )
  }
  const button = (w: Workload, action: Action, busy: boolean) => {
    const Icon = { start: Play, stop: Square, restart: RotateCw }[action]
    return (
      <button
        key={action}
        type="button"
        className="btn btn-ghost"
        disabled={!enabled || busy}
        aria-label={`${label(action)}: ${w.name}`}
        title={enabled ? label(action) : t('workloads.policyOff')}
        onClick={() => setAct({ w, action })}
      >
        <Icon size={14} aria-hidden />
      </button>
    )
  }
  const actions = (w: Workload) => {
    const busy = pending.find((p) => p.key === keyOf(w))
    return (
      <span className="flex items-center gap-1">
        {isRunning(w.state) ? [button(w, 'stop', !!busy), button(w, 'restart', !!busy)] : button(w, 'start', !!busy)}
        {busy && (
          <span role="status" className="flex items-center gap-1 whitespace-nowrap text-meta text-muted">
            <Loader2 size={14} className="motion-safe:animate-spin" aria-hidden />
            {t('workloads.busy', { action: label(busy.action) })}
          </span>
        )}
      </span>
    )
  }
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card
        title={t('workloads.tools')}
        sub={updated_at ? t('workloads.updated', { at: dateTime(updated_at) }) : undefined}
        action={
          <span className="flex items-center gap-2">
            {checked_at && (
              <span className="text-meta text-muted" title={dateTime(checked_at)}>
                {t('workloads.asOf', { ago: ago(checked_at, now) })}
              </span>
            )}
            <button type="button" className="btn" disabled={syncing || wait > 0} onClick={refresh}>
              <RefreshCw size={14} className={syncing ? 'motion-safe:animate-spin' : undefined} aria-hidden />
              {wait > 0 ? t('workloads.refreshWait', { seconds: wait }) : t('workloads.refresh')}
            </button>
          </span>
        }
      >
        <ul className="flex flex-wrap gap-2">
          {tools.map((tl) => (
            <li key={tl.kind}>
              <Badge>
                {t(`workloads.kind.${tl.kind}` as MessageKey)} {tl.version}
              </Badge>
            </li>
          ))}
        </ul>
        {!!inventory?.errors?.length && (
          <ul className="mt-2 flex flex-col gap-1 text-meta text-bad">
            {inventory.errors.map((e) => (
              <li key={e}>{t('workloads.error', { error: e })}</li>
            ))}
          </ul>
        )}
        {inventory?.truncated && <p className="mt-2 text-meta text-muted">{t('workloads.truncated')}</p>}
        {canAct && !control?.policy && <p className="mt-2 text-body text-muted">{t('workloads.policyOff')}</p>}
      </Card>
      {byKind(items, tools.map((tl) => tl.kind!)).map(([kind, list]) => (
        <Card key={kind} title={t(`workloads.kind.${kind}` as MessageKey)}>
          <Table
            caption={t(`workloads.kind.${kind}` as MessageKey)}
            cols={[
              { label: t('workloads.name') },
              { label: t('workloads.image') },
              { label: t('workloads.state') },
              { label: t('workloads.details') },
              ...(canAct ? [{ label: t('workloads.actions'), className: 'whitespace-nowrap' }] : []),
            ]}
            rows={list.map((w) => ({
              key: w.id!,
              cells: [
                <span>
                  <span className="font-medium">{w.name}</span> <span className="block font-mono text-meta text-muted">{w.id!.length > 16 ? w.id!.slice(0, 12) : w.id}</span>
                </span>,
                <span title={w.image_id ? `${w.image} (${w.image_id})` : w.image}>{mono(shortImage(w.image))}</span>,
                <Badge tone={stateTone(w.state)}>{w.state || t('workloads.unknown')}</Badge>,
                <span className="text-meta text-muted">
                  {[
                    w.type && t(`workloads.type.${w.type}` as MessageKey),
                    w.project && t('workloads.compose', { project: w.project, service: w.service ?? '' }),
                    w.cpus ? t('workloads.cpus', { count: w.cpus }) : '',
                    w.memory_mb ? t('workloads.memory', { mb: w.memory_mb }) : '',
                    w.restart && t('workloads.restartPolicy', { policy: w.restart }),
                    w.started && t('workloads.started', { at: dateTime(w.started) }),
                    (w.ports ?? []).join(', '),
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </span>,
                ...(canAct ? [actions(w)] : []),
              ],
            }))}
            empty={t('workloads.emptyKind')}
          />
        </Card>
      ))}
      <Confirm
        open={!!act}
        onClose={() => setAct(null)}
        title={act ? t(`workloads.confirm.${act.action}` as MessageKey, { name: act.w.name ?? '', device: d.hostname }) : ''}
        body={act && act.action !== 'start' ? t('workloads.confirm.graceful') : undefined}
        confirm={act ? label(act.action) : ''}
        danger={act?.action !== 'start'}
        reason={!!control?.four_eyes && act?.action !== 'start'}
        busy={run.pending}
        onConfirm={(reason) =>
          act &&
          run.run('workload_action', { kind: act.w.kind!, id: act.w.id!, action: act.action, ...(reason ? { reason } : {}) }, (r) => {
            setAct(null)
            if (r.id) follow({ cmd: r.id, key: keyOf(act.w), action: act.action, name: act.w.name ?? act.w.id!, since: Date.now() })
          })
        }
      />
    </div>
  )
}
