// The "Containers and VMs" tab of the device page: tool versions, one table
// per kind (Docker, Podman, LXC, LXD, Incus, Proxmox, libvirt) and start,
// stop and restart with a confirmation, allowed by the device's policy.
import { Boxes, Play, RotateCw, Square } from 'lucide-react'
import { useState } from 'react'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge, Card } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime } from '../../i18n/format'
import { useRun } from '../devices/actions'
import type { DeviceDetail } from '../devices/api'
import { mono, Table } from '../updates/parts'
import { useDeviceWorkloads } from './api'
import { byKind, isRunning, shortImage, stateTone, type Workload } from './logic'

type Action = 'start' | 'stop' | 'restart'

export function WorkloadsTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const q = useDeviceWorkloads(d.id)
  const run = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const [act, setAct] = useState<{ w: Workload; action: Action } | null>(null)
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <LoadingState rows={6} />
  const { inventory, control, reports, updated_at } = q.data
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
  const button = (w: Workload, action: Action) => {
    const Icon = { start: Play, stop: Square, restart: RotateCw }[action]
    const label = t(`workloads.${action}` as MessageKey)
    return (
      <button
        key={action}
        type="button"
        className="btn btn-ghost"
        disabled={!enabled}
        aria-label={`${label}: ${w.name}`}
        title={enabled ? label : t('workloads.policyOff')}
        onClick={() => setAct({ w, action })}
      >
        <Icon size={14} aria-hidden />
      </button>
    )
  }
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card title={t('workloads.tools')} sub={updated_at ? t('workloads.updated', { at: dateTime(updated_at) }) : undefined}>
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
                ...(canAct ? [<span className="flex gap-1">{isRunning(w.state) ? [button(w, 'stop'), button(w, 'restart')] : button(w, 'start')}</span>] : []),
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
        confirm={act ? t(`workloads.${act.action}` as MessageKey) : ''}
        danger={act?.action !== 'start'}
        reason={!!control?.four_eyes && act?.action !== 'start'}
        busy={run.pending}
        onConfirm={(reason) => act && run.run('workload_action', { kind: act.w.kind!, id: act.w.id!, action: act.action, ...(reason ? { reason } : {}) }, () => setAct(null))}
      />
    </div>
  )
}
