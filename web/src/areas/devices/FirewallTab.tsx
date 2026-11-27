// The firewall tab of the device page: the rules the host firewall holds
// (reported by the agent), grouped managed, foreign and system, with three
// actions per foreign rule, each written into a firewall item of the
// library: adopt, keep as an exception, discard (the remove list: every
// agent deletes the rule whenever it finds it, also after a reboot).
import { BrickWall, Check, ShieldOff, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import type { DeviceDetail } from './api'
import { filterRules } from './logic'

type Rule = Schemas['DeviceFirewallRule']
type Action = 'adopt' | 'keep' | 'remove'
const titles: Record<Action, MessageKey> = { adopt: 'devices.fw.adoptTitle', keep: 'devices.fw.keepTitle', remove: 'devices.fw.discardTitle' }
const bodies: Record<Action, MessageKey> = { adopt: 'devices.fw.adoptBody', keep: 'devices.fw.keepBody', remove: 'devices.fw.discardBody' }
const labels: Record<Action, MessageKey> = { adopt: 'devices.fw.adopt', keep: 'devices.fw.keep', remove: 'devices.fw.discard' }
const done: Record<Action, MessageKey> = { adopt: 'devices.fw.adopted', keep: 'devices.fw.kept', remove: 'devices.fw.removeSet' }
const origins = ['foreign', 'managed', 'system'] as const

const useFirewall = (id: string) => useQuery({ queryKey: ['devices', 'firewall', id], queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/firewall', { params: { path: { id } } })) })

function useRuleAction(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ rid, action, ...body }: { rid: string; action: Action; item_id?: number; name?: string; blueprint_id?: number; confirm?: boolean; confirm_risk?: boolean }) =>
      unwrap(api.POST('/api/v1/devices/{id}/firewall/rules/{rid}/{action}', { params: { path: { id, rid, action } }, body })) as Promise<{ approval_id?: number }>,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['devices'] }),
  })
}

/** Blueprints a new item can be assigned in, with the devices each reaches. */
const useTargets = (id: string, on: boolean) =>
  useQuery({ queryKey: ['devices', 'firewall', id, 'targets'], queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/firewall/targets', { params: { path: { id } } })), enabled: on })

const mono = (v?: string) => <span className="font-mono text-meta break-all">{v ?? ''}</span>
const raw = (v?: string) => <pre className="overflow-x-auto rounded bg-surface-2 p-2 font-mono text-meta break-all whitespace-pre-wrap">{v}</pre>

export function FirewallTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const fw = useFirewall(d.id)
  const act = useRuleAction(d.id)
  const [q, setQ] = useState('')
  const [pick, setPick] = useState<{ rule: Rule; action: Action } | null>(null)
  const [ack, setAck] = useState(false)
  const [item, setItem] = useState('')
  const [name, setName] = useState('')
  const [bp, setBp] = useState('')
  const [sure, setSure] = useState(false)
  const targets = useTargets(d.id, !!pick && item === 'new')
  // preselected: the device's own blueprint, never the global default
  const own = targets.data?.items.find((x) => x.device && !x.global_default)
  const chosen = bp || (own ? String(own.id) : '')
  const target = targets.data?.items.find((x) => String(x.id) === chosen)
  const needsSure = !!target && (target.global_default || target.devices > 1)
  const items = d.items.filter((i) => i.type === 'com.limdm.firewall')
  if (fw.error) return <ErrorState error={fw.error} onRetry={() => void fw.refetch()} />
  if (!fw.data) return <LoadingState rows={6} />
  const { reports, inventory: inv, rules, updated_at } = fw.data
  if (!reports) {
    return (
      <EmptyState icon={BrickWall} title={t('devices.fw.none')}>
        {t('devices.fw.noneBody')}
      </EmptyState>
    )
  }
  const shown = filterRules(rules, q)
  const risky = pick?.action === 'remove' && !!pick.rule.risk
  const openPick = (rule: Rule, action: Action) => {
    setAck(false)
    setItem(items[0] ? String(items[0].id) : 'new')
    setName('')
    setBp('')
    setSure(false)
    setPick({ rule, action })
  }
  const savePick = () => {
    if (!pick) return
    const body = {
      ...(item === 'new' ? { name: name.trim(), blueprint_id: Number(chosen), confirm: sure } : { item_id: Number(item) }),
      ...(pick.action === 'remove' ? { confirm_risk: ack } : {}),
    }
    act.mutate(
      { rid: pick.rule.id, action: pick.action, ...body },
      {
        onSuccess: (r) => {
          toast(r.approval_id ? t('devices.toast.approval') : t(done[pick.action]))
          setPick(null)
        },
        onError: (e) => toast(errorText(e), 'error'),
      },
    )
  }
  const policy = (p?: string) => (p ? <Badge tone={p === 'accept' || p === 'allow' ? 'warn' : 'ok'}>{p}</Badge> : <span className="text-muted">{t('devices.fw.unknown')}</span>)
  const facts: [MessageKey, ReactNode][] = [
    ['devices.fw.backend', <span className="font-medium">{inv.backend || t('devices.fw.noBackend')}</span>],
    ['devices.fw.state', inv.active ? <Badge tone="ok">{t('devices.fw.active')}</Badge> : <Badge tone="warn">{t('devices.fw.inactive')}</Badge>],
    ['devices.fw.in', policy(inv.policy.in)],
    ['devices.fw.out', policy(inv.policy.out)],
    ['devices.fw.forward', policy(inv.policy.forward)],
  ]
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card title={t('devices.fw.title')} sub={updated_at ? t('devices.fw.reported', { at: dateTime(updated_at) }) : undefined}>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {facts.map(([k, v]) => (
            <div key={k}>
              <dt className="text-meta text-muted">{t(k)}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        {inv.truncated && <p className="mt-2 text-meta text-warn">{t('devices.fw.truncated')}</p>}
        {(inv.errors ?? []).map((e) => (
          <p key={e} className="mt-2 font-mono text-meta break-all text-bad">
            {e}
          </p>
        ))}
        <p className="mt-2 text-meta text-muted">{t('devices.fw.help')}</p>
      </Card>
      <Field label={t('devices.fw.filter')}>{({ id }) => <input id={id} type="search" className="field max-w-md" value={q} onChange={(e) => setQ(e.target.value)} />}</Field>
      {origins.map((o) => {
        const list = shown.filter((r) => r.origin === o)
        const actions = o === 'foreign' && admin
        return (
          <Card key={o} title={`${t(`devices.fw.group.${o}`)} ${fmt(list.length)}`} sub={t(`devices.fw.groupSub.${o}`)}>
            {list.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-body">
                  <caption className="sr-only">{t(`devices.fw.group.${o}`)}</caption>
                  <thead className="text-meta text-muted">
                    <tr>
                      <th scope="col" className="py-1.5 pr-3 font-medium">
                        {t('devices.fw.rule')}
                      </th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">
                        {t('devices.fw.place')}
                      </th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">
                        {t('devices.fw.raw')}
                      </th>
                      {actions && (
                        <th scope="col" className="py-1.5 font-medium">
                          <span className="sr-only">{t('devices.fw.actions')}</span>
                        </th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((r) => (
                      <tr key={r.id} className="border-t border-line align-top">
                        <td className="py-1.5 pr-3">
                          <div className="flex flex-wrap items-center gap-1">
                            {r.direction && <Badge>{t(`devices.fw.dir.${r.direction}` as MessageKey)}</Badge>}
                            <span className="font-medium">{r.action}</span>
                            {mono([r.service, r.port && `${r.port}${r.proto ? '/' + r.proto : ''}`, !r.port && r.proto].filter(Boolean).join(' '))}
                            {r.kept && <Badge tone="ok">{t('devices.fw.keptBadge')}</Badge>}
                            {r.risk && <Badge tone="bad">{t(`devices.fw.risk.${r.risk}` as MessageKey)}</Badge>}
                          </div>
                          <div className="text-meta text-muted">
                            {[r.from && t('devices.fw.from', { v: r.from }), r.to && t('devices.fw.to', { v: r.to }), r.iface && t('devices.fw.iface', { v: r.iface }), r.comment].filter(Boolean).join(' · ')}
                          </div>
                        </td>
                        <td className="py-1.5 pr-3">{mono([r.source, r.table, r.chain, r.zone].filter(Boolean).join(' '))}</td>
                        <td className="py-1.5 pr-3">{mono(r.raw)}</td>
                        {actions && (
                          <td className="py-1.5 whitespace-nowrap">
                            <button type="button" className="btn btn-ghost" disabled={!!r.adopt_error} title={r.adopt_error || t('devices.fw.adopt')} aria-label={`${t('devices.fw.adopt')}: ${r.raw}`} onClick={() => openPick(r, 'adopt')}>
                              <Check size={14} aria-hidden />
                            </button>
                            <button type="button" className="btn btn-ghost" disabled={r.kept} title={t('devices.fw.keep')} aria-label={`${t('devices.fw.keep')}: ${r.raw}`} onClick={() => openPick(r, 'keep')}>
                              <ShieldOff size={14} aria-hidden />
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost text-bad"
                              title={t('devices.fw.discard')}
                              aria-label={`${t('devices.fw.discard')}: ${r.raw}`}
                              onClick={() => openPick(r, 'remove')}
                            >
                              <Trash2 size={14} aria-hidden />
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState compact title={t(`devices.fw.empty.${o}`)} />
            )}
          </Card>
        )
      })}
      <Modal
        open={!!pick}
        onClose={() => setPick(null)}
        title={t(titles[pick?.action ?? 'adopt'])}
        description={t(bodies[pick?.action ?? 'adopt'])}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setPick(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={act.isPending || (risky && !ack) || (item === 'new' && (!name.trim() || !target || (needsSure && !sure)))} onClick={savePick}>
              {t(labels[pick?.action ?? 'adopt'])}
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          {raw(pick?.rule.raw)}
          {risky && pick?.rule.risk && (
            <div className="flex flex-col gap-2 rounded border border-bad p-2">
              <p className="text-body text-bad">{t(`devices.fw.riskBody.${pick.rule.risk}` as MessageKey)}</p>
              <label className="flex items-center gap-2 text-body">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                {t('devices.fw.riskAck')}
              </label>
            </div>
          )}
          <Field label={t('devices.fw.item')}>
            {({ id }) => (
              <select id={id} className="field" value={item} onChange={(e) => setItem(e.target.value)}>
                {items.map((i) => (
                  <option key={i.id} value={String(i.id)}>
                    {i.name}
                  </option>
                ))}
                <option value="new">{t('devices.fw.newItem')}</option>
              </select>
            )}
          </Field>
          {item === 'new' && (
            <Field label={t('devices.fw.itemName')} help={t('devices.fw.itemNameHelp')} required>
              {({ id, describedBy }) => <input id={id} className="field" aria-describedby={describedBy} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}
            </Field>
          )}
          {item === 'new' && (
            <Field label={t('devices.fw.blueprint')} help={t('devices.fw.blueprintHelp')} required>
              {({ id, describedBy }) => (
                <select
                  id={id}
                  className="field"
                  aria-describedby={describedBy}
                  value={chosen}
                  onChange={(e) => (setBp(e.target.value), setSure(false))}
                >
                  <option value="">{t('devices.fw.blueprintPick')}</option>
                  {(targets.data?.items ?? []).map((x) => (
                    <option key={x.id} value={String(x.id)}>
                      {t(x.global_default ? 'devices.fw.blueprintGlobal' : 'devices.fw.blueprintOption', { name: x.name, n: fmt(x.devices) })}
                    </option>
                  ))}
                </select>
              )}
            </Field>
          )}
          {item === 'new' && needsSure && target && (
            <div className="flex flex-col gap-2 rounded border border-warn p-2">
              <p className="text-body">{target.global_default ? t('devices.fw.reachGlobal') : t('devices.fw.reachMany', { n: fmt(target.devices) })}</p>
              <label className="flex items-center gap-2 text-body">
                <input type="checkbox" checked={sure} onChange={(e) => setSure(e.target.checked)} />
                {t('devices.fw.reachAck')}
              </label>
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}
