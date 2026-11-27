// The firewall tab of the device page: the rules the host firewall holds
// (reported by the agent), grouped managed, foreign and system, with three
// actions per foreign rule: adopt into a firewall item, keep as an
// exception, discard on the device (signed command, admins, four eyes).
import { BrickWall, Check, ShieldOff, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type Schemas } from '../../api/client'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { useRun } from './actions'
import type { DeviceDetail } from './api'
import { filterRules } from './logic'

type Rule = Schemas['DeviceFirewallRule']
const origins = ['foreign', 'managed', 'system'] as const

const useFirewall = (id: string) => useQuery({ queryKey: ['devices', 'firewall', id], queryFn: () => unwrap(api.GET('/api/v1/devices/{id}/firewall', { params: { path: { id } } })) })

function useRuleAction(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ rid, action, item_id, name }: { rid: string; action: 'adopt' | 'keep'; item_id?: number; name?: string }) =>
      unwrap(api.POST('/api/v1/devices/{id}/firewall/rules/{rid}/{action}', { params: { path: { id, rid, action } }, body: { item_id, name } })) as Promise<{ approval_id?: number }>,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['devices'] }),
  })
}

const mono = (v?: string) => <span className="font-mono text-meta break-all">{v ?? ''}</span>
const raw = (v?: string) => <pre className="overflow-x-auto rounded bg-surface-2 p-2 font-mono text-meta break-all whitespace-pre-wrap">{v}</pre>

export function FirewallTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const fw = useFirewall(d.id)
  const run = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const act = useRuleAction(d.id)
  const [q, setQ] = useState('')
  const [pick, setPick] = useState<{ rule: Rule; action: 'adopt' | 'keep' } | null>(null)
  const [discard, setDiscard] = useState<Rule | null>(null)
  const [ack, setAck] = useState(false)
  const [item, setItem] = useState('')
  const [name, setName] = useState('')
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
  const fourEyes = d.four_eyes_commands.includes('firewall_remove_rule')
  const openPick = (rule: Rule, action: 'adopt' | 'keep') => {
    setItem(items[0] ? String(items[0].id) : 'new')
    setName('')
    setPick({ rule, action })
  }
  const savePick = () => {
    if (!pick) return
    const body = item === 'new' ? { name: name.trim() } : { item_id: Number(item) }
    act.mutate(
      { rid: pick.rule.id, action: pick.action, ...body },
      {
        onSuccess: (r) => {
          toast(r.approval_id ? t('devices.toast.approval') : t(pick.action === 'adopt' ? 'devices.fw.adopted' : 'devices.fw.kept'))
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
                              onClick={() => {
                                setAck(false)
                                setDiscard(r)
                              }}
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
        title={t(pick?.action === 'keep' ? 'devices.fw.keepTitle' : 'devices.fw.adoptTitle')}
        description={t(pick?.action === 'keep' ? 'devices.fw.keepBody' : 'devices.fw.adoptBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setPick(null)}>
              {t('common.cancel')}
            </button>
            <button type="button" className="btn btn-primary" disabled={act.isPending || (item === 'new' && !name.trim())} onClick={savePick}>
              {t(pick?.action === 'keep' ? 'devices.fw.keep' : 'devices.fw.adopt')}
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          {raw(pick?.rule.raw)}
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
        </div>
      </Modal>
      <Confirm
        open={!!discard}
        onClose={() => setDiscard(null)}
        title={t('devices.fw.discardTitle')}
        body={t('devices.fw.discardBody', { host: d.hostname })}
        confirm={t('devices.fw.discard')}
        danger
        reason={fourEyes}
        busy={run.pending || (!!discard?.risk && !ack)}
        onConfirm={(reason) => discard && run.run('firewall_remove_rule', { rule_id: discard.id, ...(discard.risk ? { confirm_risk: ack } : {}), ...(reason ? { reason } : {}) }, () => setDiscard(null))}
      >
        {raw(discard?.raw)}
        {discard?.risk && (
          <div className="flex flex-col gap-2 rounded border border-bad p-2">
            <p className="text-body text-bad">{t(`devices.fw.riskBody.${discard.risk}` as MessageKey)}</p>
            <label className="flex items-center gap-2 text-body">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              {t('devices.fw.riskAck')}
            </label>
          </div>
        )}
      </Confirm>
    </div>
  )
}
