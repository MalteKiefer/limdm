// The host name card of the configuration tab: what com.limdm.hostname
// computed on the device, the source, the result and the name before the
// last change, as the agent reported it.
import { Badge, Card, type Tone } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateTime } from '../../i18n/format'
import type { DeviceDetail } from './api'

export const hostnameTone = (r?: string): Tone => (r === 'failed' ? 'bad' : r === 'waiting' ? 'warn' : r ? 'ok' : 'off')

export function HostnameCard({ d }: { d: DeviceDetail }) {
  const t = useT()
  const h = d.inventory.hostname_info
  if (!h?.result) return null
  const row = (label: string, value?: string) => (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className="font-mono break-all">{value || '–'}</dd>
    </>
  )
  return (
    <Card title={t('devices.hn.title')} sub={t('devices.hn.sub')} id="dv-hostname">
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-body">
        {row(t('devices.hn.current'), d.inventory.hostname)}
        {row(t('devices.hn.target'), h.target)}
        {row(t('devices.hn.source'), h.source)}
        <dt className="text-muted">{t('devices.hn.result')}</dt>
        <dd>
          <Badge tone={hostnameTone(h.result)}>{t(`devices.hn.r.${h.result}` as MessageKey)}</Badge>
          {h.detail && <span className="ml-2 text-meta text-muted">{h.detail}</span>}
        </dd>
        {h.previous && row(t('devices.hn.previous'), h.previous)}
        {h.changed_at && (
          <>
            <dt className="text-muted">{t('devices.hn.changed')}</dt>
            <dd title={dateTime(h.changed_at)}>{ago(h.changed_at)}</dd>
          </>
        )}
        {(h.ptr || h.fqdn || h.address) && row(t('devices.hn.address'), [h.address, h.ptr && `PTR ${h.ptr}`, h.fqdn && `DNS ${h.fqdn}`].filter(Boolean).join(' · '))}
      </dl>
      {h.warning && (
        <p role="note" className="mt-3 rounded-lg bg-warn-soft p-3 text-body">
          {h.warning}
        </p>
      )}
    </Card>
  )
}
