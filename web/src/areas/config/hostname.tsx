// com.limdm.hostname in the item editor: the warning that a new host name
// is disruptive, and the name the declaration computes for one device
// (from its last report; part of the template preview).
import { TriangleAlert } from 'lucide-react'
import { useT } from '../../i18n'

export type HostnamePreviewData = {
  current: string
  target?: string
  source?: string
  error?: string
  serial?: string
  facts?: { address?: string; mac?: string; ptr?: string; fqdn?: string; result?: string; target?: string }
}

/** Shown in the editor of every host name item. */
export function HostnameWarning() {
  const t = useT()
  return (
    <div role="note" className="card flex gap-2 border-warn bg-warn-soft p-[var(--pad-card)] text-body">
      <TriangleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-hidden />
      <div>
        <p className="font-semibold">{t('config.hnWarnTitle')}</p>
        <p className="text-meta">{t('config.hnWarn')}</p>
      </div>
    </div>
  )
}

export function HostnameResult({ data }: { data: HostnamePreviewData }) {
  const t = useT()
  const f = data.facts ?? {}
  return (
    <div className="flex flex-col gap-2">
      {data.error ? (
        <p role="alert" className="rounded-lg bg-bad-soft p-3 text-body text-bad">
          {t('config.hnKeeps', { error: data.error })}
        </p>
      ) : (
        <p className="rounded-lg bg-surface-2 p-3 text-body">
          <span className="font-mono">{data.current || '–'}</span> → <span className="font-mono font-semibold">{data.target}</span>
          {data.target && data.current && data.target.split('.')[0] === data.current && <span className="text-muted"> ({t('config.hnSame')})</span>}
        </p>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-meta">
        <dt className="text-muted">{t('config.hnSource')}</dt>
        <dd className="font-mono">{data.source || '–'}</dd>
        <dt className="text-muted">PTR</dt>
        <dd className="font-mono break-all">{f.ptr || '–'}</dd>
        <dt className="text-muted">DNS</dt>
        <dd className="font-mono break-all">{f.fqdn || '–'}</dd>
        <dt className="text-muted">{t('config.hnSerial')}</dt>
        <dd className="font-mono break-all">{data.serial || '–'}</dd>
      </dl>
      <p className="text-meta text-muted">{t('config.hnFactsHelp')}</p>
    </div>
  )
}
