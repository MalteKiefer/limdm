// Evidence export: pick a file, download it through the API, show its
// SHA-256 next to the matching export.done audit entry.
import { useQueryClient } from '@tanstack/react-query'
import { FileCheck2 } from 'lucide-react'
import { useState } from 'react'
import { Field } from '../../components/form'
import { errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Modal } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateTime } from '../../i18n/format'
import { downloadExport, type ExportKind } from '../../components/download'
import { useExportAudit } from './api'
import { isoDay } from './logic'

const kinds: ExportKind[] = ['evidence.pdf', 'evidence.json', 'compliance.csv', 'compliance-history.csv', 'exceptions.csv', 'inventory.csv', 'audit.csv']
const windows = [30, 90, 365]

export function ExportDialog({ open, onClose, initial = 'evidence.pdf', at: initialAt, device }: { open: boolean; onClose: () => void; initial?: ExportKind; at?: string; device?: string }) {
  const t = useT()
  const qc = useQueryClient()
  const [kind, setKind] = useState<ExportKind>(initial)
  const [at, setAt] = useState(initialAt ?? isoDay(new Date()))
  const [days, setDays] = useState(90)
  const [busy, setBusy] = useState(false)
  const [sha, setSha] = useState<string>()
  const audit = useExportAudit(open)
  const match = sha ? audit.data?.items?.find((e) => e.detail?.includes(`sha256=${sha}`)) : undefined
  const run = async () => {
    setBusy(true)
    try {
      const h = await downloadExport(kind, kind === 'compliance-history.csv' ? { at, device } : kind.startsWith('evidence.') ? { days } : {})
      setSha(h)
      toast(t('compliance.exp.done', { file: kind }))
      // the server writes export.done right after the last byte: look again briefly
      for (let i = 0; i < 5; i++) {
        await qc.invalidateQueries({ queryKey: ['compliance', 'exports'] })
        const items = qc.getQueryData<{ items?: { detail?: string }[] }>(['compliance', 'exports'])?.items
        if (items?.some((e) => e.detail?.includes(`sha256=${h}`))) break
        await new Promise((r) => setTimeout(r, 300))
      }
    } catch (e) {
      toast(errorText(e), 'error')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      title={t('compliance.exp.title')}
      description={t('compliance.exp.sub')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.close')}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void run()}>
            <FileCheck2 size={15} aria-hidden /> {t('compliance.exp.download')}
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1 text-body font-medium">{t('compliance.exp.kind')}</legend>
          {kinds.map((k) => (
            <label key={k} className="flex items-start gap-2 text-body">
              <input type="radio" name="export-kind" value={k} checked={kind === k} onChange={() => setKind(k)} className="mt-0.5" />
              <span>
                <span className="font-mono text-meta">{k}</span>
                <span className="block text-muted">{t(`compliance.exp.kind.${k}` as MessageKey)}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {kind === 'compliance-history.csv' && (
          <Field label={t('compliance.hist.at')} required>
            {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} type="date" className="field" value={at} max={isoDay(new Date())} onChange={(e) => setAt(e.target.value)} />}
          </Field>
        )}
        {kind.startsWith('evidence.') && (
          <Field label={t('compliance.exp.window')} help={t('compliance.exp.windowHelp')}>
            {({ id, describedBy }) => (
              <select id={id} aria-describedby={describedBy} className="field" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {windows.map((d) => (
                  <option key={d} value={d}>
                    {t('compliance.exp.days', { count: d })}
                  </option>
                ))}
              </select>
            )}
          </Field>
        )}
        {sha && (
          <div className="rounded-lg bg-surface-2 p-3 text-body" aria-live="polite">
            <div className="font-medium">{t('compliance.exp.sha')}</div>
            <code className="block font-mono text-micro break-all">{sha}</code>
            <div className="mt-1 text-muted">{match ? t('compliance.exp.match', { id: match.id ?? 0 }) : t('compliance.exp.noMatch')}</div>
          </div>
        )}
        <section>
          <h3 className="mb-1 text-meta font-semibold text-muted">{t('compliance.exp.recent')}</h3>
          {!audit.data?.items?.length ? (
            <p className="text-body text-muted">{t('compliance.exp.none')}</p>
          ) : (
            <ul className="divide-y divide-line rounded-lg border border-line text-meta">
              {audit.data.items.map((e) => (
                <li key={e.id} className="flex flex-col px-3 py-1.5">
                  <span className="flex justify-between gap-2">
                    <span className="font-mono">{e.target}</span>
                    <span className="text-muted">{e.at && dateTime(e.at)}</span>
                  </span>
                  <span className="truncate font-mono text-micro text-muted">
                    #{e.id} {e.actor} {e.detail}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Modal>
  )
}
