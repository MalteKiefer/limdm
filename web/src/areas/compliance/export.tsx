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
import { fetchExport, useExportAudit, type ExportKind } from './api'
import { isoDay, sha256Hex } from './logic'

const kinds: ExportKind[] = ['compliance.csv', 'compliance-history.csv', 'exceptions.csv', 'inventory.csv', 'audit.csv']

/** Saves a blob under a file name (an object URL is same origin, CSP allows it). */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Downloads an export and returns the hex SHA-256 of its bytes. */
export async function downloadExport(kind: ExportKind, query: { at?: string; device?: string } = {}) {
  const blob = await fetchExport(kind, query)
  const sha = await sha256Hex(await blob.arrayBuffer())
  saveBlob(blob, `limdm-${isoDay(new Date()).replaceAll('-', '')}-${kind}`)
  return sha
}

export function ExportDialog({ open, onClose, initial = 'compliance.csv', at: initialAt, device }: { open: boolean; onClose: () => void; initial?: ExportKind; at?: string; device?: string }) {
  const t = useT()
  const qc = useQueryClient()
  const [kind, setKind] = useState<ExportKind>(initial)
  const [at, setAt] = useState(initialAt ?? isoDay(new Date()))
  const [busy, setBusy] = useState(false)
  const [sha, setSha] = useState<string>()
  const audit = useExportAudit(open)
  const match = sha ? audit.data?.items?.find((e) => e.detail?.includes(`sha256=${sha}`)) : undefined
  const run = async () => {
    setBusy(true)
    try {
      const h = await downloadExport(kind, kind === 'compliance-history.csv' ? { at, device } : {})
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
          <legend className="mb-1 text-[13px] font-medium">{t('compliance.exp.kind')}</legend>
          {kinds.map((k) => (
            <label key={k} className="flex items-start gap-2 text-[13px]">
              <input type="radio" name="export-kind" value={k} checked={kind === k} onChange={() => setKind(k)} className="mt-0.5" />
              <span>
                <span className="font-mono text-[12px]">{k}</span>
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
        {sha && (
          <div className="rounded-lg bg-surface-2 p-3 text-[13px]" aria-live="polite">
            <div className="font-medium">{t('compliance.exp.sha')}</div>
            <code className="block font-mono text-[11.5px] break-all">{sha}</code>
            <div className="mt-1 text-muted">{match ? t('compliance.exp.match', { id: match.id ?? 0 }) : t('compliance.exp.noMatch')}</div>
          </div>
        )}
        <section>
          <h3 className="mb-1 text-[12.5px] font-semibold text-muted">{t('compliance.exp.recent')}</h3>
          {!audit.data?.items?.length ? (
            <p className="text-[13px] text-muted">{t('compliance.exp.none')}</p>
          ) : (
            <ul className="divide-y divide-line rounded-lg border border-line text-[12.5px]">
              {audit.data.items.map((e) => (
                <li key={e.id} className="flex flex-col px-3 py-1.5">
                  <span className="flex justify-between gap-2">
                    <span className="font-mono">{e.target}</span>
                    <span className="text-muted">{e.at && dateTime(e.at)}</span>
                  </span>
                  <span className="truncate font-mono text-[11px] text-muted">
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
