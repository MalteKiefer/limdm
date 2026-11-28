// Small parts shared by the updates page and the device tab.
import { CheckCircle2, CircleDashed, MinusCircle, OctagonX } from 'lucide-react'
import type { ReactNode } from 'react'
import { Badge } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { severityTone } from './logic'

export type Col = { label: string; className?: string }

export function Table({ caption, cols, rows, empty }: { caption: string; cols: Col[]; rows: { key: string; cells: ReactNode[] }[]; empty: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-body">
        <caption className="sr-only">{caption}</caption>
        <thead className="text-meta text-muted">
          <tr>
            {cols.map((c, i) => (
              <th key={i} scope="col" className={'py-1.5 pr-3 font-medium ' + (c.className ?? '')}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length ? (
            rows.map((r) => (
              <tr key={r.key} className="border-t border-line align-top">
                {r.cells.map((c, i) => (
                  <td key={i} className={'py-1.5 pr-3 ' + (cols[i]?.className ?? '')}>
                    {c}
                  </td>
                ))}
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan={cols.length} className="py-4 text-center text-muted">
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

// feedName is the display name of the base feed a derivative was matched through (ubuntu: Ubuntu).
export const feedName = (via: string) => via.charAt(0).toUpperCase() + via.slice(1)

export const mono = (v?: string | number) => <span className="font-mono text-meta break-all">{v ?? ''}</span>

/** A security flag with the advisory's severity (text, never color alone). */
export function SecurityTag({ security, severity }: { security?: boolean; severity?: string }) {
  const t = useT()
  if (!security) return <span className="text-muted">{t('updates.no')}</span>
  return <Badge tone={severityTone(severity) === 'neutral' ? 'warn' : severityTone(severity)}>{severity ? `${t('updates.security')} · ${severity}` : t('updates.security')}</Badge>
}

const runTone = {
  installed: 'ok',
  no_updates: 'neutral',
  failed: 'bad',
  unsupported: 'off',
} as const
const runIcon = {
  installed: CheckCircle2,
  no_updates: MinusCircle,
  failed: OctagonX,
}

/** Outcome of an update run. */
export function RunBadge({ result }: { result?: string }) {
  const t = useT()
  const I = runIcon[result as keyof typeof runIcon] ?? CircleDashed
  return (
    <Badge tone={runTone[result as keyof typeof runTone] ?? 'off'}>
      <I size={12} aria-hidden /> {t(`updates.result.${result ?? 'unsupported'}` as MessageKey)}
    </Badge>
  )
}

export function SourceLabel({ source }: { source?: string }) {
  const t = useT()
  return <>{t(`updates.source.${source ?? 'os_all'}` as MessageKey)}</>
}
