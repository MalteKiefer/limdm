// Line diff between two texts (JSON of a declaration, a script), unified view
// with old and new line numbers. Added and removed lines differ by sign and
// color, so the change reads without color too.
import { diffLines } from 'diff'
import { useMemo } from 'react'
import { useT } from '../i18n'
import { cx } from '../lib/cx'

type Line = { kind: '+' | '-' | ' '; text: string; a?: number; b?: number }

export function diffRows(before: string, after: string): Line[] {
  const out: Line[] = []
  let a = 1
  let b = 1
  for (const part of diffLines(before, after)) {
    const lines = part.value.replace(/\n$/, '').split('\n')
    for (const text of lines) {
      if (part.added) out.push({ kind: '+', text, b: b++ })
      else if (part.removed) out.push({ kind: '-', text, a: a++ })
      else out.push({ kind: ' ', text, a: a++, b: b++ })
    }
  }
  return out
}

export function DiffViewer({ before, after, label }: { before: string; after: string; label?: string }) {
  const t = useT()
  const rows = useMemo(() => diffRows(before, after), [before, after])
  const added = rows.filter((r) => r.kind === '+').length
  const removed = rows.filter((r) => r.kind === '-').length
  return (
    <figure className="overflow-hidden rounded-lg border border-line">
      <figcaption className="flex gap-3 border-b border-line bg-surface-2 px-3 py-1.5 text-[12px] text-muted">
        <span className="font-medium text-fg">{label ?? t('diff.title')}</span>
        {added + removed === 0 ? (
          <span>{t('diff.none')}</span>
        ) : (
          <>
            <span className="text-ok">{t('diff.added', { count: added })}</span>
            <span className="text-bad">{t('diff.removed', { count: removed })}</span>
          </>
        )}
      </figcaption>
      <div className="max-h-[480px] overflow-auto">
        <table className="w-full font-mono text-[12px] leading-5">
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={cx(r.kind === '+' && 'bg-ok-soft', r.kind === '-' && 'bg-bad-soft')}>
                <td className="w-10 px-2 text-right text-muted select-none">{r.a ?? ''}</td>
                <td className="w-10 px-2 text-right text-muted select-none">{r.b ?? ''}</td>
                <td className={cx('w-5 text-center select-none', r.kind === '+' ? 'text-ok' : r.kind === '-' ? 'text-bad' : 'text-muted')} aria-label={r.kind === '+' ? '+' : r.kind === '-' ? '−' : undefined}>
                  {r.kind}
                </td>
                <td className="pr-3 whitespace-pre">{r.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </figure>
  )
}
