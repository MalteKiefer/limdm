// JSON expert editor: a plain textarea with line numbers. The parent gets
// the parsed value only while the text is valid JSON; errors name line and
// column. No eval, no third party editor (CSP).
import { useId, useMemo } from 'react'
import { useT } from '../i18n'

/** Parses JSON; on failure the line and column of the error (1 based). */
export function parseJSON(text: string): { ok: true; value: unknown } | { ok: false; line: number; col: number; msg: string } {
  try {
    return { ok: true, value: JSON.parse(text) }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    const lc = /line (\d+) column (\d+)/i.exec(msg)
    if (lc) return { ok: false, line: Number(lc[1]), col: Number(lc[2]), msg }
    const pos = /position (\d+)/i.exec(msg)
    const at = pos ? Number(pos[1]) : text.length
    const before = text.slice(0, at).split('\n')
    return { ok: false, line: before.length, col: before[before.length - 1].length + 1, msg: msg.replace(/\s*(in JSON )?at position \d+.*$/i, '') }
  }
}

export function JsonEditor({ value, onChange, label, rows = 18, readOnly }: { value: string; onChange: (text: string, parsed?: unknown) => void; label?: string; rows?: number; readOnly?: boolean }) {
  const t = useT()
  const id = useId()
  const res = useMemo(() => parseJSON(value), [value])
  const lines = value.split('\n').length
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-[13px] font-medium">
        {label ?? t('json.label')}
      </label>
      <div className="flex overflow-hidden rounded-md border border-field bg-surface focus-within:outline-2 focus-within:outline-accent" aria-hidden={false}>
        <pre aria-hidden className="num m-0 min-w-10 bg-surface-2 px-2 py-2 text-right font-mono text-[12.5px] leading-5 text-muted select-none">
          {Array.from({ length: Math.max(lines, rows) }, (_, i) => i + 1).join('\n')}
        </pre>
        <textarea
          id={id}
          value={value}
          readOnly={readOnly}
          rows={Math.max(rows, lines)}
          spellCheck={false}
          wrap="off"
          aria-invalid={!res.ok || undefined}
          aria-describedby={`${id}-state`}
          onChange={(e) => {
            const r = parseJSON(e.target.value)
            onChange(e.target.value, r.ok ? r.value : undefined)
          }}
          onKeyDown={(e) => {
            if (e.key !== 'Tab' || readOnly) return
            e.preventDefault()
            const el = e.currentTarget
            const s = el.selectionStart
            const next = `${value.slice(0, s)}  ${value.slice(el.selectionEnd)}`
            onChange(next, undefined)
            requestAnimationFrame(() => el.setSelectionRange(s + 2, s + 2))
          }}
          className="min-w-0 flex-1 resize-y bg-transparent px-2 py-2 font-mono text-[12.5px] leading-5 outline-none"
        />
      </div>
      <p id={`${id}-state`} role="status" className={res.ok ? 'text-[12.5px] text-muted' : 'text-[12.5px] font-medium text-bad'}>
        {res.ok ? t('json.valid') : t('json.invalid', { line: res.line, col: res.col, msg: res.msg })}
      </p>
    </div>
  )
}
