// Query bar: the list query language as text with key suggestions, the
// parsed terms as removable chips, and facets with counts that add terms.
// Text and facets write the same string, which the page keeps in the URL.
import { Search, X } from 'lucide-react'
import { useId, useState } from 'react'
import { useT } from '../i18n'
import { fmt } from '../i18n/format'
import { addToken, formatToken, hasToken, removeToken, tokenize, trailing } from '../lib/query'
import { cx } from '../lib/cx'

export type QueryKey = { key: string; help: string }

export function QueryBar({ value, onChange, keys, placeholder, label }: { value: string; onChange: (q: string) => void; keys: QueryKey[]; placeholder?: string; label?: string }) {
  const t = useT()
  const [draft, setDraft] = useState(value)
  const [seen, setSeen] = useState(value)
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const listId = useId()
  if (value !== seen) {
    // the query changed from outside (facet, view, back button): show it
    setSeen(value)
    setDraft(value)
  }
  const word = trailing(draft)
  // suggest keys while a word without ":" is typed at the end
  const typing = word && !draft.endsWith(' ') && !draft.endsWith(':') && !/:\S*$/.test(draft) ? word.key : null
  const suggestions = typing != null && typing !== '' ? keys.filter((k) => k.key.startsWith(typing) && k.key !== typing) : []
  const showList = open && suggestions.length > 0
  const pick = (k: QueryKey) => {
    setDraft(draft.slice(0, draft.length - (typing?.length ?? 0)) + k.key + ':')
    setActive(0)
  }
  const tokens = tokenize(value)
  return (
    <div className="flex flex-col gap-2">
      <form
        role="search"
        className="relative"
        onSubmit={(e) => {
          e.preventDefault()
          onChange(draft.trim())
          setOpen(false)
        }}
      >
        <Search size={16} aria-hidden className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted" />
        <input
          className="field !h-9 pl-9 font-mono text-body"
          aria-label={label ?? t('query.label')}
          role="combobox"
          aria-expanded={showList}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={showList ? `${listId}-${active}` : undefined}
          placeholder={placeholder ?? t('query.placeholder')}
          value={draft}
          spellCheck={false}
          autoComplete="off"
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onChange={(e) => {
            setDraft(e.target.value)
            setOpen(true)
            setActive(0)
          }}
          onKeyDown={(e) => {
            if (!showList) return
            if (e.key === 'ArrowDown') setActive((a) => (a + 1) % suggestions.length)
            else if (e.key === 'ArrowUp') setActive((a) => (a - 1 + suggestions.length) % suggestions.length)
            else if (e.key === 'Tab' || (e.key === 'Enter' && suggestions[active])) pick(suggestions[active])
            else if (e.key === 'Escape') setOpen(false)
            else return
            e.preventDefault()
          }}
        />
        {showList && (
          <ul id={listId} role="listbox" aria-label={t('query.suggestions')} className="absolute top-full right-0 left-0 z-30 mt-1 overflow-hidden rounded-lg border border-line bg-surface p-1 shadow-pop">
            {suggestions.map((k, i) => (
              <li
                key={k.key}
                id={`${listId}-${i}`}
                role="option"
                aria-selected={i === active}
                onMouseDown={(e) => {
                  e.preventDefault()
                  pick(k)
                }}
                className={cx('flex cursor-default items-baseline gap-3 rounded-md px-2 py-1.5', i === active && 'bg-surface-2')}
              >
                <span className="font-mono text-body">{k.key}:</span>
                <span className="truncate text-meta text-muted">{k.help}</span>
              </li>
            ))}
          </ul>
        )}
      </form>
      {tokens.length > 0 && (
        <ul className="flex flex-wrap items-center gap-1.5">
          {tokens.map((tok) => {
            const text = formatToken(tok)
            return (
              <li key={text}>
                <span className="inline-flex items-center gap-1 rounded-md border border-line bg-surface py-0.5 pr-0.5 pl-2 font-mono text-meta">
                  {text}
                  <button type="button" className="grid size-5 place-items-center rounded hover:bg-surface-2" aria-label={t('query.remove', { token: text })} onClick={() => onChange(removeToken(value, tok))}>
                    <X size={12} />
                  </button>
                </span>
              </li>
            )
          })}
          <li>
            <button type="button" className="btn btn-ghost !h-7 text-meta text-accent" onClick={() => onChange('')}>
              {t('query.clear')}
            </button>
          </li>
        </ul>
      )}
    </div>
  )
}

export type Facet = { key: string; title: string; values: { value: string; count: number; label?: string }[] }

/** Facet lists with counts; a click toggles key:value in the query. */
export function Facets({ facets, value, onChange }: { facets: Facet[]; value: string; onChange: (q: string) => void }) {
  const t = useT()
  return (
    <nav aria-label={t('query.facets')} className="flex flex-col gap-4">
      {facets.map((f) => (
        <section key={f.key}>
          <h3 className="mb-1 text-micro font-semibold tracking-wide text-muted uppercase">{f.title}</h3>
          <ul className="flex flex-col">
            {f.values.map((v) => {
              const tok = { key: f.key, value: v.value }
              const on = hasToken(value, tok)
              return (
                <li key={v.value}>
                  <button
                    type="button"
                    aria-pressed={on}
                    onClick={() => onChange(on ? removeToken(value, tok) : addToken(value, tok))}
                    className={cx('flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-body hover:bg-surface-2', on && 'bg-accent-soft text-on-accent-soft')}
                  >
                    <span className="min-w-0 flex-1 truncate">{v.label ?? (v.value || '–')}</span>
                    <span className="num text-meta text-muted">{fmt(v.count)}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </nav>
  )
}
