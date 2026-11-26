// Layout patterns: tabs bound to the URL, the side sheet next to a list,
// the split view that holds both, and the wizard.
import { ChevronDown, ChevronUp, X } from 'lucide-react'
import { useEffect, useId, useRef, type ReactNode } from 'react'
import { useT } from '../i18n'
import { cx } from '../lib/cx'

/** Tabs; the caller binds value to a search parameter so every tab has a URL. */
export function TabBar<T extends string>({ tabs, value, onChange, label, idBase }: { tabs: { value: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void; label: string; idBase?: string }) {
  const gen = useId()
  const base = idBase ?? gen
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const move = (i: number) => {
    const n = (i + tabs.length) % tabs.length
    onChange(tabs[n].value)
    refs.current[n]?.focus()
  }
  return (
    <div role="tablist" aria-label={label} className="mb-[var(--gap)] flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((tab, i) => (
        <button
          key={tab.value}
          ref={(el) => {
            refs.current[i] = el
          }}
          type="button"
          role="tab"
          id={`${base}-tab-${tab.value}`}
          aria-controls={`${base}-panel`}
          aria-selected={value === tab.value}
          tabIndex={value === tab.value ? 0 : -1}
          onClick={() => onChange(tab.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowRight') move(i + 1)
            if (e.key === 'ArrowLeft') move(i - 1)
            if (e.key === 'Home') move(0)
            if (e.key === 'End') move(tabs.length - 1)
          }}
          className={cx('-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 font-medium whitespace-nowrap', value === tab.value ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg')}
        >
          {tab.label}
          {tab.count != null && <span className="num rounded-full bg-surface-2 px-1.5 text-[11px]">{tab.count}</span>}
        </button>
      ))}
    </div>
  )
}

/** The panel of a TabBar with the same idBase. */
export function TabPanel({ idBase, value, children }: { idBase: string; value: string; children: ReactNode }) {
  return (
    <div role="tabpanel" id={`${idBase}-panel`} aria-labelledby={`${idBase}-tab-${value}`}>
      {children}
    </div>
  )
}

/**
 * Detail sheet next to a list: Esc closes, J and K step through the list
 * (outside text fields). Not modal: the list stays usable.
 */
export function SideSheet({ title, sub, onClose, onPrev, onNext, actions, children }: { title: ReactNode; sub?: ReactNode; onClose: () => void; onPrev?: () => void; onNext?: () => void; actions?: ReactNode; children: ReactNode }) {
  const t = useT()
  const headingId = useId()
  const ref = useRef<HTMLElement>(null)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      if (/INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'Escape') onClose()
      else if (e.key === 'j' && onNext) onNext()
      else if (e.key === 'k' && onPrev) onPrev()
      else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onNext, onPrev])
  return (
    <aside ref={ref} aria-labelledby={headingId} className="sheet-in card flex max-h-[calc(100dvh-88px)] min-w-0 flex-col overflow-hidden lg:sticky lg:top-[72px]">
      <header className="flex items-start gap-2 border-b border-line px-[var(--pad-card)] py-3">
        <div className="min-w-0 flex-1">
          <h2 id={headingId} className="truncate text-[15px] font-semibold">
            {title}
          </h2>
          {sub && <div className="text-[12.5px] text-muted">{sub}</div>}
        </div>
        {onPrev && (
          <button type="button" className="btn btn-ghost px-1.5" onClick={onPrev} aria-label={t('sheet.prev')}>
            <ChevronUp size={16} />
          </button>
        )}
        {onNext && (
          <button type="button" className="btn btn-ghost px-1.5" onClick={onNext} aria-label={t('sheet.next')}>
            <ChevronDown size={16} />
          </button>
        )}
        <button type="button" className="btn btn-ghost px-1.5" onClick={onClose} aria-label={t('sheet.close')}>
          <X size={16} />
        </button>
      </header>
      {actions && <div className="flex flex-wrap gap-2 border-b border-line px-[var(--pad-card)] py-2">{actions}</div>}
      <div className="min-h-0 flex-1 overflow-y-auto p-[var(--pad-card)]">{children}</div>
    </aside>
  )
}

/**
 * List and detail side by side; with no detail the list takes the width.
 * Below the lg breakpoint the detail replaces the list (phone: one after the other).
 */
export function SplitView({ list, detail, detailWidth = 'minmax(360px,44%)' }: { list: ReactNode; detail?: ReactNode; detailWidth?: string }) {
  return (
    <div className={cx('grid min-w-0 gap-[var(--gap)]', detail ? 'split-on' : '')} style={detail ? ({ '--split-detail': detailWidth } as React.CSSProperties) : undefined}>
      <div className={cx('min-w-0', !!detail && 'max-lg:hidden')}>{list}</div>
      {detail}
    </div>
  )
}

export type WizardStep = { id: string; title: string; content: ReactNode; valid?: boolean }

/** Steps with a progress list; Next stays disabled while the current step is invalid. */
export function Wizard({ steps, step, onStep, onFinish, finishLabel, busy }: { steps: WizardStep[]; step: number; onStep: (n: number) => void; onFinish: () => void; finishLabel?: string; busy?: boolean }) {
  const t = useT()
  const cur = steps[step]
  const last = step === steps.length - 1
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <nav aria-label={t('wizard.steps')}>
        <ol className="flex flex-wrap gap-2">
          {steps.map((s, i) => (
            <li key={s.id} aria-current={i === step ? 'step' : undefined} className={cx('flex items-center gap-2 rounded-full px-3 py-1 text-[12.5px]', i === step ? 'bg-accent text-on-accent' : i < step ? 'bg-accent-soft text-on-accent-soft' : 'bg-surface-2 text-muted')}>
              <span className="num font-semibold">{i + 1}</span> {s.title}
            </li>
          ))}
        </ol>
      </nav>
      <section aria-label={t('wizard.step', { n: step + 1, total: steps.length })}>{cur.content}</section>
      <div className="flex justify-between gap-2">
        <button type="button" className="btn" disabled={step === 0} onClick={() => onStep(step - 1)}>
          {t('common.back')}
        </button>
        <button type="button" className="btn btn-primary" disabled={cur.valid === false || busy} onClick={() => (last ? onFinish() : onStep(step + 1))}>
          {last ? (finishLabel ?? t('common.done')) : t('common.next')}
        </button>
      </div>
    </div>
  )
}
