// Small building blocks shared by every page. Base UI parts are used only
// where they inject no <style> elements (CSP: style-src 'self').
import { Dialog } from '@base-ui/react/dialog'
import { Menu } from '@base-ui/react/menu'
import { Switch as BSwitch } from '@base-ui/react/switch'
import { Tooltip } from '@base-ui/react/tooltip'
import { ArrowDownRight, ArrowUpRight, CheckCircle2, CircleDashed, Clock, Minus, OctagonX, TriangleAlert, X, type LucideIcon } from 'lucide-react'
import type { ReactElement, ReactNode } from 'react'
import { useT, type MessageKey } from '../i18n'
import { fmt1 } from '../i18n/format'
import { cx } from '../lib/cx'

/** Device statuses of the API and how they look: color plus icon, never color alone. */
export type DeviceStatus = 'compliant' | 'in grace' | 'non-compliant' | 'stale' | 'pending' | 'retired'
export type Tone = 'ok' | 'warn' | 'bad' | 'off'
export const statusTone: Record<DeviceStatus, Tone> = {
  compliant: 'ok',
  'in grace': 'warn',
  'non-compliant': 'bad',
  stale: 'off',
  pending: 'warn',
  retired: 'off',
}
const toneClass: Record<Tone, string> = { ok: 'text-ok bg-ok-soft', warn: 'text-warn bg-warn-soft', bad: 'text-bad bg-bad-soft', off: 'text-off bg-off-soft' }
const statusIcon: Record<DeviceStatus, LucideIcon> = {
  compliant: CheckCircle2,
  'in grace': Clock,
  'non-compliant': OctagonX,
  stale: CircleDashed,
  pending: TriangleAlert,
  retired: CircleDashed,
}

export function StatusPill({ status, compact }: { status: DeviceStatus; compact?: boolean }) {
  const t = useT()
  const I = statusIcon[status] ?? CircleDashed
  const label = t(`status.${status}` as MessageKey)
  return (
    <span className={cx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[12px] font-medium whitespace-nowrap', toneClass[statusTone[status] ?? 'off'])}>
      <I size={13} aria-hidden />
      {compact ? <span className="sr-only">{label}</span> : label}
    </span>
  )
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' | 'info' | Tone }) {
  const c = {
    neutral: 'bg-surface-2 text-fg-2',
    accent: 'bg-accent-soft text-on-accent-soft',
    info: 'bg-info-soft text-info',
    ...toneClass,
  }[tone]
  return <span className={cx('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[12px] font-medium whitespace-nowrap', c)}>{children}</span>
}

export function Card({ title, sub, action, children, className, bodyClass, id }: { title?: ReactNode; sub?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string }) {
  return (
    <section className={cx('card flex min-w-0 flex-col', className)} aria-labelledby={title && id ? id : undefined}>
      {title && (
        <header className="flex items-start justify-between gap-3 px-[var(--pad-card)] pt-[var(--pad-card)]">
          <div className="min-w-0">
            <h2 id={id} className="text-[14px] font-semibold">
              {title}
            </h2>
            {sub && <p className="mt-0.5 text-[12.5px] text-muted">{sub}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={cx('pad min-w-0 flex-1', bodyClass)}>{children}</div>
    </section>
  )
}

export function PageHeader({ title, sub, actions, children }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return (
    <header className="mb-[var(--gap)] flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-[22px] leading-tight font-semibold tracking-[-0.01em]">{title}</h1>
        {sub && <p className="mt-1 text-muted">{sub}</p>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  )
}

/** A change with arrow and words; goodUp decides the color, the arrow always shows the real direction. */
export function Delta({ value, unit, goodUp = true, label }: { value: number; unit?: string; goodUp?: boolean; label?: string }) {
  const t = useT()
  const flat = Math.abs(value) < 0.05
  const good = flat ? null : value > 0 === goodUp
  const I = flat ? Minus : value > 0 ? ArrowUpRight : ArrowDownRight
  return (
    <span className={cx('num inline-flex items-center gap-0.5 text-[12px] font-medium', good === null ? 'text-muted' : good ? 'text-ok' : 'text-bad')}>
      <I size={14} aria-hidden />
      {flat ? t('common.unchanged') : `${value > 0 ? '+' : '−'}${fmt1(Math.abs(value))} ${unit ?? t('common.points')}`}
      {label && <span className="font-normal text-muted">&nbsp;{label}</span>}
    </span>
  )
}

export function Avatar({ name, size = 24 }: { name: string; size?: number }) {
  const ini = name
    .replace(/^local:/, '')
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .map((p) => p[0]?.toUpperCase())
    .slice(0, 2)
    .join('')
  return (
    <span aria-hidden className="inline-grid shrink-0 place-items-center rounded-full bg-surface-2 text-[10px] font-semibold text-fg-2 ring-1 ring-line" style={{ width: size, height: size }}>
      {ini || '?'}
    </span>
  )
}

export function Tip({ label, children }: { label: string; children: ReactElement }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger render={children} />
      <Tooltip.Portal>
        <Tooltip.Positioner sideOffset={6} className="z-[70]">
          <Tooltip.Popup className="rounded-md bg-fg px-2 py-1 text-[12px] text-bg shadow-pop">{label}</Tooltip.Popup>
        </Tooltip.Positioner>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

export type MenuEntry = { label: string; icon?: LucideIcon; onClick?: () => void; danger?: boolean; hint?: string; checked?: boolean } | 'sep' | { group: string }

export function ActionMenu({ trigger, items, align = 'end' }: { trigger: ReactElement; items: MenuEntry[]; align?: 'start' | 'end' }) {
  return (
    <Menu.Root modal={false}>
      <Menu.Trigger render={trigger} />
      <Menu.Portal>
        <Menu.Positioner sideOffset={6} align={align} className="z-50">
          <Menu.Popup className="max-h-[70vh] min-w-[220px] overflow-y-auto rounded-lg border border-line bg-surface p-1 shadow-pop outline-none">
            {items.map((it, i) =>
              it === 'sep' ? (
                <div key={i} role="separator" className="my-1 h-px bg-line" />
              ) : 'group' in it ? (
                <div key={i} className="px-2 pt-2 pb-1 text-[11px] font-semibold tracking-wide text-muted uppercase">
                  {it.group}
                </div>
              ) : (
                <Menu.Item
                  key={i}
                  onClick={it.onClick}
                  aria-current={it.checked || undefined}
                  className={cx('flex cursor-default items-center gap-2 rounded-md px-2 py-1.5 outline-none data-[highlighted]:bg-surface-2', it.danger && 'text-bad')}
                >
                  {it.icon && <it.icon size={15} aria-hidden />}
                  <span className="flex-1">{it.label}</span>
                  {it.checked && <CheckCircle2 size={14} className="text-accent" aria-hidden />}
                  {it.hint && <span className="text-[11px] text-muted">{it.hint}</span>}
                </Menu.Item>
              ),
            )}
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  )
}

export function Switch({ checked, onChange, label, id, disabled }: { checked: boolean; onChange: (v: boolean) => void; label?: string; id?: string; disabled?: boolean }) {
  return (
    <BSwitch.Root
      id={id}
      checked={checked}
      disabled={disabled}
      onCheckedChange={onChange}
      aria-label={label}
      className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-field bg-surface-2 transition-colors data-[checked]:border-accent data-[checked]:bg-accent data-[disabled]:opacity-50"
    >
      <BSwitch.Thumb className="block size-3.5 translate-x-0.5 rounded-full bg-field transition-transform data-[checked]:translate-x-[18px] data-[checked]:bg-on-accent" />
    </BSwitch.Root>
  )
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex w-fit self-start rounded-md border border-line-strong bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          onKeyDown={(e) => {
            const i = options.findIndex((x) => x.value === value)
            if (e.key === 'ArrowRight') onChange(options[(i + 1) % options.length].value)
            if (e.key === 'ArrowLeft') onChange(options[(i - 1 + options.length) % options.length].value)
          }}
          tabIndex={value === o.value ? 0 : -1}
          className={cx('rounded px-2.5 py-1 text-[12.5px] font-medium', value === o.value ? 'bg-surface text-fg shadow-sm ring-1 ring-line' : 'text-muted hover:text-fg')}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Modal({ open, onClose, title, description, children, footer, wide }: { open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; children?: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const t = useT()
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fade-in fixed inset-0 z-40 bg-[var(--c-overlay)]" />
        <Dialog.Popup className={cx('fade-in fixed top-[12vh] left-1/2 z-50 max-h-[80vh] w-[calc(100vw-32px)] -translate-x-1/2 overflow-y-auto rounded-xl border border-line bg-surface shadow-pop outline-none', wide ? 'max-w-2xl' : 'max-w-md')}>
          <div className="flex items-start justify-between gap-4 p-5 pb-0">
            <div>
              <Dialog.Title className="text-[16px] font-semibold">{title}</Dialog.Title>
              {description && <Dialog.Description className="mt-1 text-muted">{description}</Dialog.Description>}
            </div>
            <Dialog.Close className="btn btn-ghost -mt-1 -mr-2 px-2" aria-label={t('common.close')}>
              <X size={16} />
            </Dialog.Close>
          </div>
          {children && <div className="p-5">{children}</div>}
          {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('skeleton', className)} aria-hidden />
}
