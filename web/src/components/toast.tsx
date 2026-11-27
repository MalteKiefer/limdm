// Toasts: short confirmations and errors, announced politely (errors
// assertively), gone after a few seconds or on click.
import { CheckCircle2, CircleAlert, X } from 'lucide-react'
import { useSyncExternalStore } from 'react'
import { useT } from '../i18n'
import { cx } from '../lib/cx'

type ToastItem = { id: number; text: string; tone: 'ok' | 'error' }
let list: ToastItem[] = []
let seq = 0
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

function dismiss(id: number) {
  list = list.filter((x) => x.id !== id)
  emit()
}

/** Shows a confirmation (or, with tone error, a failure) for a few seconds. */
export function toast(text: string, tone: ToastItem['tone'] = 'ok') {
  const id = ++seq
  list = [...list.slice(-3), { id, text, tone }]
  emit()
  setTimeout(() => dismiss(id), tone === 'error' ? 8000 : 4000)
}

export function Toaster() {
  const t = useT()
  const items = useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => {
        listeners.delete(l)
      }
    },
    () => list,
  )
  return (
    <section aria-label={t('toast.region')} className="pointer-events-none fixed right-4 bottom-[calc(1rem+var(--bulk-h,0px))] z-[60] flex flex-col gap-2">
      <div role="status" aria-live="polite" className="flex flex-col gap-2">
        {items.filter((x) => x.tone === 'ok').map((x) => (
          <Item key={x.id} item={x} />
        ))}
      </div>
      <div role="alert" aria-live="assertive" className="flex flex-col gap-2">
        {items.filter((x) => x.tone === 'error').map((x) => (
          <Item key={x.id} item={x} />
        ))}
      </div>
    </section>
  )
}

function Item({ item }: { item: ToastItem }) {
  const t = useT()
  const I = item.tone === 'ok' ? CheckCircle2 : CircleAlert
  return (
    <div className={cx('fade-in pointer-events-auto flex max-w-sm items-center gap-2 rounded-lg px-3 py-2 text-body shadow-pop', item.tone === 'ok' ? 'bg-fg text-bg' : 'bg-bad text-surface')}>
      <I size={15} aria-hidden className="shrink-0" />
      <span className="flex-1">{item.text}</span>
      <button type="button" className="rounded p-0.5 opacity-80 hover:opacity-100" aria-label={t('toast.dismiss')} onClick={() => dismiss(item.id)}>
        <X size={13} />
      </button>
    </div>
  )
}
