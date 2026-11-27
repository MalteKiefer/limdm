// Timeline: events grouped by day under sticky headings, newest first.
import type { ReactNode } from 'react'
import { dateLong, dateTime } from '../i18n/format'

export type TimelineItem = { id: string | number; at: string | number | Date; title: ReactNode; meta?: ReactNode; icon?: ReactNode }

const dayKey = (v: TimelineItem['at']) => {
  const d = new Date(v)
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}

export function Timeline({ items, label }: { items: TimelineItem[]; label: string }) {
  const groups: { key: string; at: TimelineItem['at']; items: TimelineItem[] }[] = []
  for (const it of [...items].sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())) {
    const k = dayKey(it.at)
    if (groups[groups.length - 1]?.key !== k) groups.push({ key: k, at: it.at, items: [] })
    groups[groups.length - 1].items.push(it)
  }
  return (
    <div aria-label={label} role="feed">
      {groups.map((g) => (
        <section key={g.key} aria-label={dateLong(g.at)}>
          <h3 className="sticky top-14 z-10 bg-bg/95 py-1.5 text-meta font-semibold text-muted backdrop-blur">{dateLong(g.at)}</h3>
          <ol className="relative ml-2 border-l border-line">
            {g.items.map((it) => (
              <li key={it.id} className="relative py-2 pl-5" aria-label={typeof it.title === 'string' ? it.title : undefined}>
                <span className="absolute top-3 -left-[5px] grid size-[9px] place-items-center rounded-full bg-surface ring-2 ring-line-strong" aria-hidden>
                  {it.icon}
                </span>
                <div className="text-body">{it.title}</div>
                <div className="text-meta text-muted">
                  <time dateTime={new Date(it.at).toISOString()}>{dateTime(it.at)}</time>
                  {it.meta && <> · {it.meta}</>}
                </div>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  )
}
