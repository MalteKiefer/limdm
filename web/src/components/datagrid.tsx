// Data grid: TanStack Table for columns, selection and visibility, TanStack
// Virtual for rows (10 000 rows stay smooth). Sorting is the server's
// (sort string as in the API: "hostname", "-last_seen"); the grid shows it
// with aria-sort and asks for a new one. Below 768 px rows become cards when
// the page gives a card renderer.
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type RowSelectionState,
  type VisibilityState,
} from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp, ChevronsUpDown, Columns3, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { useT } from '../i18n'
import { cx } from '../lib/cx'
import { ActionMenu } from './ui'

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData, TValue> {
    /** Sort field of the API; columns without one are not sortable. */
    sortKey?: string
    className?: string
    /** Shown in the column chooser; defaults to the header text. */
    label?: string
  }
}

export type { RowSelectionState, VisibilityState }
// the value type of a column is free (accessor columns of any field)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type GridColumn<T> = ColumnDef<T, any>

function useMedia(query: string) {
  return useSyncExternalStore(
    (l) => {
      const m = matchMedia(query)
      m.addEventListener('change', l)
      return () => m.removeEventListener('change', l)
    },
    () => matchMedia(query).matches,
  )
}

export type DataGridProps<T> = {
  data: T[]
  columns: GridColumn<T>[]
  getRowId: (row: T) => string
  label: string
  sort?: string
  onSortChange?: (sort: string) => void
  selection?: RowSelectionState
  onSelectionChange?: (s: RowSelectionState) => void
  columnVisibility?: VisibilityState
  activeId?: string
  onRowClick?: (row: T) => void
  onEndReached?: () => void
  loadingMore?: boolean
  maxHeight?: string
  empty?: ReactNode
  card?: (row: T) => ReactNode
}

export function DataGrid<T>({ data, columns, getRowId, label, sort, onSortChange, selection, onSelectionChange, columnVisibility, activeId, onRowClick, onEndReached, loadingMore, maxHeight = 'calc(100dvh - 260px)', empty, card }: DataGridProps<T>) {
  const t = useT()
  const narrow = useMedia('(max-width: 767px)')
  const scroller = useRef<HTMLDivElement>(null)
  const cols = useMemo<GridColumn<T>[]>(() => {
    if (!onSelectionChange) return columns
    const select: GridColumn<T> = {
      id: '_select',
      header: ({ table }) => (
        <input
          type="checkbox"
          aria-label={t('grid.selectAll')}
          checked={table.getIsAllRowsSelected()}
          ref={(el) => {
            if (el) el.indeterminate = table.getIsSomeRowsSelected()
          }}
          onChange={table.getToggleAllRowsSelectedHandler()}
        />
      ),
      cell: ({ row }) => <input type="checkbox" aria-label={t('grid.selectRow')} checked={row.getIsSelected()} onChange={row.getToggleSelectedHandler()} onClick={(e) => e.stopPropagation()} />,
      meta: { className: 'w-9' },
    }
    return [select, ...columns]
  }, [columns, onSelectionChange, t])
  // TanStack Table returns functions that change identity; the React compiler lint knows
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data,
    columns: cols,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    manualSorting: true,
    enableRowSelection: !!onSelectionChange,
    state: { rowSelection: selection ?? {}, columnVisibility: columnVisibility ?? {} },
    onRowSelectionChange: (u) => onSelectionChange?.(typeof u === 'function' ? u(selection ?? {}) : u),
  })
  const rows = table.getRowModel().rows
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => (narrow && card ? 76 : 40), overscan: 12 })
  const items = v.getVirtualItems()
  const last = items[items.length - 1]
  useEffect(() => {
    if (onEndReached && last && last.index >= rows.length - 5 && !loadingMore) onEndReached()
  }, [last, rows.length, onEndReached, loadingMore])

  if (!rows.length) return <div className="card">{empty ?? <p className="p-6 text-center text-muted">{t('grid.empty')}</p>}</div>

  const sortName = sort?.replace(/^-/, '')
  const desc = sort?.startsWith('-')

  if (narrow && card) {
    return (
      <div ref={scroller} className="overflow-y-auto" style={{ maxHeight }} role="list" aria-label={label}>
        <div className="relative" style={{ height: v.getTotalSize() }}>
          {items.map((it) => {
            const row = rows[it.index]
            return (
              <div key={row.id} role="listitem" data-index={it.index} ref={v.measureElement} className="absolute right-0 left-0 pb-2" style={{ transform: `translateY(${it.start}px)` }}>
                <button type="button" onClick={() => onRowClick?.(row.original)} className={cx('card block w-full p-3 text-left', row.id === activeId && 'ring-2 ring-accent')}>
                  {card(row.original)}
                </button>
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  const pad = { top: items[0]?.start ?? 0, bottom: v.getTotalSize() - (last?.end ?? 0) }
  return (
    <div ref={scroller} className="card overflow-auto" style={{ maxHeight }}>
      <table className="w-full text-left text-[13px]" aria-label={label} aria-rowcount={rows.length + 1}>
        <thead className="sticky top-0 z-10 bg-surface text-[12px] text-muted shadow-[0_1px_0_var(--c-line)]">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => {
                const key = h.column.columnDef.meta?.sortKey
                const on = key && key === sortName
                return (
                  <th key={h.id} scope="col" aria-sort={on ? (desc ? 'descending' : 'ascending') : key ? 'none' : undefined} className={cx('px-3 py-2 font-medium whitespace-nowrap', h.column.columnDef.meta?.className)}>
                    {key && onSortChange ? (
                      <button type="button" className="inline-flex items-center gap-1 hover:text-fg" onClick={() => onSortChange(on && !desc ? `-${key}` : key)}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {on ? desc ? <ArrowDown size={13} aria-hidden /> : <ArrowUp size={13} aria-hidden /> : <ChevronsUpDown size={13} aria-hidden className="opacity-40" />}
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </th>
                )
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {pad.top > 0 && (
            <tr aria-hidden>
              <td style={{ height: pad.top }} />
            </tr>
          )}
          {items.map((it) => {
            const row = rows[it.index]
            return (
              <tr
                key={row.id}
                data-index={it.index}
                aria-rowindex={it.index + 2}
                aria-selected={row.getIsSelected() || undefined}
                aria-current={row.id === activeId || undefined}
                tabIndex={onRowClick ? 0 : undefined}
                onClick={() => onRowClick?.(row.original)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && e.target === e.currentTarget) onRowClick?.(row.original)
                }}
                className={cx('row-h border-t border-line', onRowClick && 'cursor-pointer hover:bg-surface-2', row.id === activeId && 'bg-accent-soft/60')}
              >
                {row.getVisibleCells().map((c) => (
                  <td key={c.id} className={cx('px-3 py-1', c.column.columnDef.meta?.className)}>
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </td>
                ))}
              </tr>
            )
          })}
          {pad.bottom > 0 && (
            <tr aria-hidden>
              <td style={{ height: pad.bottom }} />
            </tr>
          )}
        </tbody>
      </table>
      {loadingMore && (
        <p role="status" className="p-2 text-center text-[12.5px] text-muted">
          {t('grid.loadingMore')}
        </p>
      )}
    </div>
  )
}

/** Column chooser: shows and hides columns; the page keeps the state (and saves it in a view). */
export function ColumnChooser({ columns, value, onChange }: { columns: { id: string; label: string }[]; value: VisibilityState; onChange: (v: VisibilityState) => void }) {
  const t = useT()
  return (
    <ActionMenu
      trigger={
        <button type="button" className="btn">
          <Columns3 size={15} aria-hidden /> {t('grid.columns')}
        </button>
      }
      items={columns.map((c) => ({ label: c.label, checked: value[c.id] !== false, onClick: () => onChange({ ...value, [c.id]: value[c.id] === false }) }))}
    />
  )
}

/** Appears while rows are selected; holds the actions for all of them. */
export function BulkActionBar({ count, onClear, children }: { count: number; onClear: () => void; children: ReactNode }) {
  const t = useT()
  if (count === 0) return null
  return (
    <div role="region" aria-label={t('bulk.selected', { count })} className="fade-in sticky bottom-4 z-20 mx-auto mt-3 flex w-fit max-w-full flex-wrap items-center gap-2 rounded-xl bg-fg px-3 py-2 text-bg shadow-pop">
      <span className="num px-1 text-[13px] font-medium">{t('bulk.selected', { count })}</span>
      <div className="flex flex-wrap gap-1.5 [&_.btn]:border-transparent [&_.btn]:bg-bg/10 [&_.btn]:text-bg [&_.btn:hover]:bg-bg/20">{children}</div>
      <button type="button" className="rounded p-1 hover:bg-bg/20" aria-label={t('bulk.clear')} onClick={onClear}>
        <X size={15} />
      </button>
    </div>
  )
}

/** Remembers a column visibility per list in the browser until a view saves it. */
export function useColumnVisibility(list: string, initial: VisibilityState = {}) {
  const key = `limdm.columns.${list}`
  const [v, setV] = useState<VisibilityState>(() => {
    try {
      return { ...initial, ...(JSON.parse(localStorage.getItem(key) ?? '{}') as VisibilityState) }
    } catch {
      return initial
    }
  })
  const set = (next: VisibilityState) => {
    setV(next)
    try {
      localStorage.setItem(key, JSON.stringify(next))
    } catch {
      // private mode
    }
  }
  return [v, set] as const
}
