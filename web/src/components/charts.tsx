// Charts. Small ones are SVG (sparkline, fleet grid, bullet, 100 % bar);
// ECharts loads lazily for lines, bars and heatmaps. Every chart has a text
// summary (role img, aria-label) and, for ECharts, a table alternative.
// Status is never shown by color alone: hatching, dots, dashed outlines.
import type { EChartsCoreOption } from 'echarts/core'
import { BarChart3, Table2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useT, type MessageKey } from '../i18n'
import { fmt } from '../i18n/format'
import { cx } from '../lib/cx'
import { usePrefs } from '../lib/prefs'
import { Skeleton, statusTone, type DeviceStatus, type Tone } from './ui'

export type Colors = Record<'fg' | 'fg2' | 'muted' | 'line' | 'grid' | 'surface' | 'accent' | 'ok' | 'warn' | 'bad' | 'info' | 'off' | 's1' | 's2' | 's3' | 's4' | 's5', string>

const cssVar = (n: string) => getComputedStyle(document.documentElement).getPropertyValue(n).trim()
function readColors(): Colors {
  const v = (n: string) => cssVar(`--c-${n}`)
  return {
    fg: v('fg'), fg2: v('fg-2'), muted: v('muted'), line: v('line-strong'), grid: v('grid'), surface: v('surface'), accent: v('accent'),
    ok: v('ok'), warn: v('warn-mark'), bad: v('bad'), info: v('info'), off: v('off'), s1: v('s1'), s2: v('s2'), s3: v('s3'), s4: v('s4'), s5: v('s5'),
  }
}

/** Shared base so every chart looks like one system; aria on (ECharts writes its own description). */
export function baseOption(c: Colors): EChartsCoreOption {
  const reduce = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
  return {
    animation: !reduce,
    animationDuration: 300,
    textStyle: { fontFamily: 'Inter Variable, system-ui, sans-serif', color: c.muted, fontSize: 11 },
    grid: { left: 8, right: 12, top: 12, bottom: 4, containLabel: true },
    tooltip: { trigger: 'axis', backgroundColor: c.surface, borderColor: c.line, textStyle: { color: c.fg, fontSize: 12 }, axisPointer: { lineStyle: { color: c.line } } },
    aria: { enabled: true, decal: { show: false } },
  }
}
export const axisX = (c: Colors, extra: object = {}) => ({ axisLine: { lineStyle: { color: c.line } }, axisTick: { show: false }, axisLabel: { color: c.muted, hideOverlap: true }, splitLine: { show: false }, ...extra })
export const axisY = (c: Colors, extra: object = {}) => ({ axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: c.muted }, splitLine: { lineStyle: { color: c.grid } }, ...extra })

type EC = typeof import('./echarts').default
let ecPromise: Promise<EC> | null = null
const loadEc = () => (ecPromise ??= import('./echarts').then((m) => m.default))

/** An ECharts chart; build gets the current theme colors and runs again on theme or density changes. */
export function EChart({ build, height = 220, label }: { build: (c: Colors) => EChartsCoreOption; height?: number; label: string }) {
  const el = useRef<HTMLDivElement>(null)
  const inst = useRef<ReturnType<EC['init']> | null>(null)
  const { theme, density } = usePrefs()
  const [ready, setReady] = useState(false)
  useEffect(() => {
    let alive = true
    let ro: ResizeObserver | undefined
    void loadEc().then((ec) => {
      if (!alive || !el.current) return
      inst.current = ec.init(el.current, undefined, { renderer: 'canvas' })
      ro = new ResizeObserver(() => inst.current?.resize())
      ro.observe(el.current)
      setReady(true)
    })
    return () => {
      alive = false
      ro?.disconnect()
      inst.current?.dispose()
      inst.current = null
    }
  }, [])
  useEffect(() => {
    if (ready) inst.current?.setOption(build(readColors()), true)
  }, [ready, build, theme, density])
  return (
    <div className="relative" style={{ height }}>
      {!ready && <Skeleton className="absolute inset-0" />}
      <div ref={el} role="img" aria-label={label} className="absolute inset-0" />
    </div>
  )
}

/** A chart with its table twin: same data, exact values, readable by screen readers. */
export function ChartFrame({ chart, table, caption }: { chart: ReactNode; table: { head: string[]; rows: (string | number)[][] }; caption: string }) {
  const t = useT()
  const [asTable, setAsTable] = useState(false)
  return (
    <div>
      <div className="mb-1 ml-auto flex w-fit gap-0.5 rounded-md border border-line p-0.5">
        <button type="button" aria-pressed={!asTable} onClick={() => setAsTable(false)} className={cx('rounded p-1', !asTable ? 'bg-surface-2 text-fg' : 'text-muted')} aria-label={t('common.asChart')}>
          <BarChart3 size={14} />
        </button>
        <button type="button" aria-pressed={asTable} onClick={() => setAsTable(true)} className={cx('rounded p-1', asTable ? 'bg-surface-2 text-fg' : 'text-muted')} aria-label={t('common.asTable')}>
          <Table2 size={14} />
        </button>
      </div>
      {asTable ? (
        <div className="max-h-[260px] overflow-auto">
          <table className="num w-full text-meta">
            <caption className="sr-only">{caption}</caption>
            <thead className="sticky top-0 bg-surface text-left text-muted">
              <tr>
                {table.head.map((h) => (
                  <th key={h} scope="col" className="py-1 pr-3 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r, i) => (
                <tr key={i} className="border-t border-line">
                  {r.map((v, j) => (
                    <td key={j} className="py-1 pr-3">
                      {v}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        chart
      )}
    </div>
  )
}

type SparkTone = 'accent' | 'ok' | 'bad' | 'warn' | 'muted'
const sparkColor: Record<SparkTone, string> = { accent: 'var(--c-accent)', ok: 'var(--c-ok)', bad: 'var(--c-bad)', warn: 'var(--c-warn-mark)', muted: 'var(--c-muted)' }

export function Sparkline({ data, tone = 'accent', height = 32, width = 120, label }: { data: number[]; tone?: SparkTone; height?: number; width?: number; label?: string }) {
  const path = useMemo(() => {
    if (data.length < 2) return null
    const min = Math.min(...data)
    const span = Math.max(...data) - min || 1
    const pts = data.map((v, i) => [(i / (data.length - 1)) * width, height - 3 - ((v - min) / span) * (height - 6)] as const)
    const d = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join('')
    return { d, area: `${d}L${width},${height}L0,${height}Z`, last: pts[pts.length - 1] }
  }, [data, height, width])
  if (!path) return null
  const color = sparkColor[tone]
  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true} className="block overflow-visible">
      <path d={path.area} fill={color} opacity={0.1} />
      <path d={path.d} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      <circle cx={path.last[0]} cy={path.last[1]} r={2.5} fill={color} />
    </svg>
  )
}

/** Patterns for status cells, rendered once by the shell. */
export function SvgDefs() {
  return (
    <svg width="0" height="0" className="absolute" aria-hidden>
      <defs>
        <pattern id="p-bad" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="4" height="4" fill="var(--c-bad)" />
          <rect width="1.3" height="4" fill="var(--c-surface)" opacity="0.55" />
        </pattern>
        <pattern id="p-warn" width="4" height="4" patternUnits="userSpaceOnUse">
          <rect width="4" height="4" fill="var(--c-warn-mark)" />
          <circle cx="2" cy="2" r="0.8" fill="var(--c-surface)" opacity="0.7" />
        </pattern>
      </defs>
    </svg>
  )
}

function paint(tone: Tone) {
  switch (tone) {
    case 'ok':
      return { fill: 'var(--c-ok)', opacity: 0.85 }
    case 'warn':
      return { fill: 'url(#p-warn)' }
    case 'bad':
      return { fill: 'url(#p-bad)' }
    case 'off':
      return { fill: 'var(--c-surface)', stroke: 'var(--c-off)', strokeWidth: 1.2, strokeDasharray: '2 1.5' }
  }
}

export function StatusSwatch({ status, size = 12 }: { status: DeviceStatus; size?: number }) {
  return (
    <svg width={size} height={size} aria-hidden className="shrink-0">
      <rect x={0.5} y={0.5} width={size - 1} height={size - 1} rx={2} {...paint(statusTone[status] ?? 'off')} />
    </svg>
  )
}

export type FleetCell = { id: string; hostname: string; status: string }
const order: DeviceStatus[] = ['non-compliant', 'in grace', 'pending', 'stale', 'compliant']

/** One cell per device, worst first; a cell opens the device. Above a few thousand devices use tiles per blueprint. */
export function FleetGrid({ cells, onPick, cell = 12 }: { cells: FleetCell[]; onPick?: (c: FleetCell) => void; cell?: number }) {
  const t = useT()
  const wrap = useRef<HTMLDivElement>(null)
  const [w, setW] = useState(320)
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setW(e.contentRect.width))
    if (wrap.current) ro.observe(wrap.current)
    return () => ro.disconnect()
  }, [])
  const gap = 3
  const cols = Math.max(8, Math.floor((w + gap) / (cell + gap)))
  const counts = order.map((s) => [s, cells.filter((c) => c.status === s).length] as const).filter(([, n]) => n > 0)
  const label = (s: DeviceStatus) => t(`status.${s}` as MessageKey)
  const summary = counts.map(([s, n]) => `${fmt(n)} ${label(s)}`).join(', ')
  return (
    <div>
      <div ref={wrap}>
        <svg width="100%" height={Math.ceil(cells.length / cols) * (cell + gap)} role="img" aria-label={t('chart.fleet', { summary })}>
          {cells.map((c, i) => (
            <rect
              key={c.id}
              x={(i % cols) * (cell + gap) + 0.5}
              y={Math.floor(i / cols) * (cell + gap) + 0.5}
              width={cell - 1}
              height={cell - 1}
              rx={2.5}
              {...paint(statusTone[c.status as DeviceStatus] ?? 'off')}
              className={onPick ? 'cursor-pointer hover:opacity-60' : undefined}
              onClick={() => onPick?.(c)}
            >
              <title>{`${c.hostname}: ${label(c.status as DeviceStatus)}`}</title>
            </rect>
          ))}
        </svg>
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-meta">
        {counts.map(([s, n]) => (
          <li key={s} className="flex items-center gap-1.5">
            <StatusSwatch status={s} />
            <span className="text-fg-2">{label(s)}</span>
            <span className="num font-semibold">{fmt(n)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** 100 % bar for an ordered distribution with few parts; labels sit in the legend. */
export function StackBar({ parts, label }: { parts: { label: string; value: number; color: string; note?: string }[]; label: string }) {
  const total = parts.reduce((s, p) => s + p.value, 0) || 1
  return (
    <div>
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-full bg-surface-2" role="img" aria-label={`${label}: ${parts.map((p) => `${p.label} ${p.value}`).join(', ')}`}>
        {parts.map((p) => p.value > 0 && <div key={p.label} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} />)}
      </div>
      <ul className="mt-3 flex flex-col gap-1 text-meta">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-2">
            <span className="size-2.5 shrink-0 rounded-sm" style={{ background: p.color }} aria-hidden />
            <span className="truncate text-fg-2">{p.label}</span>
            <span className="num ml-auto font-semibold">{fmt(p.value)}</span>
            {p.note && <span className="text-micro text-muted">{p.note}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Value against a target line. */
export function Bullet({ value, target, label }: { value: number; target: number; label: string }) {
  const tone = value >= target ? 'bg-ok' : value >= target - 7 ? 'bg-warn-mark' : 'bg-bad'
  return (
    <div className="relative h-2 rounded-full bg-surface-2" role="img" aria-label={label}>
      <div className={cx('h-2 rounded-full', tone)} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      <div className="absolute -top-1 h-4 w-0.5 rounded bg-fg" style={{ left: `${target}%` }} aria-hidden />
    </div>
  )
}
