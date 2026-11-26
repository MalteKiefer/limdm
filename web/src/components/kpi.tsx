// KPI card: one question, one number, the change and a sparkline; the
// whole card links to the list behind the number.
import { Link } from '@tanstack/react-router'
import { ArrowRight } from 'lucide-react'
import type { ReactNode } from 'react'
import { Sparkline } from './charts'

export function KpiCard({ to, search, label, value, unit, delta, spark, tone, sparkLabel }: { to: string; search?: Record<string, string>; label: string; value: ReactNode; unit?: ReactNode; delta?: ReactNode; spark?: number[]; tone?: 'accent' | 'bad' | 'warn' | 'muted' | 'ok'; sparkLabel?: string }) {
  return (
    <Link to={to} search={search} className="card group flex flex-col gap-1 p-[var(--pad-card)] transition-colors hover:border-line-strong">
      <span className="flex items-center justify-between text-[12.5px] font-medium text-muted">
        {label}
        <ArrowRight size={13} className="opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
      </span>
      <span className="flex items-baseline gap-1.5">
        <span className="num text-[26px] leading-tight font-semibold tracking-tight">{value}</span>
        {unit && <span className="text-[12px] text-muted">{unit}</span>}
      </span>
      {delta}
      <div className="mt-auto h-7 pt-1">{spark && spark.length > 1 && <Sparkline data={spark} tone={tone} height={26} label={sparkLabel} />}</div>
    </Link>
  )
}
