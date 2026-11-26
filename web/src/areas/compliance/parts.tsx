// Small pieces shared by the compliance pages: the section navigation, the
// badges for check results, severities and exception states.
import { Link } from '@tanstack/react-router'
import { CheckCircle2, CircleDashed, OctagonX, ShieldOff } from 'lucide-react'
import { Badge } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'

const sections = [
  { to: '/compliance', label: 'compliance.tab.overview' },
  { to: '/compliance/exceptions', label: 'compliance.tab.exceptions' },
  { to: '/compliance/history', label: 'compliance.tab.history' },
  { to: '/compliance/policies', label: 'compliance.tab.policies' },
] as const

/** Links between the compliance pages, shown under each page header. */
export function SectionNav() {
  const t = useT()
  return (
    <nav aria-label={t('compliance.tabs')} className="mb-[var(--gap)] flex gap-1 overflow-x-auto border-b border-line">
      {sections.map((s) => (
        <Link
          key={s.to}
          to={s.to}
          activeOptions={{ exact: true, includeSearch: false }}
          className="-mb-px border-b-2 border-transparent px-3 py-2 font-medium whitespace-nowrap text-muted hover:text-fg"
          activeProps={{ className: '!border-accent !text-fg', 'aria-current': 'page' }}
        >
          {t(s.label)}
        </Link>
      ))}
    </nav>
  )
}

const resultTone = { pass: 'ok', fail: 'bad', excepted: 'info', advisory: 'warn' } as const
const resultIcon = { pass: CheckCircle2, fail: OctagonX, excepted: ShieldOff }

/** A check result (pass, fail, na, excepted ...) with icon and text, never color alone. */
export function ResultBadge({ status }: { status: string }) {
  const t = useT()
  const I = resultIcon[status as keyof typeof resultIcon] ?? CircleDashed
  return (
    <Badge tone={resultTone[status as keyof typeof resultTone] ?? 'off'}>
      <I size={12} aria-hidden /> {t(`compliance.status.${status}` as MessageKey)}
    </Badge>
  )
}

const sevTone = { low: 'neutral', medium: 'warn', high: 'bad', critical: 'bad' } as const

export function SeverityBadge({ severity }: { severity?: string }) {
  const t = useT()
  if (!severity) return null
  return <Badge tone={sevTone[severity as keyof typeof sevTone] ?? 'neutral'}>{t(`compliance.severity.${severity}` as MessageKey)}</Badge>
}

export function ExceptionBadge({ state }: { state?: string }) {
  const t = useT()
  return <Badge tone={state === 'active' ? 'ok' : 'off'}>{t(`compliance.exc.state.${state ?? 'expired'}` as MessageKey)}</Badge>
}
