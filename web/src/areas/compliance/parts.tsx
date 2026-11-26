// Small pieces shared by the compliance pages: the section navigation and
// the exception state badge.
import { Link } from '@tanstack/react-router'
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

export function ExceptionBadge({ state }: { state?: string }) {
  const t = useT()
  return <Badge tone={state === 'active' ? 'ok' : 'off'}>{t(`compliance.exc.state.${state ?? 'expired'}` as MessageKey)}</Badge>
}
