// The settings page: a list of sections on the left (a row of chips on
// narrow screens), the section's forms on the right. The section lives in
// the URL (?s=), each section module loads on demand.
import { useNavigate, useSearch } from '@tanstack/react-router'
import { lazy, Suspense, type ComponentType } from 'react'
import { useMe, type Me } from '../../api/me'
import { ErrorBoundary, ErrorState, LoadingState } from '../../components/states'
import { PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { cx } from '../../lib/cx'
import { sections, type SectionId } from './sections'

const mod = <K extends string>(load: () => Promise<Record<K, ComponentType>>, name: K) => lazy(() => load().then((m) => ({ default: m[name] })))
const server = () => import('./server')
const people = () => import('./people')
const ops = () => import('./ops')
const fleet = () => import('./fleet')
const cve = () => import('./cvefeeds')
const logs = () => import('../logs/settings')

const views: Record<SectionId, ComponentType> = {
  general: mod(server, 'General'),
  access: mod(server, 'Access'),
  privacy: mod(server, 'Privacy'),
  signin: mod(server, 'SignIn'),
  password: mod(server, 'Password'),
  approvals: mod(server, 'Approvals'),
  shell: mod(server, 'RemoteShell'),
  enroll: mod(server, 'Enrollment'),
  keys: mod(ops, 'Keys'),
  users: mod(people, 'Users'),
  tenants: mod(people, 'Tenants'),
  tokens: mod(people, 'Tokens'),
  notifications: mod(ops, 'Notifications'),
  backup: mod(ops, 'Backup'),
  retention: mod(server, 'Retention'),
  operations: mod(server, 'Operations'),
  directory: mod(fleet, 'Directory'),
  network: mod(fleet, 'Network'),
  agents: mod(fleet, 'Agents'),
  cve: mod(cve, 'CVEFeeds'),
  logs: mod(logs, 'LogSettings'),
}

/** The sections the signed in user may open, in navigation order. */
export function visibleSections(me: Me) {
  const tenantOnly = !!me.tenant && !me.super
  const scoped = me.role !== 'admin' && (me.scope_tags.length > 0 || me.scope_groups.length > 0)
  return sections.filter((x) => {
    if (x.tenant === 'only-global' && (tenantOnly || scoped)) return false
    if (x.tenant === 'multi' && !me.multi_tenant) return false
    if (x.admin && !me.permissions.includes('admin')) return false
    return true
  })
}

export function SettingsPage() {
  const t = useT()
  const me = useMe()
  const search = useSearch({ strict: false }) as { s?: string }
  const navigate = useNavigate()
  const list = visibleSections(me)
  const current = list.find((x) => x.id === search.s) ?? list[0]
  if (!me.permissions.includes('audit')) {
    return (
      <div>
        <PageHeader title={t('settings.title')} />
        <ErrorState error={new Error(t('settings.noAccess'))} />
      </div>
    )
  }
  const View = views[current.id]
  const groups = [...new Set(list.map((x) => x.group))]
  return (
    <div>
      <PageHeader title={t('settings.title')} sub={t('settings.sub')} />
      <div className="grid gap-[var(--gap)] lg:grid-cols-[230px_minmax(0,1fr)]">
        <nav aria-label={t('settings.sections')} className="flex gap-1 overflow-x-auto pb-1 lg:flex-col lg:overflow-visible">
          {groups.map((g) => (
            <div key={g} className="contents lg:flex lg:flex-col lg:gap-0.5 lg:pb-3">
              <span className="hidden px-2.5 pb-1 text-micro font-semibold tracking-wide text-muted uppercase lg:block">{t(`settings.group.${g}` as MessageKey)}</span>
              {list
                .filter((x) => x.group === g)
                .map((x) => (
                  <a
                    key={x.id}
                    href={`/app/settings?s=${x.id}`}
                    onClick={(e) => {
                      if (e.metaKey || e.ctrlKey || e.shiftKey) return
                      e.preventDefault()
                      void navigate({ to: '/settings', search: { s: x.id } })
                    }}
                    aria-current={current.id === x.id ? 'page' : undefined}
                    className={cx(
                      'flex shrink-0 items-center gap-2 rounded-md px-2.5 py-1.5 font-medium whitespace-nowrap',
                      current.id === x.id ? 'bg-surface text-fg ring-1 ring-line' : 'text-muted hover:bg-surface-2 hover:text-fg',
                    )}
                  >
                    <x.icon size={15} aria-hidden /> {t(`settings.nav.${x.id}` as MessageKey)}
                  </a>
                ))}
            </div>
          ))}
        </nav>
        <div className="card min-w-0 px-[var(--pad-card)] pb-2">
          <ErrorBoundary key={current.id}>
            <Suspense fallback={<LoadingState rows={6} />}>
              <View />
            </Suspense>
          </ErrorBoundary>
        </div>
      </div>
    </div>
  )
}
