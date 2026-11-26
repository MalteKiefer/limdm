// The app shell: task based navigation (areas), tenant view, top bar with
// search, live state and inbox, command palette, toasts. Pages render in
// the Outlet inside an error boundary, so a crashing page leaves the shell.
import { Dialog } from '@base-ui/react/dialog'
import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import { Bell, Bookmark, Building2, ChevronsUpDown, CircleHelp, ExternalLink, Languages, LogOut, Menu as MenuIcon, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Rows3, Rows4, Search, Sun, UserRound, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useInboxCount, useLiveState, startLive } from '../api/live'
import { useMe } from '../api/me'
import { useSavedViews } from '../api/views'
import { SvgDefs } from '../components/charts'
import { ErrorBoundary } from '../components/states'
import { Toaster } from '../components/toast'
import { ActionMenu, Avatar, Tip } from '../components/ui'
import { currentLocale, useT, type MessageKey } from '../i18n'
import { accentTokens } from '../lib/contrast'
import { cx } from '../lib/cx'
import { resolvedTheme, setPrefs, usePrefs, type Theme } from '../lib/prefs'
import type { Area } from './area'
import { areas } from './areas'
import { Palette } from './palette'
import { signOut, switchTenant, useTenants } from './tenants'

function useInbox() {
  const live = useInboxCount()
  return live ?? 0
}

function NavItem({ nav, collapsed, count }: { nav: NonNullable<Area['nav']>; collapsed: boolean; count?: number }) {
  const t = useT()
  const path = useRouterState({ select: (s) => s.location.pathname })
  const on = nav.to === '/' ? path === '/' : path === nav.to || path.startsWith(nav.to + '/')
  const label = t(nav.label)
  const link = (
    <Link
      to={nav.to}
      aria-current={on ? 'page' : undefined}
      className={cx(
        'group flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13.5px] font-medium transition-colors',
        on ? 'bg-surface text-fg shadow-sm ring-1 ring-line' : 'text-fg-2 hover:bg-surface-2 hover:text-fg',
        collapsed && 'justify-center px-0',
      )}
    >
      <nav.icon size={17} aria-hidden className={on ? 'text-accent' : 'text-muted group-hover:text-fg'} />
      {collapsed ? <span className="sr-only">{label}</span> : <span className="flex-1 truncate">{label}</span>}
      {!collapsed && !!count && <span className="num rounded-full bg-accent px-1.5 text-[11px] font-semibold text-on-accent">{count}</span>}
    </Link>
  )
  return collapsed ? <Tip label={label}>{link}</Tip> : link
}

function NavViews({ list, to }: { list: string; to: string }) {
  const views = useSavedViews(list).data ?? []
  const search = useRouterState({ select: (s) => s.location.search as { q?: string } })
  const path = useRouterState({ select: (s) => s.location.pathname })
  if (!views.length) return null
  return (
    <ul className="mb-1 ml-[19px] flex flex-col border-l border-line pl-2">
      {views.slice(0, 8).map((v) => (
        <li key={v.id}>
          <Link to={to} search={{ q: v.query || undefined, sort: v.sort || undefined }} className={cx('flex items-center gap-2 rounded px-2 py-1 text-[12.5px]', path === to && search.q === v.query ? 'font-medium text-fg' : 'text-muted hover:text-fg')}>
            {v.shared ? <Users size={12} aria-hidden /> : <Bookmark size={12} aria-hidden />}
            <span className="truncate">{v.name}</span>
          </Link>
        </li>
      ))}
    </ul>
  )
}

function TenantSwitch({ collapsed }: { collapsed: boolean }) {
  const t = useT()
  const me = useMe()
  const tenants = useTenants()
  if (!me.multi_tenant) return null
  const name = me.tenant?.name ?? t('tenant.all')
  const button = (
    <button type="button" className={cx('flex w-full items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-2 text-left hover:border-line-strong', collapsed && 'justify-center px-0')} aria-label={`${t('tenant.choose')}: ${name}`}>
      <Building2 size={16} className="shrink-0 text-muted" aria-hidden />
      {!collapsed && (
        <>
          <span className="min-w-0 flex-1">
            <span className="block text-[11px] text-muted">{t('tenant.label')}</span>
            <span className="block truncate text-[13px] font-medium">{name}</span>
          </span>
          {tenants.data && <ChevronsUpDown size={14} className="text-muted" aria-hidden />}
        </>
      )}
    </button>
  )
  if (!tenants.data) return button
  return (
    <ActionMenu
      align="start"
      trigger={button}
      items={[
        { group: t('tenant.view') },
        { label: t('tenant.all'), checked: !me.tenant, onClick: () => void switchTenant(0) },
        'sep',
        ...tenants.data.map((x) => ({ label: x.name, hint: String(x.devices), checked: me.tenant?.id === x.id, onClick: () => void switchTenant(x.id) })),
      ]}
    />
  )
}

function Sidebar({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const t = useT()
  const me = useMe()
  const inbox = useInbox()
  const navs = areas
    .map((a) => a.nav)
    .filter((n): n is NonNullable<Area['nav']> => !!n && (!n.permission || me.permissions.includes(n.permission)))
    .sort((a, b) => a.order - b.order)
  return (
    <nav aria-label={t('nav.main')} className="flex h-full flex-col gap-4 overflow-y-auto p-3" onClick={(e) => (e.target as HTMLElement).closest('a') && onNavigate?.()}>
      <div className={cx('flex items-center gap-2 px-1.5 pt-1', collapsed && 'justify-center px-0')}>
        <Logo />
        {!collapsed && <span className="truncate text-[15px] font-semibold tracking-tight">{me.company_name || t('app.name')}</span>}
      </div>
      <TenantSwitch collapsed={collapsed} />
      <ul className="flex flex-col gap-0.5">
        {navs
          .filter((n) => !n.bottom)
          .map((n) => (
            <li key={n.to}>
              <NavItem nav={n} collapsed={collapsed} count={n.to === '/inbox' ? inbox : undefined} />
              {n.views && !collapsed && <NavViews list={n.views} to={n.to} />}
            </li>
          ))}
      </ul>
      <ul className="mt-auto flex flex-col gap-0.5">
        {navs
          .filter((n) => n.bottom)
          .map((n) => (
            <li key={n.to}>
              <NavItem nav={n} collapsed={collapsed} />
            </li>
          ))}
        <li>
          <a href="/classic" className={cx('flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] text-muted hover:bg-surface-2 hover:text-fg', collapsed && 'justify-center px-0')}>
            <ExternalLink size={16} aria-hidden />
            {collapsed ? <span className="sr-only">{t('nav.oldConsole')}</span> : t('nav.oldConsole')}
          </a>
        </li>
        <li>
          <UserMenu collapsed={collapsed} />
        </li>
      </ul>
    </nav>
  )
}

function UserMenu({ collapsed }: { collapsed: boolean }) {
  const t = useT()
  const me = useMe()
  const p = usePrefs()
  const login = me.login.replace(/^local:/, '')
  const navigate = useNavigate()
  const themes: [Theme, MessageKey][] = [
    ['system', 'user.themeSystem'],
    ['light', 'user.themeLight'],
    ['dark', 'user.themeDark'],
  ]
  return (
    <ActionMenu
      align="start"
      trigger={
        <button type="button" className={cx('mt-1 flex w-full items-center gap-2 rounded-md p-1.5 text-left hover:bg-surface-2', collapsed && 'justify-center')} aria-label={t('user.menu')}>
          <Avatar name={login} size={28} />
          {!collapsed && (
            <span className="min-w-0 leading-tight">
              <span className="block truncate text-[13px] font-medium">{login}</span>
              <span className="block text-[11.5px] text-muted">{t(`role.${me.role}` as MessageKey)}</span>
            </span>
          )}
        </button>
      }
      items={[
        { group: t('user.appearance') },
        ...themes.map(([v, k]) => ({ label: t(k), icon: v === 'dark' ? Moon : v === 'light' ? Sun : Monitor, checked: p.theme === v, onClick: () => setPrefs({ theme: v }) })),
        { label: p.density === 'compact' ? t('user.comfortable') : t('user.compact'), icon: p.density === 'compact' ? Rows3 : Rows4, onClick: () => setPrefs({ density: p.density === 'compact' ? 'comfortable' : 'compact' }) },
        { group: t('user.language') },
        { label: 'Deutsch', icon: Languages, checked: currentLocale() === 'de', onClick: () => setPrefs({ locale: 'de' }) },
        { label: 'English', icon: Languages, checked: currentLocale() === 'en', onClick: () => setPrefs({ locale: 'en' }) },
        'sep',
        { label: t('settings.profile.title'), icon: UserRound, onClick: () => void navigate({ to: '/profile' }) },
        { label: t('settings.help.title'), icon: CircleHelp, onClick: () => void navigate({ to: '/help' }) },
        { label: t('nav.oldConsole'), icon: ExternalLink, onClick: () => location.assign('/classic') },
        { label: t('user.signOut'), icon: LogOut, onClick: () => void signOut() },
      ]}
    />
  )
}

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className="shrink-0">
      <rect width="32" height="32" rx="8" fill="var(--c-accent)" />
      <path d="M10 8v16h12" stroke="var(--c-on-accent)" strokeWidth="3.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="21.5" cy="10.5" r="2.6" fill="var(--c-on-accent)" />
    </svg>
  )
}

function Topbar({ onMenu, onSearch, collapsed }: { onMenu: () => void; onSearch: () => void; collapsed: boolean }) {
  const t = useT()
  const p = usePrefs()
  const inbox = useInbox()
  const live = useLiveState()
  const dark = resolvedTheme(p) === 'dark'
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-bg/85 px-4 backdrop-blur lg:px-6">
      <button type="button" className="btn btn-ghost px-2 lg:hidden" onClick={onMenu} aria-label={t('nav.open')}>
        <MenuIcon size={18} />
      </button>
      <button type="button" className="btn btn-ghost hidden px-2 lg:inline-flex" onClick={() => setPrefs({ navCollapsed: !collapsed })} aria-label={collapsed ? t('nav.expand') : t('nav.collapse')}>
        {collapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
      </button>
      <button type="button" onClick={onSearch} className="flex h-9 min-w-0 flex-1 items-center gap-2 rounded-lg border border-line bg-surface px-3 text-left text-muted hover:border-line-strong md:max-w-[520px]">
        <Search size={16} aria-hidden />
        <span className="flex-1 truncate">{t('top.search')}</span>
        <span className="kbd hidden sm:inline">{t('top.searchKey')}</span>
      </button>
      <div className="ml-auto flex items-center gap-1">
        <span className="mr-2 hidden items-center gap-1.5 text-[12px] text-muted md:flex" title={t('top.liveHint')} role="status">
          <span className={cx('size-2 rounded-full', live === 'live' ? 'live-dot bg-ok' : live === 'connecting' ? 'bg-warn-mark' : 'bg-off')} aria-hidden />
          {live === 'live' ? t('top.live') : live === 'connecting' ? t('top.liveConnecting') : t('top.liveOffline')}
        </span>
        <Tip label={t('top.theme')}>
          <button type="button" className="btn btn-ghost px-2" onClick={() => setPrefs({ theme: dark ? 'light' : 'dark' })} aria-label={t('top.theme')}>
            {dark ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </Tip>
        <Tip label={t('top.density')}>
          <button type="button" className="btn btn-ghost hidden px-2 sm:inline-flex" onClick={() => setPrefs({ density: p.density === 'compact' ? 'comfortable' : 'compact' })} aria-label={t('top.density')}>
            {p.density === 'compact' ? <Rows3 size={17} /> : <Rows4 size={17} />}
          </button>
        </Tip>
        <Link to="/inbox" className="btn btn-ghost relative px-2" aria-label={t('top.inbox', { count: inbox })}>
          <Bell size={17} />
          {inbox > 0 && <span className="num absolute top-0.5 right-0.5 grid h-4 min-w-4 place-items-center rounded-full bg-bad px-1 text-[10px] font-semibold text-surface">{inbox}</span>}
        </Link>
      </div>
    </header>
  )
}

/** Applies the tenant accent, corrected for contrast on the current surface. */
function useAccent(color: string) {
  const p = usePrefs()
  useEffect(() => {
    const root = document.documentElement
    const dark = resolvedTheme(p) === 'dark'
    const surface = getComputedStyle(root).getPropertyValue('--c-surface').trim()
    const tokens = color ? accentTokens(color, surface, dark) : null
    const names = ['--c-accent', '--c-accent-hover', '--c-on-accent', '--c-accent-soft', '--c-on-accent-soft']
    names.forEach((n) => root.style.removeProperty(n))
    if (tokens) Object.entries(tokens).forEach(([k, v]) => root.style.setProperty(k, v))
  }, [color, p])
}

export function Shell() {
  const t = useT()
  const me = useMe()
  const [palette, setPalette] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const p = usePrefs()
  const collapsed = p.navCollapsed
  const path = useRouterState({ select: (s) => s.location.pathname })
  useAccent(me.accent)
  useEffect(() => startLive(), [])
  useEffect(() => {
    document.documentElement.lang = currentLocale()
  })
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      const typing = /INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable
      if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
        e.preventDefault()
        setPalette(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  return (
    <div className={cx('min-h-dvh lg:grid', collapsed ? 'lg:grid-cols-[64px_1fr]' : 'lg:grid-cols-[244px_1fr]')}>
      <SvgDefs />
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-surface focus:p-2">
        {t('app.skip')}
      </a>
      <aside className="sticky top-0 hidden h-dvh border-r border-line lg:block">
        <Sidebar collapsed={collapsed} />
      </aside>
      <Dialog.Root open={mobileNav} onOpenChange={setMobileNav}>
        <Dialog.Portal>
          <Dialog.Backdrop className="fixed inset-0 z-40 bg-[var(--c-overlay)] lg:hidden" />
          <Dialog.Popup className="fixed inset-y-0 left-0 z-50 w-[280px] max-w-[85vw] border-r border-line bg-bg outline-none lg:hidden">
            <Dialog.Title className="sr-only">{t('nav.title')}</Dialog.Title>
            <Sidebar collapsed={false} onNavigate={() => setMobileNav(false)} />
          </Dialog.Popup>
        </Dialog.Portal>
      </Dialog.Root>
      <div className="flex min-w-0 flex-col">
        <Topbar onMenu={() => setMobileNav(true)} onSearch={() => setPalette(true)} collapsed={collapsed} />
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1600px] min-w-0 flex-1 px-4 py-5 outline-none lg:px-6">
          <ErrorBoundary key={path}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
      <Palette open={palette} setOpen={setPalette} />
      <Toaster />
    </div>
  )
}
