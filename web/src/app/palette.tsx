// Command palette (Ctrl K, /): pages, area actions, preferences, tenants and
// a device search. cmdk sits in a Base UI dialog (cmdk's own dialog pulls in
// a scroll lock that injects <style>, which the CSP refuses).
import { Dialog } from '@base-ui/react/dialog'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { Command } from 'cmdk'
import { Building2, Languages, Laptop, Moon, Rows4, Search, Sun, type LucideIcon } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { api, unwrap } from '../api/client'
import { chooseLocale, useMe } from '../api/me'
import { useT } from '../i18n'
import { loadAllCatalogs } from '../i18n/catalog'
import { currentLocale, locales } from '../i18n'
import { resolvedTheme, setPrefs, usePrefs } from '../lib/prefs'
import { SearchResults } from '../areas/home/search'
import { areas } from './areas'
import { switchTenant, useTenants } from './tenants'

const group =
  'px-1 [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:pt-3 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-micro [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-muted [&_[cmdk-group-heading]]:uppercase'

function Item({ icon: I, children, onSelect, value, hint }: { icon: LucideIcon; children: ReactNode; onSelect: () => void; value?: string; hint?: string }) {
  return (
    <Command.Item value={value} onSelect={onSelect} className="flex cursor-default items-center gap-2.5 rounded-md px-2.5 py-2 data-[selected=true]:bg-surface-2">
      <I size={16} className="text-muted" aria-hidden />
      <span className="flex-1 truncate">{children}</span>
      {hint && <span className="text-meta text-muted">{hint}</span>}
    </Command.Item>
  )
}

export function Palette({ open, setOpen }: { open: boolean; setOpen: (v: boolean) => void }) {
  const t = useT()
  const me = useMe()
  const nav = useNavigate()
  const p = usePrefs()
  const tenants = useTenants()
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  // the area commands' labels: every catalog, once the palette opens
  const [, setLoaded] = useState(false)
  useEffect(() => {
    if (open) void loadAllCatalogs().then(() => setLoaded(true))
  }, [open])
  useEffect(() => {
    const id = setTimeout(() => setTerm(search.trim()), 200)
    return () => clearTimeout(id)
  }, [search])
  const devices = useQuery({
    queryKey: ['devices', 'palette', term],
    enabled: open && term.length >= 2,
    queryFn: () => unwrap(api.GET('/api/v1/devices', { params: { query: { q: term, limit: 8 } } })).then((r) => r.items ?? []),
  })
  const close = (fn: () => void) => () => {
    setOpen(false)
    setSearch('')
    fn()
  }
  const go = (to: string, search?: Record<string, string>) => void nav({ to, search })
  const visible = areas.filter((a) => a.nav && (!a.nav.permission || me.permissions.includes(a.nav.permission)))
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-[var(--c-overlay)]" />
        <Dialog.Popup className="fade-in fixed top-[10vh] left-1/2 z-50 w-[calc(100vw-24px)] max-w-[640px] -translate-x-1/2 overflow-hidden rounded-xl border border-line bg-surface shadow-pop outline-none">
          <Dialog.Title className="sr-only">{t('palette.title')}</Dialog.Title>
          <Command label={t('palette.title')} loop>
            <div className="flex items-center gap-2 border-b border-line px-4">
              <Search size={17} className="text-muted" aria-hidden />
              <Command.Input autoFocus value={search} onValueChange={setSearch} placeholder={t('palette.placeholder')} className="h-12 flex-1 bg-transparent text-title outline-none placeholder:text-muted" />
              <span className="kbd">Esc</span>
            </div>
            <Command.List className="max-h-[min(60vh,440px)] overflow-y-auto pb-2">
              <Command.Empty className="p-6 text-center text-muted">{t('palette.empty')}</Command.Empty>
              <Command.Group heading={t('palette.goto')} className={group}>
                {visible.map((a) => (
                  <Item key={a.id} icon={a.nav!.icon} onSelect={close(() => go(a.nav!.to))}>
                    {t(a.nav!.label)}
                  </Item>
                ))}
              </Command.Group>
              <Command.Group heading={t('palette.actions')} className={group}>
                {areas.flatMap((a) => a.commands?.() ?? []).map((c) => (
                  <Item key={c.id} icon={c.icon} value={`${c.label} ${c.keywords ?? ''}`} onSelect={close(() => c.run(go))}>
                    {c.label}
                  </Item>
                ))}
                <Item icon={resolvedTheme(p) === 'dark' ? Sun : Moon} onSelect={close(() => setPrefs({ theme: resolvedTheme(p) === 'dark' ? 'light' : 'dark' }))}>
                  {t('top.theme')}
                </Item>
                <Item icon={Rows4} onSelect={close(() => setPrefs({ density: p.density === 'compact' ? 'comfortable' : 'compact' }))}>
                  {t('top.density')}
                </Item>
                {locales
                  .filter((l) => l.id !== currentLocale())
                  .map((l) => (
                    <Item key={l.id} icon={Languages} value={`${t('palette.language')} ${l.name}`} onSelect={close(() => chooseLocale(l.id))} hint={l.name}>
                      {t('palette.language')}
                    </Item>
                  ))}
                {tenants.data?.map((x) => (
                  <Item key={x.id} icon={Building2} onSelect={close(() => void switchTenant(x.id))}>
                    {t('palette.switchTenant', { name: x.name })}
                  </Item>
                ))}
              </Command.Group>
              {!!devices.data?.length && (
                <Command.Group heading={t('palette.devices')} className={group}>
                  {devices.data.map((d) => (
                    <Item key={d.id} icon={Laptop} value={`${search} ${d.hostname} ${d.id}`} hint={d.os} onSelect={close(() => void nav({ to: '/devices/$id', params: { id: d.id } }))}>
                      <span className="font-mono text-body">{d.hostname}</span>
                    </Item>
                  ))}
                </Command.Group>
              )}
              <SearchResults term={term} group={group} go={(to, s) => close(() => go(to, s))()} />
            </Command.List>
          </Command>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
