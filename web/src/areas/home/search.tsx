// Global search in the command palette beyond devices: pending approvals,
// library items, blueprints and (admins and auditors) the audit log. Each
// source is the list endpoint the matching page uses, so roles, tenant and
// scope stay the server's.
import { useQuery } from '@tanstack/react-query'
import { Command } from 'cmdk'
import { Boxes, LayoutTemplate, ScrollText, ShieldAlert, type LucideIcon } from 'lucide-react'
import { api, unwrap } from '../../api/client'
import { useCan } from '../../api/me'
import { useT } from '../../i18n'
import { ago } from '../../i18n/format'
import { actionLabel } from '../inbox/risk'

const has = (term: string, ...v: (string | undefined)[]) => v.some((x) => x?.toLowerCase().includes(term.toLowerCase()))

type Go = (to: string, search?: Record<string, string>) => void

export function SearchResults({ term, group, go }: { term: string; group: string; go: Go }) {
  const t = useT()
  const canAudit = useCan('audit')
  const on = term.length >= 2
  const approvals = useQuery({
    queryKey: ['approvals', 'pending'],
    enabled: on,
    queryFn: () => unwrap(api.GET('/api/v1/approvals', { params: { query: { status: 'pending', limit: 500 } } })).then((p) => p.items ?? []),
  })
  const items = useQuery({ queryKey: ['config', 'search', 'library'], enabled: on, staleTime: 60_000, queryFn: () => unwrap(api.GET('/api/v1/library-items')).then((p) => p.items ?? []) })
  const blueprints = useQuery({ queryKey: ['config', 'search', 'blueprints'], enabled: on, staleTime: 60_000, queryFn: () => unwrap(api.GET('/api/v1/blueprints')).then((p) => p.items ?? []) })
  const audit = useQuery({
    queryKey: ['activity', 'search', term],
    enabled: on && canAudit,
    queryFn: () => unwrap(api.GET('/api/v1/audit', { params: { query: { q: term, limit: 5 } } })).then((p) => p.items ?? []),
  })
  if (!on) return null
  const rows: { key: string; heading: string; icon: LucideIcon; list: { id: string; label: string; hint?: string; run: () => void }[] }[] = [
    {
      key: 'approvals',
      heading: t('home.search.approvals'),
      icon: ShieldAlert,
      list: (approvals.data ?? [])
        .filter((a) => has(term, a.target, a.requested_by, a.action, a.reason))
        .slice(0, 5)
        .map((a) => ({ id: `a${a.id}`, label: `${actionLabel(a, t)} · ${a.target}`, hint: a.requested_by, run: () => go('/inbox', { item: `a${a.id}` }) })),
    },
    {
      key: 'library',
      heading: t('home.search.library'),
      icon: Boxes,
      list: (items.data ?? [])
        .filter((i) => has(term, i.name, i.type))
        .slice(0, 5)
        .map((i) => ({ id: `l${i.id}`, label: i.name ?? '', hint: i.type, run: () => go(`/config/library/${i.id}`) })),
    },
    {
      key: 'blueprints',
      heading: t('home.search.blueprints'),
      icon: LayoutTemplate,
      list: (blueprints.data ?? [])
        .filter((b) => has(term, b.name))
        .slice(0, 5)
        .map((b) => ({ id: `b${b.id}`, label: b.name ?? '', run: () => go('/config', { tab: 'blueprints' }) })),
    },
    {
      key: 'audit',
      heading: t('home.search.audit'),
      icon: ScrollText,
      list: (audit.data ?? []).map((e) => ({ id: `e${e.id}`, label: `${e.action} · ${e.target || e.actor}`, hint: e.at ? ago(e.at) : undefined, run: () => go('/activity', { q: term }) })),
    },
  ]
  return (
    <>
      {rows
        .filter((r) => r.list.length)
        .map((r) => (
          <Command.Group key={r.key} heading={r.heading} className={group}>
            {r.list.map((x) => (
              <Command.Item key={x.id} value={`${term} ${x.id} ${x.label}`} onSelect={x.run} className="flex cursor-default items-center gap-2.5 rounded-md px-2.5 py-2 data-[selected=true]:bg-surface-2">
                <r.icon size={16} className="text-muted" aria-hidden />
                <span className="flex-1 truncate">{x.label}</span>
                {x.hint && <span className="text-[12px] text-muted">{x.hint}</span>}
              </Command.Item>
            ))}
          </Command.Group>
        ))}
    </>
  )
}
