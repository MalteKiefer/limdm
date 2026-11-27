// The device page: header with facts and actions, protective notices and
// six tabs (overview, compliance, configuration, software, inventory,
// activity), each with a URL (?tab=, ?sub=).
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { Activity, ArrowLeft, Bot, BrickWall, CheckCircle2, ChevronDown, ChevronUp, CircleAlert, Cpu, Download, HardDrive, Layers, Monitor, MoreHorizontal, RefreshCw, Server, ShieldCheck, ShieldAlert, Terminal, Trash2, Wifi } from 'lucide-react'
import { useCallback, useState, type ReactNode } from 'react'
import { useCan } from '../../api/me'
import { axisX, axisY, baseOption, ChartFrame, EChart, type Colors } from '../../components/charts'
import { TabBar, TabPanel } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { ActionMenu, Badge, Card, StatusPill, type DeviceStatus } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, dateShort, dateTime, fmt1 } from '../../i18n/format'
import { cx } from '../../lib/cx'
import { DeviceDialog, useDeviceMenu, useRun, type Dialog, type Target } from './actions'
import { useDetail, type DeviceDetail } from './api'
import { checkTone, connectionState, firewallHealth, orderNotices, protectiveAlarm, updatesHealth, usedPct } from './logic'
import { ActivityTab, InventoryTab, SoftwareTab } from './tabs'
import { UpdatesTab } from './UpdatesTab'
import { WorkloadsTab } from '../workloads/WorkloadsTab'
import { HostnameCard } from './HostnameCard'
import { FirewallTab } from './FirewallTab'

const tabs = ['overview', 'compliance', 'config', 'software', 'updates', 'firewall', 'workloads', 'inventory', 'activity'] as const
type Tab = (typeof tabs)[number]

export function DevicePage() {
  const t = useT()
  const { id } = useParams({ strict: false }) as { id: string }
  const search = useSearch({ strict: false }) as { tab?: string; sub?: string }
  const nav = useNavigate()
  const detail = useDetail(id)
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const d = detail.data
  const target: Target = { id, hostname: d?.hostname ?? id, retired: d?.retired, detail: d }
  const menu = useDeviceMenu(target, setDialog)
  const tab = (tabs as readonly string[]).includes(search.tab ?? '') ? (search.tab as Tab) : 'overview'
  const setSub = useCallback((sub: string) => void nav({ to: '/devices/$id', params: { id }, search: { tab, sub }, replace: true }), [nav, id, tab])
  if (detail.error) return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
  if (!d) return <LoadingState rows={10} />
  const failing = d.check_results.filter((c) => (c as { status: string }).status === 'fail').length
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Link to="/devices" className="inline-flex w-fit items-center gap-1 text-body text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {t('devices.title')}
      </Link>
      <Header d={d} target={target} menu={menu} open={setDialog} />
      <Notices d={d} />
      <TabBar
        idBase="dev"
        label={t('devices.tabs')}
        value={tab}
        onChange={(v) => void nav({ to: '/devices/$id', params: { id }, search: { tab: v === 'overview' ? undefined : v }, replace: true })}
        tabs={tabs.map((v) => ({ value: v, label: t(`devices.tab.${v}`), count: v === 'compliance' && failing ? failing : undefined }))}
      />
      <TabPanel idBase="dev" value={tab}>
        {tab === 'overview' && <Overview d={d} open={setDialog} />}
        {tab === 'compliance' && <Compliance d={d} />}
        {tab === 'config' && <Config d={d} />}
        {tab === 'software' && <SoftwareTab d={d} sub={search.sub} setSub={setSub} open={setDialog} />}
        {tab === 'updates' && <UpdatesTab d={d} />}
        {tab === 'firewall' && <FirewallTab d={d} />}
        {tab === 'workloads' && <WorkloadsTab d={d} />}
        {tab === 'inventory' && <InventoryTab d={d} sub={search.sub} setSub={setSub} open={setDialog} />}
        {tab === 'activity' && <ActivityTab d={d} />}
      </TabPanel>
      <DeviceDialog dialog={dialog} target={target} onClose={() => setDialog(null)} />
    </div>
  )
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="truncate text-body">{children || '–'}</dd>
    </div>
  )
}

function Header({ d, target, menu, open }: { d: DeviceDetail; target: Target; menu: ReturnType<typeof useDeviceMenu>; open: (x: Dialog) => void }) {
  const t = useT()
  const admin = useCan('admin')
  const commands = useCan('commands')
  const helpdeskView = !admin && commands
  const { run, pending } = useRun(target)
  const inv = d.inventory
  return (
    <header className="card flex flex-col gap-4 p-[var(--pad-card)]">
      <div className="flex flex-wrap items-start gap-4">
        <div className="grid size-12 shrink-0 place-items-center rounded-xl bg-surface-2 text-fg-2 ring-1 ring-line" aria-hidden>
          {inv.desktop ? <Monitor size={22} /> : <Server size={22} />}
        </div>
        <div className="min-w-0 flex-1">
          <h1 className="truncate font-mono text-heading font-semibold">{d.hostname}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-body text-muted">
            <StatusPill status={d.status as DeviceStatus} />
            <span>{inv.os_name || d.os}</span>
            <span>{t('devices.seen', { ago: d.last_seen ? ago(d.last_seen) : t('devices.never') })}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {!d.retired && commands && (
            <button type="button" className="btn" disabled={pending} onClick={() => run('sync')}>
              <RefreshCw size={14} aria-hidden /> {t('devices.cmd.sync')}
            </button>
          )}
          {!d.retired && d.shell.enabled && d.shell.allowed && (
            <button type="button" className="btn" onClick={() => open({ kind: 'shell' })}>
              <Terminal size={14} aria-hidden /> {t('devices.cmd.shell')}
            </button>
          )}
          {d.retired && admin && (
            <button type="button" className="btn btn-danger" onClick={() => open({ kind: 'delete' })}>
              <Trash2 size={14} aria-hidden /> {t('devices.delete.title')}
            </button>
          )}
          {menu.length > 0 && (
            <ActionMenu
              trigger={
                <button type="button" className="btn" aria-label={t('devices.actionsFor', { name: d.hostname })}>
                  <MoreHorizontal size={16} aria-hidden /> {t('devices.actions')}
                </button>
              }
              items={menu}
            />
          )}
        </div>
      </div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 xl:grid-cols-6">
        <Fact label={t('devices.fact.model')}>{[inv.vendor, inv.model].filter(Boolean).join(' ')}</Fact>
        <Fact label={t('devices.fact.serial')}>
          <span className="font-mono">{inv.serial}</span>
        </Fact>
        <Fact label={t('devices.fact.user')}>
          {d.primary_user && (helpdeskView ? d.primary_user : <Link to="/settings" search={{ s: 'directory', sel: undefined }}>
                {d.primary_user}
              </Link>)}
        </Fact>
        <Fact label={t('devices.fact.blueprint')}>
          {d.blueprints.find((b) => b.applies)?.name ?? d.blueprint}
          <span className="block text-meta text-muted">
            {d.blueprint_source.Kind === 'device'
              ? t('devices.bp.device')
              : d.blueprint_source.Kind === 'group'
                ? t('devices.bp.group', { group: d.blueprint_source.Group, prio: d.blueprint_source.Priority })
                : t('devices.bp.default')}
          </span>
        </Fact>
        <Fact label={t('devices.fact.agent')}>
          <Link to="/devices" search={{ q: `agent:${d.agent_version}` }} className="font-mono hover:underline">
            {d.agent_version}
          </Link>
          {d.update_requested ? (
            <span className="block text-meta text-muted">{t('devices.agent.requested')}</span>
          ) : d.update_state ? (
            <span className="block text-meta text-muted">
              {d.update_version} {d.update_state}
            </span>
          ) : null}
        </Fact>
        <Fact label={t('devices.fact.tags')}>
          {d.tags.length
            ? d.tags.map((tag) => (
                <Link key={tag} to="/devices" search={{ q: `tag:${tag}` }} className="mr-1">
                  <Badge>#{tag}</Badge>
                </Link>
              ))
            : null}
        </Fact>
        <Fact label={t('devices.fact.signedIn')}>{(inv.logged_in_users ?? []).join(', ')}</Fact>
      </dl>
    </header>
  )
}

const protectiveKey: Record<string, MessageKey> = {
  lock: 'devices.prot.lock',
  unlock: 'devices.prot.unlock',
  lost: 'devices.prot.lost',
  found: 'devices.prot.found',
  wipe: 'devices.prot.wipe',
  allow_uninstall: 'devices.prot.uninstall',
}

type Notice = { level: 'security' | 'compliance' | 'info'; key: string; node: ReactNode }

/**
 * Protective notices in one place, security first, then compliance, then
 * information. The most important one shows; the rest fold behind a button.
 */
function Notices({ d }: { d: DeviceDetail }) {
  const t = useT()
  const audit = useCan('audit')
  const [all, setAll] = useState(false)
  const out: Notice[] = []
  const box = (tone: 'bad' | 'warn' | 'ok', key: string, children: ReactNode) =>
    out.push({
      level: tone === 'bad' ? 'security' : tone === 'warn' ? 'compliance' : 'info',
      key,
      node: (
        <div key={key} className={cx('flex flex-wrap items-center gap-2 rounded-lg border px-4 py-2.5 text-body', tone === 'bad' ? 'border-bad/30 bg-bad-soft' : tone === 'warn' ? 'border-warn/30 bg-warn-soft' : 'border-ok/30 bg-ok-soft')}>
          {children}
        </div>
      ),
    })
  for (const p of d.protective)
    box(
      protectiveAlarm(p.type) ? 'bad' : 'ok',
      `p-${p.type}`,
      <>
        <strong>{t(protectiveKey[p.type] ?? 'devices.prot.uninstall')}</strong>
        <span>{t('devices.prot.by', { by: p.by, at: dateTime(p.at) })}</span>
        <Badge tone={p.status === 'ok' ? 'ok' : p.status === 'failed' ? 'bad' : 'warn'}>{t(p.status === 'ok' ? 'devices.prot.done' : p.status === 'failed' ? 'devices.prot.failed' : 'devices.prot.waiting')}</Badge>
      </>,
    )
  if (d.tampered_at)
    box(
      'bad',
      'tamper',
      <>
        <ShieldAlert size={15} aria-hidden />
        <strong>{t('devices.notice.tamper')}</strong> {dateTime(d.tampered_at)}.{' '}
        {audit ? (
          <Link to="/activity" search={{ action: 'agent.tamper', target: d.id } as never}>
            {t('devices.notice.tamperAudit')}
          </Link>
        ) : (
          t('devices.notice.tamperAudit')
        )}
      </>,
    )
  if (d.auto_locked)
    box(
      'bad',
      'locked',
      <>
        <strong>{t('devices.notice.autoLocked')}</strong> {t('devices.notice.autoLockedBody')}
      </>,
    )
  if (d.failing_since)
    box(
      'warn',
      'grace',
      <>
        <CircleAlert size={15} aria-hidden />
        <span>
          {t('devices.notice.failingSince', { at: dateTime(d.failing_since) })}
          {d.grace_until && ' ' + t(d.status === 'in grace' ? 'devices.notice.graceEnds' : 'devices.notice.graceEnded', { at: dateTime(d.grace_until) })}{' '}
          {d.lock_at ? !d.auto_locked && t('devices.notice.lockAt', { at: dateTime(d.lock_at) }) : t('devices.notice.noLock')} {d.notify_on_grace && t('devices.notice.notify')}
        </span>
      </>,
    )
  if (!out.length) return null
  const list = orderNotices(out)
  const shown = all ? list : list.slice(0, 1)
  return (
    <section aria-label={t('devices.notices')} role="status" className="flex flex-col gap-2">
      {shown.map((n) => n.node)}
      {list.length > 1 && (
        <button type="button" className="btn btn-ghost self-start text-meta" aria-expanded={all} onClick={() => setAll(!all)}>
          {all ? <ChevronUp size={14} aria-hidden /> : <ChevronDown size={14} aria-hidden />}
          {all ? t('devices.notice.less') : t('devices.notice.more', { count: list.length - 1 })}
        </button>
      )}
    </section>
  )
}

function Health({ icon: I, label, value, tone, note }: { icon: typeof Cpu; label: string; value: ReactNode; tone: 'ok' | 'warn' | 'bad' | 'off'; note: ReactNode }) {
  return (
    <div className="card flex gap-3 p-[var(--pad-card)]">
      <span className={cx('grid size-9 shrink-0 place-items-center rounded-lg', { ok: 'bg-ok-soft text-ok', warn: 'bg-warn-soft text-warn', bad: 'bg-bad-soft text-bad', off: 'bg-off-soft text-off' }[tone])} aria-hidden>
        <I size={18} />
      </span>
      <div className="min-w-0">
        <div className="text-meta text-muted">{label}</div>
        <div className="font-semibold">{value}</div>
        <div className="truncate text-meta text-muted">{note}</div>
      </div>
    </div>
  )
}

type Check = { id: string; title?: string; level?: number; status: string; detail?: string; remediated?: boolean; refs?: { bsi?: string[]; iso?: string[]; cis?: string[] }; severity?: string }

function Overview({ d, open }: { d: DeviceDetail; open: (x: Dialog) => void }) {
  const t = useT()
  const inv = d.inventory
  const checks = d.check_results as Check[]
  const failing = checks.filter((c) => c.status === 'fail')
  const vols = inv.volumes ?? []
  const plain = vols.filter((v) => !v.encrypted && !d.encryption_exempt.includes(v.mount))
  const root = vols.find((v) => v.mount === '/')
  const [now] = useState(() => Date.now())
  const certDays = Math.round((new Date(d.cert_expires).getTime() - now) / 86_400_000)
  const newest = d.agent_versions[0]
  const canRec = useCan('commands')
  const upd = updatesHealth(checks)
  const fw = firewallHealth(checks, d.declarations)
  const conn = connectionState(d.last_seen, d.status)
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <div className="grid gap-[var(--gap)] sm:grid-cols-2 xl:grid-cols-4">
        <Health icon={ShieldCheck} label={t('devices.health.compliance')} value={t('devices.health.failing', { count: failing.length })} tone={failing.length ? 'bad' : checks.length ? 'ok' : 'off'} note={t('devices.health.evaluated', { count: checks.length })} />
        <Health
          icon={HardDrive}
          label={t('devices.health.encryption')}
          value={vols.length ? (plain.length ? t('devices.health.plain', { count: plain.length }) : t('devices.health.encrypted')) : '–'}
          tone={!vols.length ? 'off' : plain.length ? 'bad' : 'ok'}
          note={t('devices.health.keys', { count: d.recovery_keys.length })}
        />
        <Health
          icon={Bot}
          label={t('devices.health.agent')}
          value={<span className="font-mono">{d.agent_version}</span>}
          tone={!newest || newest === d.agent_version ? 'ok' : 'warn'}
          note={newest && newest !== d.agent_version ? t('devices.health.newer', { version: newest }) : t('devices.health.current')}
        />
        <Health icon={ShieldCheck} label={t('devices.health.cert')} value={dateShort(d.cert_expires)} tone={certDays < 14 ? 'warn' : 'ok'} note={t('devices.health.certDays', { count: certDays })} />
        <Health icon={Download} label={t('devices.health.updates')} value={t(`devices.health.upd.${upd.state}`)} tone={upd.tone} note={upd.detail ?? ''} />
        <Health icon={BrickWall} label={t('devices.health.firewall')} value={t(`devices.health.fw.${fw.state}`)} tone={fw.tone} note={t(fw.managed ? 'devices.health.fw.managed' : 'devices.health.fw.unmanaged')} />
        <Health
          icon={Wifi}
          label={t('devices.health.connection')}
          value={t(`devices.health.conn.${conn.state}`)}
          tone={conn.tone}
          note={[d.last_seen && t('devices.seen', { ago: ago(d.last_seen) }), d.external_ip, d.place].filter(Boolean).join(' · ')}
        />
      </div>
      <div className="grid gap-[var(--gap)] xl:grid-cols-3">
        <Card className="xl:col-span-2" title={t('devices.load.title')} sub={t('devices.load.sub')} id="dv-load">
          {d.metrics.length < 2 ? <EmptyState compact icon={Activity} title={t('devices.load.none')}>{t('devices.load.noneBody')}</EmptyState> : <LoadChart d={d} />}
        </Card>
        <Card title={t('devices.open.title')} id="dv-open">
          {root && (
            <div className="mb-4">
              <div className="mb-1.5 flex justify-between text-meta">
                <span className="text-muted">{t('devices.open.root')}</span>
                <span className="num">{t('devices.open.rootUse', { pct: usedPct(root.size_gb, root.free_gb), size: root.size_gb })}</span>
              </div>
              <div className="h-2 rounded-full bg-surface-2" role="meter" aria-valuenow={usedPct(root.size_gb, root.free_gb)} aria-valuemin={0} aria-valuemax={100} aria-label={t('devices.open.root')}>
                <div className={cx('h-2 rounded-full', usedPct(root.size_gb, root.free_gb) > 90 ? 'bg-bad' : usedPct(root.size_gb, root.free_gb) > 80 ? 'bg-warn-mark' : 'bg-accent')} style={{ width: `${usedPct(root.size_gb, root.free_gb)}%` }} />
              </div>
            </div>
          )}
          {failing.length ? (
            <ul className="flex flex-col gap-1.5 text-body">
              {failing.slice(0, 6).map((c) => (
                <li key={c.id} className="flex items-start gap-2">
                  <CircleAlert size={14} className="mt-0.5 shrink-0 text-bad" aria-hidden />
                  <span className="min-w-0">
                    <span className="block truncate">{c.title || c.id}</span>
                    {c.detail && <span className="block truncate text-meta text-muted">{c.detail}</span>}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState compact icon={CheckCircle2} title={t('devices.open.none')} />
          )}
        </Card>
      </div>
      <Card title={t('devices.sys.title')} id="dv-sys">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2 xl:grid-cols-4">
          {/* the operating system name is in the page header */}
          <Fact label={t('devices.sys.version')}>
            {inv.os_version} {inv.os_codename && <span className="text-muted">({inv.os_codename})</span>}
          </Fact>
          <Fact label={t('devices.sys.kernel')}>
            <span className="font-mono">{inv.kernel}</span>
          </Fact>
          <Fact label={t('devices.sys.arch')}>{inv.arch}</Fact>
          <Fact label={t('devices.sys.desktop')}>{inv.desktop ? `${inv.desktop}${inv.display_manager ? ` (${inv.display_manager})` : ''}` : t('devices.sys.noDesktop')}</Fact>
          <Fact label={t('devices.sys.memory')}>{inv.memory_mb ? `${fmt1(inv.memory_mb / 1024)} GiB` : ''}</Fact>
          <Fact label={t('devices.sys.cpu')}>{inv.cpu_threads ? t('devices.sys.cpuVal', { cores: inv.cpu_cores ?? 0, threads: inv.cpu_threads }) : ''}</Fact>
          <Fact label={t('devices.sys.recovery')}>
            {d.recovery_keys.length ? (
              <button type="button" className="text-accent hover:underline" onClick={() => open({ kind: 'recovery', uuid: d.recovery_keys[0].uuid, path: d.recovery_keys[0].device })} disabled={!canRec}>
                {t('devices.sys.recoveryVal', { count: d.recovery_keys.length })}
              </button>
            ) : (
              t('devices.sys.none')
            )}
          </Fact>
          <Fact label={t('devices.sys.booted')}>{inv.boot_time ? dateTime(inv.boot_time * 1000) : ''}</Fact>
          <Fact label={t('devices.sys.id')}>
            <span className="font-mono">{d.id}</span>
          </Fact>
          <Fact label={t('devices.sys.enrolled')}>{d.enrolled_at ? dateTime(d.enrolled_at) : ''}</Fact>
          <Fact label={t('devices.sys.cert')}>{t('devices.sys.certVal', { at: dateTime(d.cert_expires) })}</Fact>
          <Fact label={t('devices.sys.key')}>
            {d.tpm_bound ? <span title={`EK SHA-256 ${d.tpm_ek_sha256}`}>{t('devices.sys.keyTpm')}</span> : t('devices.sys.keyFile')}
          </Fact>
          <Fact label={t('devices.fact.inventory')}>{inv.source}</Fact>
        </dl>
      </Card>
    </div>
  )
}

function LoadChart({ d }: { d: DeviceDetail }) {
  const t = useT()
  const m = d.metrics
  const build = useCallback(
    (c: Colors) => ({
      ...baseOption(c),
      legend: { top: 0, textStyle: { color: c.muted } },
      xAxis: { type: 'time', ...axisX(c) },
      yAxis: [
        { type: 'value', max: 100, ...axisY(c, { axisLabel: { color: c.muted, formatter: '{value} %' } }) },
        { type: 'value', ...axisY(c, { splitLine: { show: false } }) },
      ],
      tooltip: { trigger: 'axis' },
      series: [
        { name: t('devices.load.mem'), type: 'line', showSymbol: false, data: m.map((p) => [p.at, Math.round(p.mem_pct)]), lineStyle: { color: c.s1 }, itemStyle: { color: c.s1 } },
        { name: t('devices.load.disk'), type: 'line', showSymbol: false, data: m.map((p) => [p.at, Math.round(p.root_pct)]), lineStyle: { color: c.s2, type: 'dashed' }, itemStyle: { color: c.s2 } },
        { name: t('devices.load.load'), type: 'line', yAxisIndex: 1, showSymbol: false, data: m.map((p) => [p.at, p.load1]), lineStyle: { color: c.s3, type: 'dotted' }, itemStyle: { color: c.s3 } },
      ],
    }),
    [m, t],
  )
  return (
    <ChartFrame
      caption={t('devices.load.title')}
      chart={<EChart build={build} height={240} label={t('devices.load.title')} />}
      table={{ head: [t('devices.load.time'), t('devices.load.mem'), t('devices.load.disk'), t('devices.load.load')], rows: m.map((p) => [dateTime(p.at), `${Math.round(p.mem_pct)} %`, `${Math.round(p.root_pct)} %`, fmt1(p.load1)]) }}
    />
  )
}

function Refs({ list }: { list?: string[] }) {
  return list?.length ? (
    <span className="flex flex-wrap gap-1">
      {list.map((r) => (
        <Badge key={r}>{r}</Badge>
      ))}
    </span>
  ) : (
    <span className="text-muted">–</span>
  )
}


function Compliance({ d }: { d: DeviceDetail }) {
  const t = useT()
  const checks = d.check_results as Check[]
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap justify-end gap-2">
        <Link className="btn" to="/compliance/exceptions" search={{ new: checks.find((c) => c.status === 'fail')?.id ?? '1' }}>
          {t('devices.comp.exception')}
        </Link>
        <a className="btn" href="/api/v1/exports/compliance.csv">
          <Download size={14} aria-hidden /> {t('devices.comp.evidence')}
        </a>
      </div>
      {!checks.length ? (
        <div className="card">
          <EmptyState icon={ShieldCheck} title={t('devices.comp.none')}>
            {t('devices.comp.noneBody')}
          </EmptyState>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-left text-body">
            <caption className="sr-only">{t('devices.tab.compliance')}</caption>
            <thead className="text-meta text-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">{t('devices.comp.status')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('devices.comp.check')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('devices.comp.level')}</th>
                <th scope="col" className="px-3 py-2 font-medium">{t('devices.comp.remediation')}</th>
                <th scope="col" className="px-3 py-2 font-medium">BSI</th>
                <th scope="col" className="px-3 py-2 font-medium">ISO 27001</th>
                <th scope="col" className="px-3 py-2 font-medium">CIS</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.id} className="border-t border-line align-top">
                  <td className="px-3 py-2">
                    <Badge tone={checkTone(c.status)}>{t(`devices.check.${c.status}` as MessageKey)}</Badge>
                    {c.remediated && <span className="mt-1 block text-meta text-ok">{t('devices.comp.remediated')}</span>}
                  </td>
                  <td className="px-3 py-2">
                    {c.title || c.id}
                    <span className="block font-mono text-micro text-muted">{c.id}</span>
                  </td>
                  <td className="px-3 py-2">{c.severity ? t(`devices.sev.${c.severity}` as MessageKey) : c.level ? `L${c.level}` : '–'}</td>
                  <td className="max-w-md px-3 py-2 text-muted">{c.detail || '–'}</td>
                  <td className="px-3 py-2">
                    <Refs list={c.refs?.bsi} />
                  </td>
                  <td className="px-3 py-2">
                    <Refs list={c.refs?.iso} />
                  </td>
                  <td className="px-3 py-2 text-meta text-muted">{c.refs?.cis?.join('; ') || '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

const declTone = (s: string) => (s === 'active' ? 'ok' : s === 'pending' ? 'warn' : 'bad')

function Config({ d }: { d: DeviceDetail }) {
  const t = useT()
  const certs = d.inventory.certificates ?? []
  const applied = d.blueprints.find((b) => b.applies)
  const bpLink = applied && (
    <Link className="btn" to="/config/blueprints/$id" params={{ id: String(applied.id) }}>
      {t('devices.cfg.openBlueprint', { name: applied.name })}
    </Link>
  )
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Card
        title={t('devices.cfg.resolved')}
        id="dv-res"
        sub={
          <span>
            {d.chain.map((b, i) => (
              <span key={b.id}>
                {i > 0 && ' → '}
                <Link to="/config/blueprints/$id" params={{ id: String(b.id) }}>
                  {b.name}
                </Link>
              </span>
            ))}
          </span>
        }
      >
        {d.items.length ? (
          <ol className="flex flex-col divide-y divide-line text-body">
            {d.items.map((it, i) => (
              <li key={it.id} className="flex items-center gap-3 py-1.5">
                <span className="num w-6 text-muted">{i + 1}</span>
                <Link to="/config/library/$id" params={{ id: String(it.id) }} className="flex-1 hover:underline">
                  {it.name}
                </Link>
                <span className="font-mono text-meta text-muted">{it.type}</span>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState compact icon={Layers} title={t('devices.cfg.noItems')} action={bpLink} />
        )}
      </Card>
      <Card title={t('devices.cfg.decls')} id="dv-decl">
        {d.declarations.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body">
              <thead className="text-meta text-muted">
                <tr>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.comp.status')}</th>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.cfg.identifier')}</th>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.cfg.type')}</th>
                  <th scope="col" className="py-1.5 font-medium">{t('devices.cfg.reasons')}</th>
                </tr>
              </thead>
              <tbody>
                {d.declarations.map((x) => (
                  <tr key={x.identifier} className="border-t border-line align-top">
                    <td className="py-1.5 pr-3">
                      <Badge tone={declTone(x.state)}>{t(`devices.decl.${x.state.replace(' ', '_')}` as MessageKey)}</Badge>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-meta">{x.identifier}</td>
                    <td className="py-1.5 pr-3 font-mono text-meta text-muted">{x.type}</td>
                    <td className="py-1.5 text-muted">{[...x.reasons, ...(x.info ?? [])].join('; ') || '–'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState compact icon={Layers} title={t('devices.cfg.noDecls')} action={bpLink} />
        )}
      </Card>
      <HostnameCard d={d} />
      {certs.length > 0 && (
        <Card title={t('devices.cfg.certs')} sub={t('devices.cfg.certsSub')} id="dv-certs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-body">
              <thead className="text-meta text-muted">
                <tr>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.cfg.name')}</th>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.cfg.subject')}</th>
                  <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.cfg.validUntil')}</th>
                  <th scope="col" className="py-1.5 font-medium">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {certs.map((c) => (
                  <tr key={c.sha256} className="border-t border-line">
                    <td className="py-1.5 pr-3">{c.name}</td>
                    <td className="py-1.5 pr-3 font-mono text-meta">{c.subject}</td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">{dateTime(c.not_after)}</td>
                    <td className="py-1.5 font-mono text-meta" title={c.sha256}>
                      {c.sha256.slice(0, 16)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
