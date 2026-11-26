// The updates tab of the device page: the device's update ring, the last
// run per source, pending updates with versions, and the rollback actions
// (hold a package, downgrade it: Debian family and dnf, four eyes).
import { Link } from '@tanstack/react-router'
import { Lock, LockOpen, PackageCheck, Undo2 } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { Confirm } from '../../components/settingsform'
import { EmptyState, ErrorState, LoadingState } from '../../components/states'
import { Badge, Card } from '../../components/ui'
import { useT } from '../../i18n'
import { dateTime } from '../../i18n/format'
import { useDeviceUpdates } from '../updates/api'
import { sortPending } from '../updates/logic'
import { mono, RunBadge, SecurityTag, SourceLabel, Table } from '../updates/parts'
import { useRun } from './actions'
import type { DeviceDetail } from './api'

export function UpdatesTab({ d }: { d: DeviceDetail }) {
  const t = useT()
  const admin = useCan('admin')
  const u = useDeviceUpdates(d.id)
  const run = useRun({ id: d.id, hostname: d.hostname, detail: d })
  const [act, setAct] = useState<{
    kind: 'hold' | 'release' | 'downgrade'
    name: string
  } | null>(null)
  const [name, setName] = useState('')
  const [version, setVersion] = useState('')
  if (u.error) return <ErrorState error={u.error} onRetry={() => void u.refetch()} />
  if (!u.data) return <LoadingState rows={6} />
  const { ring, status, reports } = u.data
  const pending = sortPending(status?.pending ?? [])
  const fourEyes = d.four_eyes_commands.includes('package_downgrade')
  const os = pending.filter((p) => p.source !== 'flatpak' && !p.patch)
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <div className="grid gap-[var(--gap)] lg:grid-cols-2">
        <Card title={t('updates.dev.ring')}>
          {ring ? (
            <div className="flex flex-col gap-1">
              <div className="font-medium">
                {ring.name} {ring.paused ? <Badge tone="warn">{t('updates.ring.paused')}</Badge> : <Badge tone="ok">{t('updates.ring.active')}</Badge>}
              </div>
              <div className="text-[12.5px] text-muted">{ring.wave ? t('updates.ring.waveN', { wave: ring.wave }) + (ring.wave_at ? ` · ${dateTime(ring.wave_at)}` : '') : t('updates.ring.noWave')}</div>
            </div>
          ) : (
            <p className="text-muted">{t('updates.dev.noRing')}</p>
          )}
          <Link to="/updates" className="mt-2 inline-flex text-[13px] text-accent hover:underline">
            {t('updates.dev.toRings')}
          </Link>
        </Card>
        <Card title={t('updates.dev.summary')}>
          {reports ? (
            <ul className="flex flex-col gap-1 text-[13px]">
              <li>{t('updates.dev.pendingN', { count: os.length })}</li>
              <li>
                {t('updates.dev.securityN', {
                  count: os.filter((p) => p.security).length + pending.filter((p) => p.patch).length,
                })}
              </li>
              {status?.security_since && (
                <li className="text-bad">
                  {t('updates.dev.since', {
                    at: dateTime(status.security_since),
                  })}
                </li>
              )}
              {status?.pending_error && <li className="text-bad">{t('updates.dev.error', { error: status.pending_error })}</li>}
            </ul>
          ) : (
            <p className="text-muted">{t('updates.dev.noReport')}</p>
          )}
        </Card>
      </div>
      <Card title={t('updates.dev.runs')} sub={t('updates.dev.runsSub')}>
        <Table
          caption={t('updates.dev.runs')}
          cols={[{ label: t('updates.sourceCol') }, { label: t('updates.dev.at') }, { label: t('updates.dev.result') }, { label: t('updates.dev.detail') }]}
          rows={(status?.runs ?? []).map((r) => ({
            key: r.source!,
            cells: [
              <SourceLabel source={r.source} />,
              r.at ? dateTime(r.at) : '',
              <span>
                <RunBadge result={r.result} /> {r.count ? t('updates.dev.count', { count: r.count }) : ''}
              </span>,
              <span className="font-mono text-[12px] break-all whitespace-pre-wrap text-muted">{r.detail}</span>,
            ],
          }))}
          empty={t('updates.dev.noRuns')}
        />
      </Card>
      <Card title={t('updates.dev.pending')} sub={t('updates.dev.pendingSub')}>
        {pending.length ? (
          <Table
            caption={t('updates.dev.pending')}
            cols={[
              { label: t('updates.package') },
              { label: t('updates.dev.current') },
              { label: t('updates.dev.candidate') },
              { label: t('updates.sourceCol') },
              { label: t('updates.security') },
              { label: 'CVE' },
              ...(admin ? [{ label: '' }] : []),
            ]}
            rows={pending.map((p) => ({
              key: `${p.name}-${p.source}-${p.patch ? 'patch' : ''}`,
              cells: [
                <span>
                  {mono(p.name)} {p.patch && <Badge>{t('updates.dev.patch')}</Badge>}
                </span>,
                mono(p.current),
                mono(p.candidate),
                <span>
                  <SourceLabel source={p.source} /> {p.origin && <span className="text-[12px] text-muted">({p.origin})</span>}
                </span>,
                <SecurityTag security={p.security} severity={p.severity} />,
                <span className="font-mono text-[12px]">{(p.cves ?? []).join(', ')}</span>,
                ...(admin
                  ? [
                      p.source === 'flatpak' || p.patch ? (
                        ''
                      ) : (
                        <button type="button" className="btn btn-ghost" aria-label={`${t('updates.dev.hold')}: ${p.name}`} title={t('updates.dev.hold')} onClick={() => setAct({ kind: 'hold', name: p.name! })}>
                          <Lock size={14} aria-hidden />
                        </button>
                      ),
                    ]
                  : []),
              ],
            }))}
            empty=""
          />
        ) : (
          <EmptyState icon={PackageCheck} title={t('updates.dev.none')}>
            {reports ? t('updates.dev.noneBody') : t('updates.dev.noReport')}
          </EmptyState>
        )}
      </Card>
      {admin && (
        <Card title={t('updates.dev.rollback')} sub={t('updates.dev.rollbackSub')}>
          <div className="flex flex-wrap items-end gap-2">
            <Field label={t('updates.package')}>{({ id }) => <input id={id} className="field font-mono" value={name} onChange={(e) => setName(e.target.value)} />}</Field>
            <Field label={t('updates.version')} help={t('updates.dev.versionHelp')}>
              {({ id, describedBy }) => <input id={id} className="field font-mono" aria-describedby={describedBy} value={version} onChange={(e) => setVersion(e.target.value)} />}
            </Field>
            <button type="button" className="btn" disabled={!name.trim()} onClick={() => setAct({ kind: 'hold', name: name.trim() })}>
              <Lock size={14} aria-hidden /> {t('updates.dev.hold')}
            </button>
            <button type="button" className="btn" disabled={!name.trim()} onClick={() => setAct({ kind: 'release', name: name.trim() })}>
              <LockOpen size={14} aria-hidden /> {t('updates.dev.release')}
            </button>
            <button type="button" className="btn btn-danger" disabled={!name.trim()} onClick={() => setAct({ kind: 'downgrade', name: name.trim() })}>
              <Undo2 size={14} aria-hidden /> {t('updates.dev.downgrade')}
            </button>
          </div>
        </Card>
      )}
      <Confirm
        open={act?.kind === 'hold' || act?.kind === 'release'}
        onClose={() => setAct(null)}
        title={t(act?.kind === 'release' ? 'updates.dev.releaseTitle' : 'updates.dev.holdTitle', { name: act?.name ?? '' })}
        body={t(act?.kind === 'release' ? 'updates.dev.releaseBody' : 'updates.dev.holdBody')}
        confirm={act?.kind === 'release' ? t('updates.dev.release') : t('updates.dev.hold')}
        busy={run.pending}
        onConfirm={() =>
          act &&
          run.run(
            'package_hold',
            {
              name: act.name,
              ...(act.kind === 'release' ? { release: true } : {}),
            },
            () => setAct(null),
          )
        }
      />
      <Confirm
        open={act?.kind === 'downgrade'}
        onClose={() => setAct(null)}
        title={t('updates.dev.downgradeTitle', { name: act?.name ?? '' })}
        body={version.trim() ? t('updates.dev.downgradeTo', { version: version.trim() }) : t('updates.dev.downgradeBody')}
        confirm={t('updates.dev.downgrade')}
        danger
        reason={fourEyes}
        busy={run.pending}
        onConfirm={(reason) =>
          act &&
          run.run(
            'package_downgrade',
            {
              name: act.name,
              version: version.trim(),
              ...(reason ? { reason } : {}),
            },
            () => setAct(null),
          )
        }
      />
    </div>
  )
}
