// Settings section "Logs": retention on the server, disk guard, quotas,
// helpdesk access, the encrypted archive (target, retention, restore) and
// the archive keys. The state of the store and the archive is shown below.
import { Link } from '@tanstack/react-router'
import { Archive, KeyRound, RotateCcw, Upload } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../api/me'
import { FormSection } from '../../components/form'
import { Confirm, Facts, ListField, SectionHead, SelectField, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { ErrorState, errorText, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card } from '../../components/ui'
import { useT } from '../../i18n'
import { bytes, dateTime, fmt, fmt1 } from '../../i18n/format'
import { z } from '../../lib/zod'
import { useBackup, useSaveSection, useSettings } from '../settings/api'
import { restoreDay, rotateKeys, runArchive, useLogAction, useLogStatus } from './api'

const num = (lo: number, hi: number, msg: string) => z.string().refine((v) => /^\d+$/.test(v.trim()) && Number(v) >= lo && Number(v) <= hi, msg)

/** "2=500" lines to the tenant quota map; invalid lines are refused by the schema. */
const parseQuotas = (text: string) => Object.fromEntries(text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => l.split('=').map((x) => x.trim())).map(([k, v]) => [k, Number(v)]))
const quotasOK = (text: string) => text.split('\n').every((l) => !l.trim() || /^\s*\d+\s*=\s*\d+\s*$/.test(l))

export function LogSettings() {
  const t = useT()
  const q = useSettings()
  const backup = useBackup()
  const save = useSaveSection('logs' as never)
  const admin = useCan('admin')
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const l = q.data.logs
  const targets = backup.data?.targets.map((x) => x.name) ?? []
  const schema = z.object({
    retention_days: num(1, 90, t('logs.set.errRetention')),
    max_store_gb: num(0, 100000, t('logs.set.errNumber')),
    min_free_pct: num(0, 50, t('logs.set.errFree')),
    device_mb_per_day: num(1, 10240, t('logs.set.errDevice')),
    tenant_mb_per_day: num(0, 1048576, t('logs.set.errNumber')),
    tenant_quotas: z.string().refine(quotasOK, t('logs.set.errQuotas')),
    helpdesk_device_logs: z.boolean(),
    archive: z.boolean(),
    archive_target: z.string(),
    archive_retention_days: num(0, 3650, t('logs.set.errNumber')),
    restore_hours: num(1, 720, t('logs.set.errRestore')),
  })
  const values = {
    retention_days: String(l?.retention_days ?? 7),
    max_store_gb: String(l?.max_store_gb ?? 0),
    min_free_pct: String(l?.min_free_pct ?? 0),
    device_mb_per_day: String(l?.device_mb_per_day ?? 200),
    tenant_mb_per_day: String(l?.tenant_mb_per_day ?? 0),
    tenant_quotas: Object.entries(l?.tenant_quotas ?? {})
      .map(([k, v]) => `${k}=${v}`)
      .join('\n'),
    helpdesk_device_logs: !!l?.helpdesk_device_logs,
    archive: !!l?.archive,
    archive_target: l?.archive_target ?? '',
    archive_retention_days: String(l?.archive_retention_days ?? 0),
    restore_hours: String(l?.restore_hours ?? 24),
  }
  return (
    <>
      <SectionHead title={t('settings.nav.logs')} sub={t('logs.set.sub')} />
      <SettingsForm
        readOnly={!admin}
        schema={schema}
        values={values}
        onSave={(v) =>
          save.mutateAsync({
            logs: {
              retention_days: Number(v.retention_days),
              max_store_gb: Number(v.max_store_gb),
              min_free_pct: Number(v.min_free_pct),
              device_mb_per_day: Number(v.device_mb_per_day),
              tenant_mb_per_day: Number(v.tenant_mb_per_day),
              tenant_quotas: parseQuotas(v.tenant_quotas),
              helpdesk_device_logs: v.helpdesk_device_logs,
              archive: v.archive,
              archive_target: v.archive_target,
              archive_retention_days: Number(v.archive_retention_days),
              restore_hours: Number(v.restore_hours),
            },
          })
        }
      >
        {(f) => (
          <>
            <FormSection title={t('logs.set.server')} description={t('logs.set.serverHelp')}>
              <TextField form={f} name="retention_days" type="text" label={t('logs.set.retention')} help={t('logs.set.retentionHelp')} />
              <TextField form={f} name="max_store_gb" label={t('logs.set.maxStore')} help={t('logs.set.maxStoreHelp')} />
              <TextField form={f} name="min_free_pct" label={t('logs.set.minFree')} help={t('logs.set.minFreeHelp')} />
            </FormSection>
            <FormSection title={t('logs.set.quotas')} description={t('logs.set.quotasHelp')}>
              <TextField form={f} name="device_mb_per_day" label={t('logs.set.deviceMB')} />
              <TextField form={f} name="tenant_mb_per_day" label={t('logs.set.tenantMB')} help={t('logs.set.tenantMBHelp')} />
              <ListField form={f} name="tenant_quotas" label={t('logs.set.tenantQuotas')} help={t('logs.set.tenantQuotasHelp')} placeholder="2=500" />
            </FormSection>
            <FormSection title={t('logs.set.access')}>
              <Toggle form={f} name="helpdesk_device_logs" label={t('logs.set.helpdesk')} help={t('logs.set.helpdeskHelp')} />
            </FormSection>
            <FormSection title={t('logs.set.archive')} description={t('logs.set.archiveHelp')}>
              <Toggle form={f} name="archive" label={t('logs.set.archiveOn')} />
              <SelectField form={f} name="archive_target" label={t('logs.set.target')} help={t('logs.set.targetHelp')} options={[{ value: '', label: t('logs.set.noTarget') }, ...targets.map((n) => ({ value: n, label: n }))]} />
              <TextField form={f} name="archive_retention_days" label={t('logs.set.archiveRetention')} help={t('logs.set.archiveRetentionHelp')} />
              <TextField form={f} name="restore_hours" label={t('logs.set.restoreHours')} />
              <Link to="/settings" search={{ s: 'backup' } as never} className="text-body text-accent hover:underline">
                {t('logs.set.toTargets')}
              </Link>
            </FormSection>
          </>
        )}
      </SettingsForm>
      <Status archiveOn={!!l?.archive} />
    </>
  )
}

function Status({ archiveOn }: { archiveOn: boolean }) {
  const t = useT()
  const admin = useCan('admin')
  const st = useLogStatus()
  const rotate = useLogAction(rotateKeys)
  const run = useLogAction(runArchive)
  const restore = useLogAction(restoreDay)
  const [confirm, setConfirm] = useState<'rotate' | { day: string } | null>(null)
  if (st.error) return <ErrorState error={st.error} onRetry={() => void st.refetch()} />
  if (!st.data) return <LoadingState rows={4} />
  const d = st.data
  const days = [...new Set(d.archives.map((a) => a.day))]
  return (
    <div className="mt-6 flex flex-col gap-[var(--gap)]">
      <Card title={t('logs.st.title')}>
        {d.guard && (
          <p role="alert" className="mb-3 rounded-md bg-bad-soft p-3 text-body text-bad">
            {t('logs.st.guard', { reason: d.guard })}
          </p>
        )}
        <Facts
          rows={[
            [t('logs.st.store'), bytes(d.store_bytes)],
            [t('logs.st.free'), d.free_pct != null ? `${fmt1(d.free_pct)} %` : t('logs.st.freeUnknown')],
            [t('logs.st.today'), t('logs.st.todayVal', { devices: fmt(d.today.devices), lines: fmt(d.today.lines), size: bytes(d.today.bytes) })],
            [t('logs.st.dropped'), fmt(d.today.dropped)],
            [t('logs.st.days'), d.partitions.map((p) => p.day).filter(Boolean).length],
          ]}
        />
      </Card>
      <Card
        title={t('logs.st.keys')}
        sub={t('logs.st.keysSub')}
        action={
          admin && (
            <button type="button" className="btn" disabled={!d.keys.length} onClick={() => setConfirm('rotate')}>
              <KeyRound size={14} aria-hidden /> {t('logs.st.rotate')}
            </button>
          )
        }
      >
        {!d.keys.length ? (
          <p className="text-body text-muted">{t('logs.st.noKeys')}</p>
        ) : (
          <ul className="flex flex-col gap-1 text-meta">
            {d.keys.map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{k.id}</span>
                <span className="font-mono text-muted">{k.kek_id}</span>
                <span className="text-muted">{dateTime(k.created_at)}</span>
                {k.active ? <Badge tone="ok">{t('logs.st.active')}</Badge> : <Badge tone="off">{t('logs.st.retired')}</Badge>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card
        title={t('logs.st.archives')}
        sub={t('logs.st.archivesSub')}
        action={
          admin &&
          archiveOn && (
            <button type="button" className="btn" disabled={run.isPending} onClick={() => run.mutate(undefined, { onSuccess: () => toast(t('logs.st.runStarted')), onError: (e) => toast(errorText(e), 'error') })}>
              <Upload size={14} aria-hidden /> {t('logs.st.run')}
            </button>
          )
        }
      >
        {d.restores.length > 0 && (
          <p className="mb-2 text-meta text-muted">{d.restores.map((r) => t('logs.st.restored', { day: r.day, until: dateTime(r.until) })).join(' · ')}</p>
        )}
        {!days.length ? (
          <p className="text-body text-muted">{t('logs.st.noArchives')}</p>
        ) : (
          <ul className="flex max-h-80 flex-col divide-y divide-line overflow-auto">
            {days.map((day) => {
              const list = d.archives.filter((a) => a.day === day)
              return (
                <li key={day} className="flex flex-wrap items-center gap-3 py-2 text-meta">
                  <Archive size={14} aria-hidden className="text-muted" />
                  <span className="num font-mono">{day}</span>
                  <span>{t('logs.st.archiveVal', { lines: fmt(list.reduce((n, a) => n + a.lines, 0)), size: bytes(list.reduce((n, a) => n + a.bytes, 0)), tenants: list.length })}</span>
                  {list.every((a) => a.verified_at) ? <Badge tone="ok">{t('logs.st.verified')}</Badge> : <Badge tone="warn">{t('logs.st.unverified')}</Badge>}
                  {admin && (
                    <button type="button" className="btn ml-auto" onClick={() => setConfirm({ day })}>
                      <RotateCcw size={14} aria-hidden /> {t('logs.st.restore')}
                    </button>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </Card>
      <Confirm
        open={!!confirm}
        onClose={() => setConfirm(null)}
        title={confirm === 'rotate' ? t('logs.st.rotateTitle') : t('logs.st.restoreTitle', { day: typeof confirm === 'object' && confirm ? confirm.day : '' })}
        body={confirm === 'rotate' ? t('logs.st.rotateBody') : t('logs.st.restoreBody')}
        confirm={confirm === 'rotate' ? t('logs.st.rotate') : t('logs.st.restore')}
        busy={rotate.isPending || restore.isPending}
        onConfirm={() => {
          if (confirm === 'rotate')
            rotate.mutate(undefined, { onSuccess: () => (toast(t('logs.st.rotated')), setConfirm(null)), onError: (e) => toast(errorText(e), 'error') })
          else if (confirm)
            restore.mutate(confirm.day, {
              onSuccess: () => (toast(t('logs.st.restoreDone', { day: confirm.day })), setConfirm(null)),
              onError: (e) => toast(errorText(e), 'error'),
            })
        }}
      />
    </div>
  )
}
