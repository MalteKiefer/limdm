// Add device: create an enrollment token, then install the agent with the
// one line command or distribute enroll.conf; active tokens with revoke.
import { Link } from '@tanstack/react-router'
import { ArrowLeft, Copy, KeyRound, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Card, Modal, PageHeader } from '../../components/ui'
import { useT } from '../../i18n'
import { dateTime, fmt } from '../../i18n/format'
import { useBlueprintList, useEnrollment, useTokenCreate, useTokenRevoke } from './api'
import { enrollConf, installCommand } from './enrolltext'

function CopyBlock({ id, text, label }: { id: string; text: string; label: string }) {
  const t = useT()
  return (
    <div className="flex items-start gap-2">
      <pre id={id} aria-label={label} className="min-w-0 flex-1 overflow-x-auto rounded-md bg-surface-2 p-3 font-mono text-[12.5px]">
        {text}
      </pre>
      <button type="button" className="btn shrink-0" aria-label={t('devices.copyWhat', { what: label })} onClick={() => void navigator.clipboard?.writeText(text).then(() => toast(t('devices.copied')))}>
        <Copy size={14} aria-hidden /> {t('devices.copy')}
      </button>
    </div>
  )
}

export function EnrollPage() {
  const t = useT()
  const admin = useCan('admin')
  const info = useEnrollment()
  const create = useTokenCreate()
  const revoke = useTokenRevoke()
  const bps = useBlueprintList(admin)
  const [note, setNote] = useState('')
  const [bp, setBp] = useState('0')
  const [uses, setUses] = useState('1')
  const [days, setDays] = useState('7')
  const [token, setToken] = useState('')
  const [err, setErr] = useState<string>()
  const [revoking, setRevoking] = useState<string | null>(null)
  if (info.error) return <ErrorState error={info.error} onRetry={() => void info.refetch()} />
  if (!info.data) return <LoadingState rows={6} />
  const i = info.data
  const shown = token || '<token>'
  const badUses = !(Number(uses) >= 1 && Number(uses) <= 10000)
  const badDays = !(Number(days) >= 1 && Number(days) <= 90)
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <Link to="/devices" className="inline-flex w-fit items-center gap-1 text-[13px] text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {t('devices.title')}
      </Link>
      <PageHeader title={t('devices.enroll.title')} sub={t('devices.enroll.sub')} />
      {token && (
        <div role="status" className="flex flex-col gap-2 rounded-lg border border-ok/30 bg-ok-soft p-4">
          <strong>{t('devices.enroll.created')}</strong>
          <CopyBlock id="tok-created" text={token} label={t('devices.enroll.token')} />
        </div>
      )}
      <div className="grid gap-[var(--gap)] xl:grid-cols-[1fr_380px]">
        <div className="flex flex-col gap-[var(--gap)]">
          <Card title={t('devices.enroll.single')} sub={t('devices.enroll.singleSub', { repo: i.release_repo })} id="en-single">
            <CopyBlock id="tok-install" text={installCommand(i.public_url, shown)} label={t('devices.enroll.single')} />
          </Card>
          <Card title={t('devices.enroll.mass')} sub={t('devices.enroll.massSub')} id="en-mass">
            <div className="flex flex-col gap-3">
              <CopyBlock id="tok-conf" text={enrollConf(i.agent_url, i.fingerprint, shown)} label="enroll.conf" />
              <CopyBlock id="tok-mass" text={installCommand(i.public_url)} label={t('devices.enroll.mass')} />
              <p className="text-[12.5px] text-muted">{t('devices.enroll.other')}</p>
            </div>
          </Card>
          <Card title={t('devices.enroll.active')} id="en-active">
            {i.items.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13px]">
                  <caption className="sr-only">{t('devices.enroll.active')}</caption>
                  <thead className="text-[12px] text-muted">
                    <tr>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.enroll.note')}</th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.edit.blueprint')}</th>
                      <th scope="col" className="py-1.5 pr-3 text-right font-medium">{t('devices.enroll.usesLeft')}</th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.enroll.expires')}</th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('devices.enroll.by')}</th>
                      {admin && <th scope="col" />}
                    </tr>
                  </thead>
                  <tbody>
                    {i.items.map((k) => (
                      <tr key={k.id} className="border-t border-line">
                        <td className="py-1.5 pr-3">{k.note || '–'}</td>
                        <td className="py-1.5 pr-3">{k.blueprint}</td>
                        <td className="num py-1.5 pr-3 text-right">{fmt(k.uses_left)}</td>
                        <td className="py-1.5 pr-3 whitespace-nowrap">{dateTime(k.expires_at)}</td>
                        <td className="py-1.5 pr-3">{k.created_by}</td>
                        {admin && (
                          <td className="py-1.5 text-right">
                            <button type="button" className="btn btn-ghost !h-7 text-[12.5px]" onClick={() => setRevoking(k.id)}>
                              <Trash2 size={13} aria-hidden /> {t('devices.enroll.revoke')}
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState icon={KeyRound} title={t('devices.enroll.none')}>
                {t('devices.enroll.noneBody')}
              </EmptyState>
            )}
          </Card>
        </div>
        <div className="flex flex-col gap-[var(--gap)]">
          <Card title={t('devices.enroll.endpoint')} id="en-ep">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
              <dt className="text-muted">URL</dt>
              <dd className="font-mono break-all">{i.agent_url}</dd>
              <dt className="text-muted">{t('devices.enroll.transport')}</dt>
              <dd>{t('devices.enroll.mtls')}</dd>
            </dl>
            <p className="mt-3 mb-2 text-[12.5px] text-muted">{t('devices.enroll.fingerprint')}</p>
            <CopyBlock id="tok-fp" text={i.fingerprint} label={t('devices.enroll.fingerprintLabel')} />
          </Card>
          {admin && (
            <Card title={t('devices.enroll.new')} id="en-new">
              <form
                className="flex flex-col gap-4"
                onSubmit={(e) => {
                  e.preventDefault()
                  setErr(undefined)
                  create.mutate(
                    { note, blueprint_id: Number(bp), uses: Number(uses), days: Number(days) },
                    { onSuccess: (r) => (setToken((r as { token: string }).token), setNote('')), onError: (er) => setErr(errorText(er)) },
                  )
                }}
              >
                {err && (
                  <p role="alert" className="text-[13px] font-medium text-bad">
                    {err}
                  </p>
                )}
                <Field label={t('devices.enroll.note')}>{({ id }) => <input id={id} className="field" value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} placeholder={t('devices.enroll.notePlaceholder')} />}</Field>
                <Field label={t('devices.edit.blueprint')}>
                  {({ id }) => (
                    <select id={id} className="field" value={bp} onChange={(e) => setBp(e.target.value)}>
                      <option value="0">{t('devices.enroll.defaultOnly')}</option>
                      {(bps.data ?? [])
                        .filter((b) => b.name !== 'default')
                        .map((b) => (
                          <option key={b.id} value={b.id}>
                            {b.name}
                          </option>
                        ))}
                    </select>
                  )}
                </Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field label={t('devices.enroll.uses')} error={badUses ? t('devices.enroll.usesRange') : undefined}>
                    {({ id, describedBy, invalid }) => <input id={id} type="number" min={1} max={10000} className="field" aria-describedby={describedBy} aria-invalid={invalid || undefined} value={uses} onChange={(e) => setUses(e.target.value)} />}
                  </Field>
                  <Field label={t('devices.enroll.days')} error={badDays ? t('devices.enroll.daysRange') : undefined}>
                    {({ id, describedBy, invalid }) => <input id={id} type="number" min={1} max={90} className="field" aria-describedby={describedBy} aria-invalid={invalid || undefined} value={days} onChange={(e) => setDays(e.target.value)} />}
                  </Field>
                </div>
                <button type="submit" className="btn btn-primary" disabled={create.isPending || badUses || badDays}>
                  {t('devices.enroll.create')}
                </button>
              </form>
            </Card>
          )}
        </div>
      </div>
      {revoking && (
        <Modal
          open
          onClose={() => setRevoking(null)}
          title={t('devices.enroll.revoke')}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setRevoking(null)}>
                {t('common.cancel')}
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={revoke.isPending}
                onClick={() => revoke.mutate(revoking, { onSuccess: () => (toast(t('devices.enroll.revoked')), setRevoking(null)), onError: (e) => toast(errorText(e), 'error') })}
              >
                {t('devices.enroll.revoke')}
              </button>
            </>
          }
        >
          <p>{t('devices.enroll.revokeConfirm')}</p>
        </Modal>
      )}
    </div>
  )
}
