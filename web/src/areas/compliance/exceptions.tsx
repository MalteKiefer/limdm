// Risk exceptions: active, expired and revoked ones, adding with reason,
// risk owner, approver (four eyes: another person), expiry and tag scope,
// revoking, and the CSV. The server applies the same rules (addException).
import { Link, useNavigate, useSearch } from '@tanstack/react-router'
import { Download, Plus, ShieldOff } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { useCan, useMe } from '../../api/me'
import { DataGrid, type GridColumn } from '../../components/datagrid'
import { Field } from '../../components/form'
import { TabBar } from '../../components/layout'
import { EmptyState, ErrorState, errorText, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { Modal, PageHeader } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { dateShort, dateTime } from '../../i18n/format'
import { useAddException, useCompliance, useExceptions, useRequestException, useRevokeException } from './api'
import { downloadExport } from '../../components/download'
import { checkException, countStates, exceptionPath, isoDay, type Exception, type ExceptionDraft } from './logic'
import { ExceptionBadge, SectionNav } from './parts'

type Tab = 'active' | 'expired' | 'revoked' | 'all'

export function ExceptionsPage() {
  const t = useT()
  const s = useSearch({ strict: false }) as { state?: string; new?: string }
  const navigate = useNavigate()
  const go = (patch: Record<string, string | undefined>) => void navigate({ to: '/compliance/exceptions', search: { ...s, ...patch } as never, replace: true })
  const admin = useCan('admin')
  const canExport = useCan('audit')
  const path = exceptionPath(useMe())
  const q = useExceptions()
  const [revoking, setRevoking] = useState<Exception>()
  const revoke = useRevokeException()
  const tab: Tab = (['expired', 'revoked', 'all'] as const).find((x) => x === s.state) ?? 'active'
  const counts = countStates(q.data ?? [])
  const list = useMemo(() => (q.data ?? []).filter((e) => tab === 'all' || e.state === tab), [q.data, tab])
  const columns = useMemo<GridColumn<Exception>[]>(
    () => [
      { id: 'check', header: t('compliance.exc.col.check'), cell: ({ row: { original: e } }) => <Link to="/compliance" search={{ sel: e.check_id } as never} className="font-mono text-[12.5px] hover:text-accent">{e.check_id}</Link> },
      { id: 'mode', header: t('compliance.exc.col.mode'), cell: ({ row: { original: e } }) => t(`compliance.exc.mode.${e.mode}` as MessageKey) },
      { id: 'scope', header: t('compliance.exc.col.scope'), cell: ({ row: { original: e } }) => (e.tag ? <Link to="/devices" search={{ q: `tag:${e.tag}` } as never} className="hover:text-accent">{e.tag}</Link> : t('compliance.exc.allDevices')) },
      {
        id: 'reason',
        header: t('compliance.exc.col.reason'),
        cell: ({ row: { original: e } }) => (
          <span className="flex min-w-0 flex-col">
            <span className="truncate" title={e.reason}>{e.reason}</span>
            <span className="truncate text-[11.5px] text-muted">{t('compliance.exc.by', { who: e.created_by ?? '', when: e.created_at ? dateTime(e.created_at) : '' })}</span>
          </span>
        ),
      },
      { id: 'owner', header: t('compliance.exc.col.owner'), cell: ({ row: { original: e } }) => e.owner },
      { id: 'approver', header: t('compliance.exc.col.approver'), cell: ({ row: { original: e } }) => e.approver },
      { id: 'expires', header: t('compliance.exc.col.expires'), cell: ({ row: { original: e } }) => <span className="num">{e.expires_at && dateShort(lastDay(e.expires_at))}</span> },
      { id: 'state', header: t('compliance.exc.col.state'), cell: ({ row: { original: e } }) => <ExceptionBadge state={e.state} /> },
      ...(admin
        ? [
            {
              id: 'actions',
              header: '',
              cell: ({ row: { original: e } }: { row: { original: Exception } }) =>
                e.state === 'active' && (
                  <button type="button" className="btn btn-ghost text-bad" onClick={(ev) => (ev.stopPropagation(), setRevoking(e))}>
                    {t('compliance.exc.revoke')}
                  </button>
                ),
            } as GridColumn<Exception>,
          ]
        : []),
    ],
    [t, admin],
  )
  return (
    <div className="flex flex-col">
      <PageHeader
        title={t('compliance.exc.title')}
        sub={t('compliance.exc.sub')}
        actions={
          <>
            {canExport && (
              <button type="button" className="btn" onClick={() => void downloadExport('exceptions.csv').catch((e) => toast(errorText(e), 'error'))}>
                <Download size={15} aria-hidden /> {t('compliance.exc.csv')}
              </button>
            )}
            {path && (
              <button type="button" className="btn btn-primary" onClick={() => go({ new: '1' })}>
                <Plus size={15} aria-hidden /> {t(path === 'direct' ? 'compliance.exc.add' : 'compliance.exc.request')}
              </button>
            )}
          </>
        }
      />
      <SectionNav />
      <p className="mb-[var(--gap)] max-w-3xl text-[13px] text-muted">{t('compliance.exc.explain')}</p>
      <TabBar
        label={t('compliance.exc.col.state')}
        value={tab}
        onChange={(v) => go({ state: v === 'active' ? undefined : v })}
        tabs={(['active', 'expired', 'revoked', 'all'] as const).map((v) => ({ value: v, label: t(`compliance.exc.state.${v}` as MessageKey), count: counts[v] }))}
      />
      {q.error ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : !q.data ? (
        <LoadingState />
      ) : (
        <DataGrid
          label={t('compliance.exc.title')}
          data={list}
          columns={columns}
          getRowId={(e) => String(e.id)}
          maxHeight="calc(100dvh - 320px)"
          empty={
            <div className="card">
              <EmptyState icon={ShieldOff} title={t('compliance.exc.none')} />
            </div>
          }
          card={(e) => (
            <span className="flex flex-col gap-0.5">
              <span className="flex items-center justify-between gap-2">
                <span className="font-mono text-[12.5px]">{e.check_id}</span>
                <ExceptionBadge state={e.state} />
              </span>
              <span className="truncate text-[12.5px] text-muted">{e.reason}</span>
            </span>
          )}
        />
      )}
      {path && s.new && <AddException key={s.new} request={path === 'request'} check={s.new === '1' ? '' : s.new} onClose={() => go({ new: undefined })} />}
      <Modal
        open={!!revoking}
        onClose={() => setRevoking(undefined)}
        title={t('compliance.exc.revokeTitle', { check: revoking?.check_id ?? '' })}
        description={t('compliance.exc.revokeBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setRevoking(undefined)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={revoke.isPending}
              onClick={() =>
                revoke.mutate(revoking!.id!, {
                  onSuccess: () => (toast(t('compliance.exc.revoked')), setRevoking(undefined)),
                  onError: (e) => toast(errorText(e), 'error'),
                })
              }
            >
              {t('compliance.exc.revoke')}
            </button>
          </>
        }
      />
    </div>
  )
}

/** The server stores the first day after the expiry; show the last valid day. */
const lastDay = (v: string) => new Date(new Date(v).getTime() - 1)

function AddException({ check, request, onClose }: { check: string; request: boolean; onClose: () => void }) {
  const t = useT()
  const me = useMe()
  const known = useCompliance().data?.checks
  const add = useAddException()
  const ask = useRequestException()
  // a scoped account asks for one of its own tags (the server checks it again)
  const scopeTags = me.role !== 'admin' ? me.scope_tags : []
  const [d, setD] = useState<ExceptionDraft>({ check_id: check, mode: 'exclude', tag: scopeTags[0] ?? '', reason: '', owner: '', approver: '', expires: '' })
  const [shown, setShown] = useState(false)
  const errs = checkException(d, { fourEyes: me.four_eyes, login: me.login, request })
  const err = (k: keyof ExceptionDraft) => (shown && errs[k] ? t(`compliance.exc.err.${errs[k]}` as MessageKey) : undefined)
  const set = (k: keyof ExceptionDraft) => (e: { target: { value: string } }) => setD({ ...d, [k]: e.target.value })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setShown(true)
    if (Object.keys(errs).length) return
    const body = { check_id: d.check_id.trim(), mode: d.mode as 'exclude' | 'advisory', tag: d.tag.trim(), reason: d.reason.trim(), owner: d.owner.trim(), expires: d.expires }
    const onError = (x: unknown) => toast(errorText(x), 'error')
    if (request) ask.mutate(body, { onSuccess: () => (toast(t('compliance.exc.requested', { check: body.check_id })), onClose()), onError })
    else add.mutate({ ...body, approver: d.approver.trim() }, { onSuccess: () => (toast(t('compliance.exc.added', { check: body.check_id })), onClose()), onError })
  }
  const today = new Date()
  const max = new Date(today.getFullYear() + 3, today.getMonth(), today.getDate())
  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={t(request ? 'compliance.exc.form.requestTitle' : 'compliance.exc.form.title')}
      description={t(request ? 'compliance.exc.form.requestSub' : 'compliance.exc.form.sub')}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="submit" form="exc-form" className="btn btn-primary" disabled={add.isPending || ask.isPending}>
            {t(request ? 'compliance.exc.form.requestSubmit' : 'compliance.exc.form.submit')}
          </button>
        </>
      }
    >
      <form id="exc-form" noValidate onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <Field label={t('compliance.exc.form.check')} help={t('compliance.exc.form.checkHelp')} error={err('check_id')} required>
          {({ id, describedBy, invalid }) => (
            <>
              <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field font-mono" list="exc-checks" spellCheck={false} value={d.check_id} onChange={set('check_id')} />
              <datalist id="exc-checks">
                {known?.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.title}
                  </option>
                ))}
              </datalist>
            </>
          )}
        </Field>
        <Field label={t('compliance.exc.form.mode')} help={t('compliance.exc.form.modeHelp')} error={err('mode')} required>
          {({ id, describedBy }) => (
            <select id={id} aria-describedby={describedBy} className="field" value={d.mode} onChange={set('mode')}>
              <option value="exclude">{t('compliance.exc.mode.exclude')}</option>
              <option value="advisory">{t('compliance.exc.mode.advisory')}</option>
            </select>
          )}
        </Field>
        <Field label={t('compliance.exc.form.tag')} help={t('compliance.exc.form.tagHelp')} error={err('tag')}>
          {({ id, describedBy, invalid }) =>
            scopeTags.length ? (
              <select id={id} aria-describedby={describedBy} className="field" value={d.tag} onChange={set('tag')}>
                {scopeTags.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
            ) : (
              <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" spellCheck={false} value={d.tag} onChange={set('tag')} />
            )
          }
        </Field>
        <Field label={t('compliance.exc.form.expires')} help={t('compliance.exc.form.expiresHelp')} error={err('expires')} required>
          {({ id, describedBy, invalid }) => <input id={id} type="date" aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" min={isoDay(today)} max={isoDay(max)} value={d.expires} onChange={set('expires')} />}
        </Field>
        <div className="md:col-span-2">
          <Field label={t('compliance.exc.form.reason')} error={err('reason')} required>
            {({ id, describedBy, invalid }) => <textarea id={id} rows={3} maxLength={1000} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" value={d.reason} onChange={set('reason')} />}
          </Field>
        </div>
        <Field label={t('compliance.exc.form.owner')} error={err('owner')} required>
          {({ id, describedBy, invalid }) => <input id={id} maxLength={200} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" value={d.owner} onChange={set('owner')} />}
        </Field>
        {!request && (
          <Field label={t('compliance.exc.form.approver')} help={me.four_eyes ? t('compliance.exc.form.approverFourEyes') : t('compliance.exc.form.approverHelp')} error={err('approver')} required>
            {({ id, describedBy, invalid }) => <input id={id} maxLength={200} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" value={d.approver} onChange={set('approver')} />}
          </Field>
        )}
      </form>
    </Modal>
  )
}
