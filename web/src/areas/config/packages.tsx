// Package repository: upload with progress, the uploads of the tenant with
// usage and approval state, quota use, delete (refused while a library item
// uses it), and the limits and store for global administrators.
import { Link } from '@tanstack/react-router'
import { FilePlus2, Package, Trash2, Upload, X } from 'lucide-react'
import { useRef, useState } from 'react'
import { useCan } from '../../api/me'
import { Bullet } from '../../components/charts'
import { Field } from '../../components/form'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal, Segmented } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { ago, bytes, dateTime, fmt } from '../../i18n/format'
import { uploadPackage, usePackageActions, usePackages, useRefresh, type Package as Pkg, type PackageConfig } from './api'

export function PackagesTab() {
  const t = useT()
  const q = usePackages()
  const admin = useCan('admin')
  const acts = usePackageActions()
  const [del, setDel] = useState<Pkg>()
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  if (!q.data) return <LoadingState rows={6} />
  const d = q.data
  const quota = d.config.quota_mb * 1024 * 1024
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <div className="grid gap-[var(--gap)] lg:grid-cols-[minmax(0,1fr)_360px]">
        {admin ? <UploadCard kinds={d.kinds} limitMB={d.config.max_upload_mb} fourEyes={d.four_eyes} /> : <div />}
        <Card title={t('config.quota')}>
          <Bullet value={quota ? (d.used_bytes / quota) * 100 : 0} target={100} label={t('config.quotaUse')} />
          <p className="mt-2 text-[13px]">{t('config.quotaLine', { used: bytes(d.used_bytes), quota: bytes(quota), files: fmt(d.used_count), max: fmt(d.config.quota_count) })}</p>
          <p className="text-[12.5px] text-muted">{t('config.uploadLimit', { mb: fmt(d.config.max_upload_mb) })} · {t(d.config.store === 's3' ? 'config.storeS3' : 'config.storeLocal')}</p>
        </Card>
      </div>
      <Card title={t('config.uploads')} sub={t('config.uploadsSub')} bodyClass="!px-0 !py-0">
        {!d.items.length ? (
          <EmptyState icon={Package} title={t('config.noUploads')}>
            {t('config.noUploadsBody')}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left">
              <caption className="sr-only">{t('config.uploads')}</caption>
              <thead className="text-[12px] text-muted">
                <tr className="border-b border-line">
                  <th className="px-[var(--pad-card)] py-2 font-medium">{t('config.package')}</th>
                  <th className="font-medium">{t('config.kind')}</th>
                  <th className="num font-medium">{t('config.size')}</th>
                  <th className="font-medium">{t('config.usage')}</th>
                  <th className="font-medium">{t('config.uploaded')}</th>
                  <th className="pr-[var(--pad-card)]">
                    <span className="sr-only">{t('config.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((p) => (
                  <tr key={p.id} className="row-h border-b border-line align-top last:border-0">
                    <td className="px-[var(--pad-card)] py-2">
                      <div className="font-medium">
                        {p.name} <span className="font-mono text-[12px] text-muted">{p.version}</span>
                      </div>
                      <div className="font-mono text-[11.5px] break-all text-muted" title={p.sha256}>
                        {p.filename} · {p.sha256.slice(0, 16)}
                      </div>
                      {!p.approved_by && <Badge tone="warn">{t('config.awaitsApproval')}</Badge>}
                    </td>
                    <td className="py-2">
                      <Badge>{p.kind}</Badge>
                    </td>
                    <td className="num py-2">{bytes(p.size)}</td>
                    <td className="py-2 text-[12.5px]">{p.usage.length ? p.usage.join(', ') : <span className="text-muted">{t('config.unused')}</span>}</td>
                    <td className="py-2 text-[12.5px] text-muted" title={dateTime(p.created_at)}>
                      {p.uploaded_by} · {ago(p.created_at)}
                    </td>
                    <td className="py-2 pr-[var(--pad-card)] text-right whitespace-nowrap">
                      {admin && p.approved_by && (
                        <Link to="/config/library/$id" params={{ id: 'new' }} search={{ type: d.type, from: p.sha256 }} className="btn !h-7 px-2 text-[12.5px]">
                          <FilePlus2 size={13} aria-hidden /> {t('config.useInItem')}
                        </Link>
                      )}{' '}
                      {admin && (
                        <button type="button" className="btn btn-ghost !h-7 px-2 text-bad" disabled={p.usage.length > 0} aria-label={t('config.deletePackage', { name: p.name })} title={p.usage.length ? t('config.stillUsed') : undefined} onClick={() => setDel(p)}>
                          <Trash2 size={14} aria-hidden />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {admin && d.global && <StoreSettings cfg={d.config} />}
      <Modal
        open={!!del}
        onClose={() => setDel(undefined)}
        title={t('config.deletePackage', { name: del?.name ?? '' })}
        description={t('config.deletePackageBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setDel(undefined)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={acts.remove.isPending}
              onClick={() =>
                acts.remove.mutate(del!.id, {
                  onSuccess: () => toast(t('config.deletedToast', { name: del!.name })),
                  onError: (e) => toast(errorText(e), 'error'),
                  onSettled: () => setDel(undefined),
                })
              }
            >
              {t('common.delete')}
            </button>
          </>
        }
      />
    </div>
  )
}

function UploadCard({ kinds, limitMB, fourEyes }: { kinds: string[]; limitMB: number; fourEyes: boolean }) {
  const t = useT()
  const refresh = useRefresh()
  const [name, setName] = useState('')
  const [version, setVersion] = useState('')
  const [kind, setKind] = useState(kinds[0] ?? 'deb')
  const [reason, setReason] = useState('')
  const [file, setFile] = useState<File>()
  const [progress, setProgress] = useState<number>()
  const [err, setErr] = useState<string>()
  const abort = useRef<AbortController>(undefined)
  const tooBig = !!file && file.size > limitMB * 1024 * 1024
  const nameOk = /^[A-Za-z0-9._+-]{1,100}$/.test(name)
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!file || !nameOk || tooBig) return
    const form = new FormData()
    form.set('name', name)
    form.set('version', version)
    form.set('kind', kind)
    form.set('reason', reason)
    form.set('file', file)
    abort.current = new AbortController()
    setErr(undefined)
    setProgress(0)
    uploadPackage(form, setProgress, abort.current.signal).then(
      (r) => {
        toast(t(r.status === 'pending' ? 'config.uploadPending' : 'config.uploadDone', { name }))
        setFile(undefined)
        setName('')
        setVersion('')
        setReason('')
        setProgress(undefined)
        void refresh()
      },
      (e: unknown) => {
        setProgress(undefined)
        if (!(e instanceof DOMException)) setErr(errorText(e))
      },
    )
  }
  return (
    <Card title={t('config.upload')} sub={t('config.uploadSub', { mb: fmt(limitMB) })}>
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-2" noValidate>
        <Field label={t('config.file')} required error={tooBig ? t('config.tooBig', { mb: fmt(limitMB) }) : undefined}>
          {({ id, describedBy, invalid }) => (
            <input
              id={id}
              type="file"
              aria-describedby={describedBy}
              aria-invalid={invalid || undefined}
              className="field !h-auto py-1.5"
              onChange={(e) => {
                const f = e.target.files?.[0]
                setFile(f)
                if (f && !name) setName(f.name.replace(/\.(deb|rpm|apk|flatpak|sh|pkg\.tar\.(zst|xz))$/, '').replace(/[^A-Za-z0-9._+-]/g, '-').slice(0, 100))
                const ext = f?.name.match(/\.(deb|rpm|apk|flatpak|sh)$/)?.[1]
                if (ext) setKind(ext === 'sh' ? 'script' : ext)
              }}
            />
          )}
        </Field>
        <Field label={t('config.kind')}>
          {({ id }) => (
            <select id={id} className="field" value={kind} onChange={(e) => setKind(e.target.value)}>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {t(`config.kindName.${k}` as MessageKey)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('config.name')} required help={t('config.pkgNameHelp')} error={name && !nameOk ? t('config.pkgNameHelp') : undefined}>
          {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field font-mono" value={name} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Field label={t('config.version')}>{({ id }) => <input id={id} className="field font-mono" maxLength={64} value={version} onChange={(e) => setVersion(e.target.value)} />}</Field>
        {fourEyes && (
          <div className="md:col-span-2">
            <Field label={t('config.reason')} help={t('config.reasonHelp')}>
              {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} className="field" maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} />}
            </Field>
          </div>
        )}
        {err && (
          <p role="alert" className="rounded-lg bg-bad-soft p-3 text-[13px] text-bad md:col-span-2">
            {err}
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3 md:col-span-2">
          {progress !== undefined ? (
            <>
              <progress className="h-2 flex-1" max={1} value={progress} aria-label={t('config.uploading')} />
              <span className="num text-[12.5px]" aria-live="polite">
                {Math.round(progress * 100)} %
              </span>
              <button type="button" className="btn" onClick={() => abort.current?.abort()}>
                <X size={14} aria-hidden /> {t('common.cancel')}
              </button>
            </>
          ) : (
            <button type="submit" className="btn btn-primary" disabled={!file || !nameOk || tooBig}>
              <Upload size={14} aria-hidden /> {t('config.uploadBtn')}
            </button>
          )}
          {fourEyes && <span className="text-[12.5px] text-muted">{t('config.uploadFourEyes')}</span>}
        </div>
      </form>
    </Card>
  )
}

function StoreSettings({ cfg }: { cfg: PackageConfig }) {
  const t = useT()
  const acts = usePackageActions()
  const [c, setC] = useState<PackageConfig>({ ...cfg, s3: cfg.s3 ?? { endpoint: '', region: '', bucket: '', prefix: '', access_key: '', path_style: false } })
  const [err, setErr] = useState<string>()
  const num = (k: 'max_upload_mb' | 'quota_mb' | 'quota_count', label: string, help: string) => (
    <Field label={label} help={help}>
      {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} type="number" min={1} className="field num max-w-[180px]" value={c[k]} onChange={(e) => setC({ ...c, [k]: Number(e.target.value) })} />}
    </Field>
  )
  const s3 = (k: 'endpoint' | 'region' | 'bucket' | 'prefix' | 'access_key' | 'secret', label: string, secret = false) => (
    <Field label={label} help={secret ? t('config.secretKeep') : undefined}>
      {({ id, describedBy }) => <input id={id} aria-describedby={describedBy} type={secret ? 'password' : 'text'} autoComplete={secret ? 'new-password' : 'off'} className="field font-mono" value={String(c.s3?.[k] ?? '')} onChange={(e) => setC({ ...c, s3: { ...c.s3!, [k]: e.target.value } })} />}
    </Field>
  )
  return (
    <Card title={t('config.storeTitle')} sub={t('config.storeSub')}>
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault()
          setErr(undefined)
          acts.settings.mutate({ ...c, s3: c.store === 's3' ? c.s3 : undefined }, { onSuccess: () => toast(t('config.settingsSaved')), onError: (e) => setErr(errorText(e)) })
        }}
      >
        <div className="grid gap-4 md:grid-cols-3">
          {num('max_upload_mb', t('config.maxUpload'), t('config.maxUploadHelp'))}
          {num('quota_mb', t('config.quotaMB'), t('config.quotaMBHelp'))}
          {num('quota_count', t('config.quotaCount'), t('config.quotaCountHelp'))}
        </div>
        <Segmented
          label={t('config.store')}
          value={c.store}
          onChange={(v) => setC({ ...c, store: v })}
          options={[
            { value: 'local', label: t('config.storeLocal') },
            { value: 's3', label: t('config.storeS3') },
          ]}
        />
        {c.store === 's3' && (
          <div className="grid gap-4 md:grid-cols-2">
            {s3('endpoint', t('config.s3Endpoint'))}
            {s3('region', t('config.s3Region'))}
            {s3('bucket', t('config.s3Bucket'))}
            {s3('prefix', t('config.s3Prefix'))}
            {s3('access_key', t('config.s3Access'))}
            {s3('secret', t('config.s3Secret'), true)}
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" checked={!!c.s3?.path_style} onChange={(e) => setC({ ...c, s3: { ...c.s3!, path_style: e.target.checked } })} /> {t('config.s3PathStyle')}
            </label>
          </div>
        )}
        <p className="text-[12.5px] text-muted">{t('config.storeMoveNote')}</p>
        {err && (
          <p role="alert" className="rounded-lg bg-bad-soft p-3 text-[13px] text-bad">
            {err}
          </p>
        )}
        <button type="submit" className="btn btn-primary w-fit" disabled={acts.settings.isPending}>
          {t('common.save')}
        </button>
      </form>
    </Card>
  )
}
