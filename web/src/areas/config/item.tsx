// Library item editor: a form from the type's JSON Schema (or JSON for
// experts, same state), validated at the field, with the live review of
// the change on the right (devices, expected effect, diff), versions with
// rollback, and four eyes for root effective types.
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { ArrowLeft, BookOpen, Braces, ExternalLink, FormInput, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ApiError } from '../../api/client'
import { useCan, useMe } from '../../api/me'
import { Field } from '../../components/form'
import { JsonEditor, parseJSON } from '../../components/jsoneditor'
import { TabBar } from '../../components/layout'
import { SchemaForm, validate } from '../../components/schemaform'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Modal, PageHeader, Segmented } from '../../components/ui'
import { useT } from '../../i18n'
import { previewItem, useDeleteItem, useTemplate, useLibrary, usePackages, useSaveItem, useSchema, useTypes, type ItemInput } from './api'
import { Impact, PreviewDiff, Versions } from './components'
import { ScriptRuns, TemplatePreview, usesTemplate } from './templates'
import { usePreview } from './usePreview'

type Obj = Record<string, unknown>
const pretty = (v: unknown) => JSON.stringify(v ?? {}, null, 2)

export function LibraryItemPage() {
  const { id } = useParams({ strict: false }) as { id: string }
  const s = useSearch({ strict: false }) as { view?: string; type?: string; from?: string; device?: string; file?: string; remote?: string; inst?: string; mode?: string }
  const t = useT()
  const nav = useNavigate()
  const lib = useLibrary()
  const isNew = id === 'new'
  const pkgs = usePackages(isNew && !!s.from)
  // any other new item starts from the example of its type or what a device reported (?device=&file= or &remote=&inst=, mode)
  const tpl = useTemplate(isNew && !s.from && !!(s.type || s.device), { type: s.type, device: s.device, file: s.file, remote: s.remote, inst: s.inst, mode: s.mode })
  const num = isNew ? undefined : Number(id)
  const stored = lib.data?.items.find((i) => i.id === num)
  const view = s.view === 'versions' && num ? 'versions' : 'edit'
  if (lib.error) return <ErrorState error={lib.error} onRetry={() => void lib.refetch()} />
  if (tpl.error) return <ErrorState error={tpl.error} />
  if (!lib.data || pkgs.isLoading || tpl.isLoading) return <LoadingState rows={8} />
  // a new uploaded packages item from the package list: prefilled with that upload
  const upload = isNew ? pkgs.data?.items.find((x) => x.sha256 === s.from) : undefined
  const prefill =
    upload && s.type === pkgs.data?.type
      ? { name: upload.name, payload: { artifacts: [{ sha256: upload.sha256, name: upload.name, kind: upload.kind, size: upload.size }] } }
      : tpl.data
        ? { name: tpl.data.name, description: tpl.data.description, payload: tpl.data.payload as Obj }
        : undefined
  const deleted = !isNew && !stored ? lib.data.deleted.find((d) => d.id === num) : undefined
  if (!isNew && !stored && !deleted) return <EmptyState title={t('state.notFoundTitle')}>{t('state.notFoundBody')}</EmptyState>
  return (
    <div className="pb-24">
      <Link to="/config" search={{ tab: 'library' }} className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {t('config.tabLibrary')}
      </Link>
      {num && (
        <TabBar
          idBase="item"
          label={t('config.itemViews')}
          value={deleted ? 'versions' : view}
          onChange={(v) => void nav({ to: '/config/library/$id', params: { id }, search: { view: v === 'edit' ? undefined : v }, replace: true })}
          tabs={deleted ? [{ value: 'versions', label: t('config.versions') }] : [{ value: 'edit', label: t('config.editTab') }, { value: 'versions', label: t('config.versions') }]}
        />
      )}
      {deleted || view === 'versions' ? (
        <>
          <PageHeader title={stored?.name ?? deleted?.name ?? ''} sub={t('config.versionsSub')} />
          <Versions kind="library" id={num!} />
        </>
      ) : (
        <ItemEditor key={id} stored={stored} type={stored?.type ?? tpl.data?.type ?? s.type ?? ''} prefill={prefill} />
      )}
    </div>
  )
}

function ItemEditor({ stored, type, prefill }: { stored?: ItemInput & { used_by: string[]; read_only: boolean; invalid: boolean }; type: string; prefill?: { name: string; description?: string; payload: Obj } }) {
  const t = useT()
  const nav = useNavigate()
  const me = useMe()
  const admin = useCan('admin')
  const schema = useSchema(type)
  const types = useTypes()
  const info = types.data?.find((x) => x.type === type)
  const save = useSaveItem()
  const del = useDeleteItem()
  const readOnly = !admin || !!stored?.read_only
  const initial = useMemo(() => ({ name: stored?.name ?? '', description: stored?.description ?? '', payload: (stored?.payload ?? {}) as Obj }), [stored])
  const [name, setName] = useState(prefill?.name ?? initial.name)
  const [desc, setDesc] = useState(prefill?.description ?? initial.description)
  const [payload, setPayload] = useState<Obj>(prefill?.payload ?? initial.payload)
  const [mode, setMode] = useState<'form' | 'json'>('form')
  const [json, setJson] = useState(pretty(prefill?.payload ?? initial.payload))
  const [panel, setPanel] = useState<'impact' | 'diff'>('impact')
  const [serverErr, setServerErr] = useState<{ field?: string; msg: string }>()
  const [confirmDelete, setConfirmDelete] = useState(false)

  const errors = useMemo(() => (schema.data ? validate(schema.data, payload) : {}), [schema.data, payload])
  const jsonState = parseJSON(json)
  const dirty = name !== initial.name || desc !== initial.description || pretty(payload) !== pretty(initial.payload)
  const errCount = Object.keys(errors).length + (mode === 'json' && !jsonState.ok ? 1 : 0) + (name.trim() ? 0 : 1)
  const input: ItemInput | undefined = dirty && !errCount && !readOnly ? ({ id: stored?.id, name: name.trim(), type, description: desc.trim(), payload } as ItemInput) : undefined
  const preview = usePreview(input, previewItem)
  const fourEyes = !!info?.four_eyes && me.four_eyes

  if (schema.error) return <ErrorState error={schema.error} />
  if (!schema.data) return <LoadingState rows={8} />

  const switchMode = (m: 'form' | 'json') => {
    if (m === 'json') {
      setJson(pretty(payload))
      setMode('json')
    } else if (jsonState.ok && typeof jsonState.value === 'object' && jsonState.value) {
      setPayload(jsonState.value as Obj)
      setMode('form')
    } else toast(t('config.jsonFirst'), 'error')
  }
  const discard = () => {
    setName(initial.name)
    setDesc(initial.description)
    setPayload(initial.payload)
    setJson(pretty(initial.payload))
    setServerErr(undefined)
  }
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input) return
    setServerErr(undefined)
    save.mutate(input, {
      onSuccess: (r) => {
        toast(t(r.pending ? 'config.pendingToast' : 'config.savedToast', { name: input.name }))
        if (r.pending) void nav({ to: '/config', search: { tab: 'library' } })
        else if (!stored && r.id) void nav({ to: '/config/library/$id', params: { id: String(r.id) }, replace: true })
      },
      onError: (err) => {
        const field = err instanceof ApiError ? err.problem.field : undefined
        setServerErr({ field, msg: errorText(err) })
        toast(errorText(err), 'error')
      },
    })
  }

  return (
    <form onSubmit={submit} noValidate>
      <PageHeader
        title={stored?.name || t('config.newOf', { type: info?.title ?? type })}
        sub={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[12.5px]">{type}</span>
            {info && <span>{info.title}</span>}
            {fourEyes && <Badge tone="info">{t('config.fourEyes')}</Badge>}
            {stored?.read_only && <Badge tone="info">{t('config.sharedReadOnly')}</Badge>}
            {stored?.invalid && <Badge tone="bad">{t('config.sigInvalidSave')}</Badge>}
            {stored && <span className="text-muted">{stored.used_by.length ? t('config.usedBy', { list: stored.used_by.join(', ') }) : t('config.unused')}</span>}
          </span>
        }
        actions={
          <>
            {info?.doc && (
              <a href={info.doc} target="_blank" rel="noreferrer noopener" className="btn btn-ghost">
                <BookOpen size={14} aria-hidden /> {t('config.docs')} <ExternalLink size={12} aria-hidden />
              </a>
            )}
            <Segmented
              label={t('config.editMode')}
              value={mode}
              onChange={switchMode}
              options={[
                { value: 'form', label: t('config.modeForm') },
                { value: 'json', label: t('config.modeJson') },
              ]}
            />
          </>
        }
      />
      {info && <p className="-mt-2 mb-[var(--gap)] text-[13px] text-muted">{info.description}</p>}
      <div className="grid gap-[var(--gap)] xl:grid-cols-[minmax(0,1fr)_400px]">
        <fieldset disabled={readOnly} className="flex min-w-0 flex-col gap-[var(--gap)]">
          <legend className="sr-only">{t('config.itemSettings')}</legend>
          <div className="card grid gap-4 p-[var(--pad-card)] md:grid-cols-2">
            <Field label={t('config.name')} required error={!name.trim() ? t('schema.required') : serverErr?.field === 'name' ? serverErr.msg : undefined}>
              {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} aria-required className="field" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />}
            </Field>
            <Field label={t('config.description')}>{({ id }) => <input id={id} className="field" maxLength={300} value={desc} onChange={(e) => setDesc(e.target.value)} />}</Field>
          </div>
          {serverErr && serverErr.field !== 'name' && (
            <p role="alert" className="rounded-lg bg-bad-soft p-3 text-[13px] text-bad">
              {serverErr.msg}
            </p>
          )}
          {mode === 'form' ? (
            <SchemaForm schema={schema.data} value={payload} onChange={setPayload} errors={errors} idPrefix="item" />
          ) : (
            <div className="card p-[var(--pad-card)]">
              <p className="mb-2 text-[12.5px] text-muted">{t('config.jsonHelp')}</p>
              <JsonEditor
                value={json}
                label={t('config.jsonLabel')}
                readOnly={readOnly}
                onChange={(text, parsed) => {
                  setJson(text)
                  if (parsed && typeof parsed === 'object') setPayload(parsed as Obj)
                }}
              />
            </div>
          )}
        </fieldset>
        <aside className="flex flex-col gap-[var(--gap)] xl:sticky xl:top-[72px] xl:self-start" aria-label={t('config.review')}>
          <div className="card">
            <div className="flex border-b border-line px-2" role="tablist" aria-label={t('config.review')}>
              {(['impact', 'diff'] as const).map((p) => (
                <button key={p} type="button" role="tab" aria-selected={panel === p} onClick={() => setPanel(p)} className={`-mb-px border-b-2 px-3 py-2.5 font-medium ${panel === p ? 'border-accent' : 'border-transparent text-muted hover:text-fg'}`}>
                  {t(p === 'impact' ? 'config.impactTab' : 'config.diffTab')}
                </button>
              ))}
            </div>
            <div className="p-[var(--pad-card)]" role="tabpanel">
              {panel === 'impact' ? <Impact preview={preview.data} busy={preview.busy} error={preview.error} /> : <PreviewDiff preview={preview.data} />}
            </div>
          </div>
          {admin && usesTemplate(type, payload) && <TemplatePreview type={type} payload={payload} />}
          {stored && type === 'com.limdm.scripts' && <ScriptRuns payload={stored.payload as Obj} />}
          {stored && admin && !stored.read_only && (
            <div className="card p-[var(--pad-card)]">
              <h2 className="font-semibold">{t('config.deleteItem')}</h2>
              <p className="mb-3 text-[12.5px] text-muted">{stored.used_by.length ? t('config.deleteUsed') : t('config.deleteHint')}</p>
              <button type="button" className="btn text-bad" disabled={stored.used_by.length > 0} onClick={() => setConfirmDelete(true)}>
                <Trash2 size={14} aria-hidden /> {t('common.delete')}
              </button>
            </div>
          )}
        </aside>
      </div>
      {!readOnly && (
        <div className="fixed inset-x-0 bottom-0 z-20 border-t border-line bg-surface/95 backdrop-blur lg:left-[var(--sb,244px)]" role="region" aria-label={t('form.unsaved')}>
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-3 px-4 py-2.5 lg:px-6">
            <span className="text-[13px] text-muted" aria-live="polite">
              {errCount ? <span className="font-medium text-bad">{t('config.errors', { count: errCount })}</span> : dirty ? t('form.unsaved') : t('config.noChanges')}
            </span>
            <div className="ml-auto flex gap-2">
              <button type="button" className="btn" disabled={!dirty} onClick={discard}>
                {t('form.discard')}
              </button>
              <button type="submit" className="btn btn-primary" disabled={!dirty || errCount > 0 || save.isPending}>
                {mode === 'json' ? <Braces size={14} aria-hidden /> : <FormInput size={14} aria-hidden />} {t(fourEyes ? 'config.submitApproval' : 'common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title={t('config.deleteItemTitle', { name: stored?.name ?? '' })}
        description={t('config.deleteItemBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setConfirmDelete(false)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={del.isPending}
              onClick={() =>
                del.mutate(stored!.id!, {
                  onSuccess: () => {
                    toast(t('config.deletedToast', { name: stored!.name }))
                    void nav({ to: '/config', search: { tab: 'library' } })
                  },
                  onError: (e) => toast(errorText(e), 'error'),
                })
              }
            >
              {t('common.delete')}
            </button>
          </>
        }
      />
    </form>
  )
}
