// Blueprint editor: name, parent, the assignment map as a visual tree
// (items, conditions with branches and else), the inherited maps of the
// parents read only, the live review (devices, items added or removed,
// diff), rollout to all or to pilot devices first, versions and delete.
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router'
import { ArrowDown, ArrowLeft, ArrowUp, Braces, FlaskConical, GitBranch, ListTree, Plus, SplitSquareVertical, Trash2, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ApiError } from '../../api/client'
import { useCan } from '../../api/me'
import { Field } from '../../components/form'
import { JsonEditor } from '../../components/jsoneditor'
import { TabBar } from '../../components/layout'
import { EmptyState, ErrorState, LoadingState, errorText } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, Modal, PageHeader, Segmented } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { cx } from '../../lib/cx'
import { previewBlueprint, useBlueprints, useDeleteBlueprint, useLibrary, usePilot, useSaveBlueprint, type BlueprintRow, type LibraryRow, type Node } from './api'
import { Impact, PreviewDiff, Versions } from './components'
import { move, newAssign, newIf, newRule, noValue, removeAt, replaceAt, treeProblems, type Branch, type Rule } from './tree'
import { usePreview } from './usePreview'

export function BlueprintPage() {
  const { id } = useParams({ strict: false }) as { id: string }
  const s = useSearch({ strict: false }) as { view?: string }
  const t = useT()
  const nav = useNavigate()
  const bps = useBlueprints()
  const lib = useLibrary()
  const isNew = id === 'new'
  const num = isNew ? undefined : Number(id)
  if (bps.error || lib.error) return <ErrorState error={bps.error ?? lib.error} onRetry={() => void Promise.all([bps.refetch(), lib.refetch()])} />
  if (!bps.data || !lib.data) return <LoadingState rows={8} />
  const stored = bps.data.items.find((b) => b.id === num)
  const deleted = !isNew && !stored ? bps.data.deleted.find((d) => d.id === num) : undefined
  if (!isNew && !stored && !deleted) return <EmptyState title={t('state.notFoundTitle')}>{t('state.notFoundBody')}</EmptyState>
  const view = deleted ? 'versions' : s.view === 'versions' && num ? 'versions' : 'edit'
  return (
    <div className="pb-24">
      <Link to="/config" className="mb-3 inline-flex items-center gap-1 text-body text-muted hover:text-fg">
        <ArrowLeft size={14} aria-hidden /> {t('config.tabBlueprints')}
      </Link>
      {num && (
        <TabBar
          idBase="bp"
          label={t('config.itemViews')}
          value={view}
          onChange={(v) => void nav({ to: '/config/blueprints/$id', params: { id }, search: { view: v === 'edit' ? undefined : v }, replace: true })}
          tabs={deleted ? [{ value: 'versions', label: t('config.versions') }] : [{ value: 'edit', label: t('config.editTab') }, { value: 'versions', label: t('config.versions') }]}
        />
      )}
      {view === 'versions' ? (
        <>
          <PageHeader title={stored?.name ?? deleted?.name ?? ''} sub={t('config.versionsSub')} />
          <Versions kind="blueprints" id={num!} />
        </>
      ) : (
        <BlueprintEditor key={id} stored={stored} all={bps.data.items} items={lib.data.items} fields={bps.data.rule_fields} />
      )}
    </div>
  )
}

type Ctx = { items: LibraryRow[]; fields: Record<string, string[]>; problems: Record<string, string>; readOnly: boolean }

function BlueprintEditor({ stored, all, items, fields }: { stored?: BlueprintRow; all: BlueprintRow[]; items: LibraryRow[]; fields: Record<string, string[]> }) {
  const t = useT()
  const nav = useNavigate()
  const admin = useCan('admin')
  const save = useSaveBlueprint()
  const del = useDeleteBlueprint()
  const pilot = usePilot()
  const readOnly = !admin || !!stored?.read_only || !!stored?.pilot_of
  const def = all.find((b) => b.name === 'default')
  const initial = useMemo(
    () => ({ name: stored?.name ?? '', description: stored?.description ?? '', parent: stored ? (stored.parent_id ?? 0) : (def?.id ?? 0), tree: (stored?.tree ?? []) as Node[] }),
    [stored, def],
  )
  const [name, setName] = useState(initial.name)
  const [desc, setDesc] = useState(initial.description)
  const [parent, setParent] = useState<number>(initial.parent)
  const [tree, setTree] = useState<Node[]>(initial.tree)
  const [mode, setMode] = useState<'tree' | 'json'>('tree')
  const [json, setJson] = useState(JSON.stringify(initial.tree, null, 2))
  const [panel, setPanel] = useState<'impact' | 'diff'>('impact')
  const [rollout, setRollout] = useState<'all' | 'pilot'>('all')
  const [pilotPick, setPilotPick] = useState<string[]>()
  const [serverErr, setServerErr] = useState<string>()
  const [confirm, setConfirm] = useState<'delete' | 'promote' | 'abort'>()
  const isDefault = stored?.name === 'default'

  const problems = useMemo(() => treeProblems(tree, fields), [tree, fields])
  const dirty = name !== initial.name || desc !== initial.description || parent !== initial.parent || JSON.stringify(tree) !== JSON.stringify(initial.tree)
  const nameOk = /^[A-Za-z0-9._-]{1,64}$/.test(name)
  const errCount = Object.keys(problems).length + (nameOk ? 0 : 1)
  const body = { name, description: desc, parent_id: parent || null, tree }
  const preview = usePreview(dirty && !errCount && !readOnly ? { id: stored?.id, ...body } : undefined, previewBlueprint)
  const sample = preview.data?.sample ?? []
  const picked = pilotPick ?? sample.slice(0, Math.max(1, Math.round(sample.length * 0.1))).map((d) => d.id)
  const canPilot = !!stored && !stored.pilot && !isDefault && sample.length > 0 && parent === initial.parent && name === initial.name

  // the inherited maps: parents, root first
  const chain: BlueprintRow[] = []
  for (let p = all.find((b) => b.id === parent), n = 0; p && n < 10; p = all.find((b) => b.id === p!.parent_id), n++) chain.unshift(p)

  const discard = () => {
    setName(initial.name)
    setDesc(initial.description)
    setParent(initial.parent)
    setTree(initial.tree)
    setJson(JSON.stringify(initial.tree, null, 2))
    setServerErr(undefined)
  }
  const fail = (err: unknown) => {
    setServerErr(errorText(err))
    toast(errorText(err), 'error')
  }
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!dirty || errCount) return
    setServerErr(undefined)
    if (rollout === 'pilot' && canPilot) {
      pilot.start.mutate({ id: stored!.id!, tree, devices: picked }, { onSuccess: () => toast(t('config.pilotStarted', { count: picked.length })), onError: fail })
      return
    }
    save.mutate(
      { id: stored?.id, ...body },
      {
        onSuccess: (r) => {
          toast(t('config.savedToast', { name }))
          if (!stored && r.id) void nav({ to: '/config/blueprints/$id', params: { id: String(r.id) }, replace: true })
        },
        onError: (err) => (err instanceof ApiError && err.status === 412 ? fail(new Error(t('config.conflict'))) : fail(err)),
      },
    )
  }
  const ctx: Ctx = { items, fields, problems, readOnly }

  return (
    <form onSubmit={submit} noValidate>
      <PageHeader
        title={stored?.name || t('config.newBlueprint')}
        sub={
          <span className="flex flex-wrap items-center gap-2">
            {stored && t('config.devicesN', { count: stored.devices })}
            {stored?.read_only && <Badge tone="info">{t('config.sharedReadOnly')}</Badge>}
            {!!stored?.pilot_of && <Badge tone="warn">{t('config.pilotCopyNote')}</Badge>}
          </span>
        }
        actions={
          <Segmented
            label={t('config.editMode')}
            value={mode}
            onChange={(m) => {
              if (m === 'json') setJson(JSON.stringify(tree, null, 2))
              setMode(m)
            }}
            options={[
              { value: 'tree', label: t('config.modeTree') },
              { value: 'json', label: t('config.modeJson') },
            ]}
          />
        }
      />
      {stored?.pilot && (
        <div className="mb-[var(--gap)] flex flex-wrap items-center gap-3 rounded-lg border border-warn/40 bg-warn-soft p-3 text-body" role="status">
          <FlaskConical size={16} aria-hidden />
          <span className="flex-1">{t('config.pilotBanner', { count: stored.pilot.devices.length, by: stored.pilot.by })}</span>
          {admin && (
            <>
              <button type="button" className="btn" onClick={() => setConfirm('abort')}>
                {t('config.pilotAbort')}
              </button>
              <button type="button" className="btn btn-primary" onClick={() => setConfirm('promote')}>
                {t('config.pilotPromote')}
              </button>
            </>
          )}
        </div>
      )}
      <div className="grid gap-[var(--gap)] xl:grid-cols-[minmax(0,1fr)_400px]">
        <fieldset disabled={readOnly} className="flex min-w-0 flex-col gap-[var(--gap)]">
          <legend className="sr-only">{t('config.bpSettings')}</legend>
          <div className="card grid gap-4 p-[var(--pad-card)] md:grid-cols-2">
            <Field label={t('config.name')} required help={t('config.nameHelp')} error={nameOk ? undefined : t('config.nameInvalid')}>
              {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} aria-required className="field font-mono" readOnly={isDefault} value={name} onChange={(e) => setName(e.target.value)} />}
            </Field>
            <Field label={t('config.parent')} help={t('config.parentHelp')}>
              {({ id, describedBy }) => (
                <select id={id} aria-describedby={describedBy} className="field" disabled={isDefault} value={parent} onChange={(e) => setParent(Number(e.target.value))}>
                  <option value={0}>{t('config.noParent')}</option>
                  {all
                    .filter((b) => b.id !== stored?.id && !b.pilot_of)
                    .map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name}
                      </option>
                    ))}
                </select>
              )}
            </Field>
            <div className="md:col-span-2">
              <Field label={t('config.description')}>{({ id }) => <input id={id} className="field" maxLength={300} value={desc} onChange={(e) => setDesc(e.target.value)} />}</Field>
            </div>
          </div>
          {serverErr && (
            <p role="alert" className="rounded-lg bg-bad-soft p-3 text-body text-bad">
              {serverErr}
            </p>
          )}
          {chain.length > 0 && (
            <Card title={t('config.inherited')} sub={t('config.inheritedSub')}>
              <ol className="flex flex-col gap-3">
                {chain.map((p) => (
                  <li key={p.id}>
                    <div className="mb-1 flex items-center gap-2 text-body font-medium">
                      <GitBranch size={14} className="text-muted" aria-hidden />
                      <Link to="/config/blueprints/$id" params={{ id: String(p.id) }} className="hover:text-accent">
                        {p.name}
                      </Link>
                    </div>
                    <TreeSummary nodes={(p.tree ?? []) as Node[]} items={items} />
                  </li>
                ))}
              </ol>
            </Card>
          )}
          <Card title={t('config.map')} sub={t('config.mapSub')}>
            {mode === 'tree' ? (
              <NodeList nodes={tree} onChange={setTree} ctx={ctx} path="tree" depth={0} />
            ) : (
              <JsonEditor
                value={json}
                label={t('config.mapJson')}
                readOnly={readOnly}
                onChange={(text, parsed) => {
                  setJson(text)
                  if (Array.isArray(parsed)) setTree(parsed as Node[])
                }}
              />
            )}
          </Card>
        </fieldset>
        <aside className="flex flex-col gap-[var(--gap)] xl:sticky xl:top-[72px] xl:self-start" aria-label={t('config.review')}>
          <div className="card">
            <div className="flex border-b border-line px-2" role="tablist" aria-label={t('config.review')}>
              {(['impact', 'diff'] as const).map((p) => (
                <button key={p} type="button" role="tab" aria-selected={panel === p} onClick={() => setPanel(p)} className={cx('-mb-px border-b-2 px-3 py-2.5 font-medium', panel === p ? 'border-accent' : 'border-transparent text-muted hover:text-fg')}>
                  {t(p === 'impact' ? 'config.impactTab' : 'config.diffTab')}
                </button>
              ))}
            </div>
            <div className="flex flex-col gap-4 p-[var(--pad-card)]" role="tabpanel">
              {panel === 'impact' ? <Impact preview={preview.data} busy={preview.busy} error={preview.error} /> : <PreviewDiff preview={preview.data} />}
              {panel === 'impact' && canPilot && dirty && !errCount && (
                <div className="flex flex-col gap-1.5">
                  <span className="text-body font-medium">{t('config.rollout')}</span>
                  <Segmented
                    label={t('config.rollout')}
                    value={rollout}
                    onChange={setRollout}
                    options={[
                      { value: 'all', label: t('config.rolloutAll') },
                      { value: 'pilot', label: t('config.rolloutPilot', { count: picked.length }) },
                    ]}
                  />
                  <p className="text-meta text-muted">{t(rollout === 'pilot' ? 'config.rolloutPilotHelp' : 'config.rolloutAllHelp')}</p>
                  {rollout === 'pilot' && (
                    <fieldset className="flex flex-col gap-1">
                      <legend className="mb-1 text-meta font-medium">{t('config.pilotDevices')}</legend>
                      {sample.map((d) => (
                        <label key={d.id} className="flex items-center gap-2 font-mono text-meta">
                          <input type="checkbox" checked={picked.includes(d.id)} onChange={(e) => setPilotPick(e.target.checked ? [...picked, d.id] : picked.filter((x) => x !== d.id))} />
                          {d.hostname}
                        </label>
                      ))}
                    </fieldset>
                  )}
                </div>
              )}
            </div>
          </div>
          {stored?.deletable && admin && (
            <div className="card p-[var(--pad-card)]">
              <h2 className="font-semibold">{t('config.deleteBlueprint')}</h2>
              <p className="mb-3 text-meta text-muted">{t('config.deleteBlueprintHint')}</p>
              <button type="button" className="btn text-bad" onClick={() => setConfirm('delete')}>
                <Trash2 size={14} aria-hidden /> {t('common.delete')}
              </button>
            </div>
          )}
        </aside>
      </div>
      {!readOnly && (
        <div className="fixed inset-x-0 bottom-0 z-20 border-t border-line bg-surface/95 backdrop-blur lg:left-[var(--sb,244px)]" role="region" aria-label={t('form.unsaved')}>
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-3 px-4 py-2.5 lg:px-6">
            <span className="text-body text-muted" aria-live="polite">
              {errCount ? <span className="font-medium text-bad">{t('config.errors', { count: errCount })}</span> : dirty ? t('form.unsaved') : t('config.noChanges')}
            </span>
            <div className="ml-auto flex gap-2">
              <button type="button" className="btn" disabled={!dirty} onClick={discard}>
                {t('form.discard')}
              </button>
              <button type="submit" className="btn btn-primary" disabled={!dirty || errCount > 0 || save.isPending || pilot.start.isPending || (rollout === 'pilot' && canPilot && !picked.length)}>
                {t(rollout === 'pilot' && canPilot ? 'config.startPilot' : 'common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
      <Modal
        open={!!confirm}
        onClose={() => setConfirm(undefined)}
        title={t(confirm === 'delete' ? 'config.deleteBpTitle' : confirm === 'promote' ? 'config.promoteTitle' : 'config.abortTitle', { name: stored?.name ?? '' })}
        description={t(confirm === 'delete' ? 'config.deleteBpBody' : confirm === 'promote' ? 'config.promoteBody' : 'config.abortBody')}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setConfirm(undefined)}>
              {t('common.cancel')}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={del.isPending || pilot.end.isPending}
              onClick={() => {
                const done = () => setConfirm(undefined)
                if (confirm === 'delete')
                  del.mutate(stored!.id!, {
                    onSuccess: () => {
                      toast(t('config.deletedToast', { name: stored!.name! }))
                      void nav({ to: '/config' })
                    },
                    onError: fail,
                    onSettled: done,
                  })
                else pilot.end.mutate({ id: stored!.id!, op: confirm! }, { onSuccess: () => toast(t(confirm === 'promote' ? 'config.promoted' : 'config.aborted')), onError: fail, onSettled: done })
              }}
            >
              {t(confirm === 'delete' ? 'common.delete' : confirm === 'promote' ? 'config.pilotPromote' : 'config.pilotAbort')}
            </button>
          </>
        }
      />
    </form>
  )
}

/** A read only outline of a map: items and conditions. */
function TreeSummary({ nodes, items }: { nodes: Node[]; items: LibraryRow[] }) {
  const t = useT()
  if (!nodes.length) return <p className="text-meta text-muted">{t('config.emptyMap')}</p>
  return (
    <ul className="ml-2 flex flex-col gap-1 border-l border-line pl-3 text-meta">
      {nodes.map((n, i) => (
        <li key={i}>
          {n.kind === 'assign' ? (
            <span className="flex flex-wrap gap-1">{(n.items ?? []).map((id) => <Badge key={id}>{items.find((x) => x.id === id)?.name ?? `#${id}`}</Badge>)}</span>
          ) : (
            <>
              {((n.branches ?? []) as Branch[]).map((b, j) => (
                <div key={j}>
                  <span className="text-muted">{t(j ? 'config.elseIf' : 'config.if')} </span>
                  <span className="font-mono">{b.rules.map((r) => `${r.field} ${r.op} ${r.value}`).join(b.match === 'all' ? ' ∧ ' : ' ∨ ')}</span>
                  <TreeSummary nodes={b.nodes ?? []} items={items} />
                </div>
              ))}
              {!!n.else?.length && (
                <div>
                  <span className="text-muted">{t('config.else')}</span>
                  <TreeSummary nodes={n.else} items={items} />
                </div>
              )}
            </>
          )}
        </li>
      ))}
    </ul>
  )
}

/** An editable list of map nodes: assignments and conditions, in order. */
function NodeList({ nodes, onChange, ctx, path, depth }: { nodes: Node[]; onChange: (n: Node[]) => void; ctx: Ctx; path: string; depth: number }) {
  const t = useT()
  return (
    <div className="flex flex-col gap-2">
      {!nodes.length && <p className="text-meta text-muted">{t('config.emptyMap')}</p>}
      {nodes.map((n, i) => (
        <div key={i} className={cx('rounded-lg border p-3', n.kind === 'if' ? 'border-info/40 bg-info-soft/30' : 'border-line')}>
          <div className="mb-2 flex items-center gap-1">
            <span className="flex items-center gap-1.5 text-meta font-semibold text-muted">
              {n.kind === 'if' ? <SplitSquareVertical size={14} aria-hidden /> : <ListTree size={14} aria-hidden />}
              {t(n.kind === 'if' ? 'config.condition' : 'config.assign')}
            </span>
            {!ctx.readOnly && (
              <span className="ml-auto flex gap-0.5">
                <button type="button" className="btn btn-ghost !h-7 px-1.5" aria-label={t('config.moveUp')} disabled={i === 0} onClick={() => onChange(move(nodes, i, -1))}>
                  <ArrowUp size={14} />
                </button>
                <button type="button" className="btn btn-ghost !h-7 px-1.5" aria-label={t('config.moveDown')} disabled={i === nodes.length - 1} onClick={() => onChange(move(nodes, i, 1))}>
                  <ArrowDown size={14} />
                </button>
                <button type="button" className="btn btn-ghost !h-7 px-1.5" aria-label={t('config.removeNode')} onClick={() => onChange(removeAt(nodes, i))}>
                  <Trash2 size={14} />
                </button>
              </span>
            )}
          </div>
          {n.kind === 'assign' ? (
            <AssignEditor node={n} onChange={(v) => onChange(replaceAt(nodes, i, v))} ctx={ctx} />
          ) : (
            <IfEditor node={n} onChange={(v) => onChange(replaceAt(nodes, i, v))} ctx={ctx} path={`${path}.${i}`} depth={depth} />
          )}
        </div>
      ))}
      {!ctx.readOnly && (
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn btn-ghost text-accent" onClick={() => onChange([...nodes, newAssign()])}>
            <Plus size={14} aria-hidden /> {t('config.addAssign')}
          </button>
          {depth < 6 && (
            <button type="button" className="btn btn-ghost text-accent" onClick={() => onChange([...nodes, newIf(ctx.fields)])}>
              <Braces size={14} aria-hidden /> {t('config.addCondition')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function AssignEditor({ node, onChange, ctx }: { node: Node; onChange: (n: Node) => void; ctx: Ctx }) {
  const t = useT()
  const ids = node.items ?? []
  const byType = new Map<string, LibraryRow[]>()
  for (const it of ctx.items) if (!ids.includes(it.id!)) byType.set(it.type, [...(byType.get(it.type) ?? []), it])
  return (
    <div className="flex flex-col gap-2">
      <ul className="flex flex-wrap gap-1.5" aria-label={t('config.assignedItems')}>
        {ids.map((id) => {
          const it = ctx.items.find((x) => x.id === id)
          return (
            <li key={id} className="inline-flex items-center gap-1 rounded-md bg-surface-2 py-0.5 pr-0.5 pl-2 text-meta">
              <Link to="/config/library/$id" params={{ id: String(id) }} className="hover:text-accent">
                {it?.name ?? `#${id}`}
              </Link>
              {it && <span className="font-mono text-micro text-muted">{it.type.replace('com.limdm.', '')}</span>}
              {!ctx.readOnly && (
                <button type="button" className="grid size-5 place-items-center rounded hover:bg-line" aria-label={t('config.removeItem', { name: it?.name ?? String(id) })} onClick={() => onChange({ ...node, items: ids.filter((x) => x !== id) })}>
                  <X size={12} />
                </button>
              )}
            </li>
          )
        })}
        {!ids.length && <li className="text-meta text-muted">{t('config.noItemsYet')}</li>}
      </ul>
      {!ctx.readOnly && (
        <select className="field max-w-sm" aria-label={t('config.addItem')} value="" onChange={(e) => e.target.value && onChange({ ...node, items: [...ids, Number(e.target.value)] })}>
          <option value="">{t('config.addItem')}</option>
          {[...byType.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([type, list]) => (
              <optgroup key={type} label={type}>
                {list.map((it) => (
                  <option key={it.id} value={it.id}>
                    {it.name}
                  </option>
                ))}
              </optgroup>
            ))}
        </select>
      )}
    </div>
  )
}

function IfEditor({ node, onChange, ctx, path, depth }: { node: Node; onChange: (n: Node) => void; ctx: Ctx; path: string; depth: number }) {
  const t = useT()
  const branches = (node.branches ?? []) as Branch[]
  const setBranches = (bs: Branch[]) => onChange({ ...node, branches: bs })
  return (
    <div className="flex flex-col gap-3">
      {ctx.problems[path] && <p className="text-meta font-medium text-bad">{t(`config.problem.${ctx.problems[path]}` as MessageKey)}</p>}
      {branches.map((b, j) => (
        <div key={j} className="rounded-md border border-line bg-surface p-2.5">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="text-meta font-semibold">{t(j ? 'config.elseIf' : 'config.if')}</span>
            <Segmented
              label={t('config.match')}
              value={b.match}
              onChange={(m) => setBranches(replaceAt(branches, j, { ...b, match: m }))}
              options={[
                { value: 'all', label: t('config.matchAll') },
                { value: 'any', label: t('config.matchAny') },
              ]}
            />
            {!ctx.readOnly && (
              <button type="button" className="btn btn-ghost ml-auto !h-7 px-1.5" aria-label={t('config.removeBranch', { n: j + 1 })} onClick={() => setBranches(removeAt(branches, j))}>
                <Trash2 size={14} />
              </button>
            )}
          </div>
          {ctx.problems[`${path}.b${j}`] && <p className="mb-1 text-meta font-medium text-bad">{t(`config.problem.${ctx.problems[`${path}.b${j}`]}` as MessageKey)}</p>}
          <ul className="mb-2 flex flex-col gap-1.5">
            {b.rules.map((r, k) => (
              <RuleRow key={k} rule={r} fields={ctx.fields} readOnly={ctx.readOnly} problem={ctx.problems[`${path}.b${j}.r${k}`]} n={k + 1} onChange={(nr) => setBranches(replaceAt(branches, j, { ...b, rules: replaceAt(b.rules, k, nr) }))} onRemove={() => setBranches(replaceAt(branches, j, { ...b, rules: removeAt(b.rules, k) }))} />
            ))}
          </ul>
          {!ctx.readOnly && (
            <button type="button" className="btn btn-ghost mb-2 text-accent" onClick={() => setBranches(replaceAt(branches, j, { ...b, rules: [...b.rules, newRule(ctx.fields)] }))}>
              <Plus size={14} aria-hidden /> {t('config.addRule')}
            </button>
          )}
          <div className="ml-2 border-l-2 border-accent/40 pl-3">
            <div className="mb-1 text-meta font-medium text-muted">{t('config.then')}</div>
            <NodeList nodes={b.nodes ?? []} onChange={(ns) => setBranches(replaceAt(branches, j, { ...b, nodes: ns }))} ctx={ctx} path={`${path}.b${j}`} depth={depth + 1} />
          </div>
        </div>
      ))}
      {!ctx.readOnly && (
        <button type="button" className="btn btn-ghost w-fit text-accent" onClick={() => setBranches([...branches, { match: 'all', rules: [newRule(ctx.fields)], nodes: [] }])}>
          <Plus size={14} aria-hidden /> {t('config.addBranch')}
        </button>
      )}
      <div className="ml-2 border-l-2 border-line pl-3">
        <div className="mb-1 text-meta font-medium text-muted">{t('config.else')}</div>
        <NodeList nodes={node.else ?? []} onChange={(ns) => onChange({ ...node, else: ns })} ctx={ctx} path={`${path}.else`} depth={depth + 1} />
      </div>
    </div>
  )
}

function RuleRow({ rule, fields, readOnly, problem, n, onChange, onRemove }: { rule: Rule; fields: Record<string, string[]>; readOnly: boolean; problem?: string; n: number; onChange: (r: Rule) => void; onRemove: () => void }) {
  const t = useT()
  const ops = fields[rule.field] ?? []
  return (
    <li className="flex flex-col gap-0.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <select className="field !h-8 w-auto !px-2" aria-label={t('config.ruleField', { n })} value={rule.field} onChange={(e) => onChange({ field: e.target.value, op: fields[e.target.value]?.[0] ?? 'eq', value: rule.value })}>
          {Object.keys(fields)
            .sort()
            .map((f) => (
              <option key={f} value={f}>
                {t(`config.field.${f}` as MessageKey)}
              </option>
            ))}
        </select>
        <select className="field !h-8 w-auto !px-2" aria-label={t('config.ruleOp', { n })} value={rule.op} onChange={(e) => onChange({ ...rule, op: e.target.value, value: noValue(e.target.value) ? '' : rule.value })}>
          {ops.map((o) => (
            <option key={o} value={o}>
              {t(`config.op.${o}` as MessageKey)}
            </option>
          ))}
        </select>
        {!noValue(rule.op) && (
          <input className="field !h-8 w-40 flex-1 !px-2 font-mono" aria-label={t('config.ruleValue', { n })} aria-invalid={!!problem || undefined} maxLength={200} value={rule.value} onChange={(e) => onChange({ ...rule, value: e.target.value })} />
        )}
        {!readOnly && (
          <button type="button" className="btn btn-ghost !h-8 px-1.5" aria-label={t('config.removeRule', { n })} onClick={onRemove}>
            <X size={14} />
          </button>
        )}
      </div>
      {problem && <p className="text-meta font-medium text-bad">{t(`config.problem.${problem}` as MessageKey)}</p>}
    </li>
  )
}
