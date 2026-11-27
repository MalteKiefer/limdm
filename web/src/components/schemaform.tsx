// JSON Schema form renderer for declaration payloads. The server derives a
// schema per declaration type from the Go types (GET /api/v1/schemas/{type});
// the console never hand codes a declaration form. Validation runs with
// @cfworker/json-schema, which interprets the schema (no eval, CSP safe).
//
// Supported: objects (x-order keeps the field order, x-section groups
// fields into cards), booleans (switch), enums (up to three as a segmented
// control, else a select; x-enumTitles names them), numbers, strings
// (x-widget textarea, code with a file loader, secret as a masked input),
// lists of scalars (chips, numbers for integer lists), lists of choices
// (x-widget checkboxes), lists of flat objects (an editable table), lists of
// other objects (repeated fieldsets), maps (key and value table), nested
// objects (fieldsets). Integer choices keep their number type.
import { Validator, type OutputUnit } from '@cfworker/json-schema'
import { Eye, EyeOff, FileUp, Plus, Trash2, X } from 'lucide-react'
import { useState } from 'react'
import { t, useT } from '../i18n'
import { Field } from './form'
import { Segmented, Switch } from './ui'

export type JSONSchema = {
  type?: 'object' | 'string' | 'integer' | 'number' | 'boolean' | 'array'
  title?: string
  description?: string
  enum?: (string | number)[]
  format?: string
  'x-enumTitles'?: string[]
  'x-section'?: string
  'x-widget'?: 'textarea' | 'code' | 'secret' | 'checkboxes'
  'x-secret'?: boolean
  'x-order'?: string[]
  'x-patternHint'?: string
  minimum?: number
  maximum?: number
  minLength?: number
  pattern?: string
  default?: unknown
  properties?: Record<string, JSONSchema>
  additionalProperties?: boolean | JSONSchema
  required?: string[]
  items?: JSONSchema
}
type Obj = Record<string, unknown>
export type Errors = Record<string, string>

function at(s: JSONSchema | undefined, ptr: string) {
  let cur = s
  for (const part of ptr.split('/').filter(Boolean)) {
    if (!cur) return undefined
    cur = cur.type === 'array' ? cur.items : (cur.properties?.[part] ?? (typeof cur.additionalProperties === 'object' ? cur.additionalProperties : undefined))
  }
  return cur
}

/** Validates value; errors keyed by JSON pointer, in the console's language. */
export function validate(schema: JSONSchema, value: unknown): Errors {
  const res = new Validator(schema as never, '2020-12', false).validate(value)
  const out: Errors = {}
  for (const e of res.errors as OutputUnit[]) {
    if (['properties', 'items', 'allOf', '$ref', 'additionalProperties'].includes(e.keyword) && !/not allowed|additional/i.test(e.error)) continue
    let ptr = e.instanceLocation.replace(/^#/, '')
    const sub = at(schema, ptr)
    let msg = t('schema.invalid')
    switch (e.keyword) {
      case 'required': {
        const m = /"([^"]+)"/.exec(e.error)
        ptr = `${ptr}/${m?.[1] ?? ''}`
        msg = t('schema.required')
        break
      }
      case 'minimum':
        msg = t('schema.min', { n: sub?.minimum ?? 0 })
        break
      case 'maximum':
        msg = t('schema.max', { n: sub?.maximum ?? 0 })
        break
      case 'pattern':
        msg = sub?.['x-patternHint'] ?? t('schema.pattern')
        break
      case 'minLength':
        msg = t('schema.minLength')
        break
      case 'type':
        msg = t('schema.type')
        break
      case 'enum':
        msg = t('schema.enum')
        break
      case 'additionalProperties':
      case 'properties':
        msg = t('schema.unknown')
        break
    }
    out[ptr] ??= msg
  }
  return out
}

const keysOf = (s: JSONSchema) => s['x-order'] ?? Object.keys(s.properties ?? {})
const isScalar = (s?: JSONSchema) => !!s && s.type !== 'object' && s.type !== 'array'
const isMap = (s: JSONSchema) => s.type === 'object' && !s.properties && typeof s.additionalProperties === 'object'

/** The whole form of an object schema: one card per x-section. */
export function SchemaForm({ schema, value, onChange, errors, idPrefix = 'f' }: { schema: JSONSchema; value: Obj; onChange: (v: Obj) => void; errors: Errors; idPrefix?: string }) {
  const tr = useT()
  const keys = keysOf(schema)
  const section = (k: string) => schema.properties?.[k]?.['x-section'] ?? tr('schema.general')
  const sections = [...new Set(keys.map(section))]
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      {sections.map((sec) => (
        <fieldset key={sec} className="card p-[var(--pad-card)]">
          <legend className="sr-only">{sec}</legend>
          {sections.length > 1 && (
            <h3 className="mb-4 font-semibold" aria-hidden>
              {sec}
            </h3>
          )}
          <div className="flex flex-col gap-5">
            {keys
              .filter((k) => section(k) === sec)
              .map((k) => (
                <Prop key={k} name={k} schema={schema.properties![k]} required={schema.required?.includes(k)} value={value[k]} onChange={(v) => onChange(v === undefined ? omit(value, k) : { ...value, [k]: v })} errors={errors} path={`/${k}`} idPrefix={idPrefix} />
              ))}
          </div>
        </fieldset>
      ))}
    </div>
  )
}

const omit = (o: Obj, k: string) => Object.fromEntries(Object.entries(o).filter(([x]) => x !== k))
const fieldId = (prefix: string, path: string) => `${prefix}${path.replace(/[^A-Za-z0-9_-]/g, '_')}`

function Prop({ name, schema: s, value, onChange, errors, path, required, idPrefix }: { name: string; schema: JSONSchema; value: unknown; onChange: (v: unknown) => void; errors: Errors; path: string; required?: boolean; idPrefix: string }) {
  const label = s.title ?? name
  const err = errors[path]
  const id = fieldId(idPrefix, path)
  if (s.type === 'boolean')
    return (
      <div className="flex items-start justify-between gap-6">
        <div>
          <label htmlFor={id} className="text-body font-medium">
            {label}
          </label>
          {s.description && <p className="text-meta text-muted">{s.description}</p>}
          {err && <p className="text-meta font-medium text-bad">{err}</p>}
        </div>
        <Switch id={id} checked={!!(value ?? s.default)} onChange={onChange} label={label} />
      </div>
    )
  if (s.type === 'object' && isMap(s)) return <MapTable label={label} schema={s} value={(value as Record<string, unknown>) ?? {}} onChange={onChange} errors={errors} path={path} />
  if (s.type === 'object')
    return (
      <fieldset className="rounded-lg border border-line p-3">
        <legend className="px-1 text-body font-medium">{label}</legend>
        {s.description && <p className="mb-3 text-meta text-muted">{s.description}</p>}
        <div className="flex flex-col gap-4">
          {keysOf(s).map((k) => (
            <Prop key={k} name={k} schema={s.properties![k]} value={(value as Obj | undefined)?.[k]} onChange={(v) => onChange({ ...((value as Obj) ?? {}), [k]: v })} errors={errors} path={`${path}/${k}`} required={s.required?.includes(k)} idPrefix={idPrefix} />
          ))}
        </div>
      </fieldset>
    )
  if (s.type === 'array' && s.items?.type === 'object') {
    const list = (value as Obj[]) ?? []
    return keysOf(s.items).every((k) => isScalar(s.items!.properties![k])) ? (
      <ObjectTable label={label} schema={s} value={list} onChange={onChange} errors={errors} path={path} />
    ) : (
      <ObjectList label={label} schema={s} value={list} onChange={onChange} errors={errors} path={path} idPrefix={idPrefix} />
    )
  }
  return (
    <Field label={label} help={s.description} error={err} required={required} htmlFor={id}>
      {({ id: fid, describedBy, invalid }) => <Scalar s={s} id={fid} describedBy={describedBy} invalid={invalid} label={label} value={value} onChange={onChange} />}
    </Field>
  )
}

function Scalar({ s, id, describedBy, invalid, label, value, onChange, compact }: { s: JSONSchema; id?: string; describedBy?: string; invalid: boolean; label: string; value: unknown; onChange: (v: unknown) => void; compact?: boolean }) {
  const common = { id, 'aria-describedby': describedBy, 'aria-invalid': invalid || undefined, 'aria-label': compact ? label : undefined }
  const cls = compact ? 'field !h-8 !px-2' : 'field'
  // choices keep the type of the schema: integer levels stay numbers, an
  // emptied select removes the field instead of sending ""
  const pick = (v: string) => (v === '' ? undefined : s.type === 'integer' || s.type === 'number' ? Number(v) : v)
  if (s.type === 'array' && s['x-widget'] === 'checkboxes' && s.items?.enum) return <Checkboxes s={s} label={label} value={(value as unknown[]) ?? []} onChange={onChange} describedBy={describedBy} />
  if (s.enum && s.enum.length <= 3 && !compact)
    return <Segmented label={label} value={String(value ?? s.default ?? '')} onChange={(v) => onChange(pick(v))} options={s.enum.map((v, i) => ({ value: String(v), label: s['x-enumTitles']?.[i] ?? String(v) }))} />
  if (s.enum)
    return (
      <select {...common} className={cls} value={String(value ?? '')} onChange={(e) => onChange(pick(e.target.value))}>
        <option value="" />
        {s.enum.map((v, i) => (
          <option key={String(v)} value={String(v)}>
            {s['x-enumTitles']?.[i] ?? String(v)}
          </option>
        ))}
      </select>
    )
  if (s.type === 'integer' || s.type === 'number')
    return <input {...common} type="number" inputMode="numeric" className={`${cls} num max-w-[160px]`} value={value == null ? '' : String(value)} min={s.minimum} max={s.maximum} step={s.type === 'integer' ? 1 : 'any'} onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))} />
  if (s.type === 'array') return <Chips {...common} numeric={s.items?.type === 'integer' || s.items?.type === 'number'} value={(value as (string | number)[]) ?? []} onChange={onChange} />
  if (s.type === 'boolean') return <input {...common} type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
  if (s['x-widget'] === 'textarea' && !compact) return <textarea {...common} rows={4} className={cls} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)} />
  if (s['x-widget'] === 'code' && !compact) return <CodeArea common={common} label={label} value={String(value ?? '')} onChange={onChange} />
  if (s['x-widget'] === 'secret' || s['x-secret']) return <Secret common={common} cls={cls} label={label} value={String(value ?? '')} onChange={onChange} />
  return <input {...common} className={cls} value={String(value ?? '')} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)} />
}

function Chips({ value, onChange, id, numeric, ...rest }: { value: (string | number)[]; onChange: (v: (string | number)[]) => void; id?: string; numeric?: boolean }) {
  const tr = useT()
  const [draft, setDraft] = useState('')
  const add = () => {
    const raw = draft.trim()
    const v = numeric && raw !== '' && !Number.isNaN(Number(raw)) ? Number(raw) : raw
    if (raw && !value.includes(v)) onChange([...value, v])
    setDraft('')
  }
  return (
    <div className="field flex !h-auto min-h-[34px] flex-wrap items-center gap-1 py-1">
      {value.map((v) => (
        <span key={String(v)} className="inline-flex items-center gap-1 rounded bg-surface-2 py-0.5 pr-0.5 pl-2 font-mono text-meta">
          {v}
          <button type="button" className="grid size-[24px] shrink-0 place-items-center rounded hover:bg-line" aria-label={tr('query.remove', { token: String(v) })} onClick={() => onChange(value.filter((x) => x !== v))}>
            <X size={11} />
          </button>
        </span>
      ))}
      <input
        id={id}
        {...rest}
        className="min-w-[120px] flex-1 bg-transparent py-0.5 outline-none"
        value={draft}
        placeholder={tr('schema.chipsPlaceholder')}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault()
            add()
          }
          if (e.key === 'Backspace' && !draft && value.length) onChange(value.slice(0, -1))
        }}
        onBlur={add}
      />
    </div>
  )
}

type Common = { id?: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean; 'aria-label'?: string }

/** Choices of a list as checkboxes, in the order of the schema. */
function Checkboxes({ s, label, value, onChange, describedBy }: { s: JSONSchema; label: string; value: unknown[]; onChange: (v: unknown[] | undefined) => void; describedBy?: string }) {
  const opts = s.items!.enum!
  return (
    <div role="group" aria-label={label} aria-describedby={describedBy} className="flex flex-wrap gap-x-4 gap-y-1.5">
      {opts.map((o, i) => (
        <label key={String(o)} className="inline-flex items-center gap-1.5 text-body">
          <input
            type="checkbox"
            checked={value.includes(o)}
            onChange={(e) => {
              const next = opts.filter((x) => (x === o ? e.target.checked : value.includes(x)))
              onChange(next.length ? next : undefined)
            }}
          />
          {s.items!['x-enumTitles']?.[i] ?? String(o)}
        </label>
      ))}
    </div>
  )
}

/** Monospace text (scripts, PEM, SQL) that can also be loaded from a file. */
function CodeArea({ common, label, value, onChange }: { common: Common; label: string; value: string; onChange: (v: unknown) => void }) {
  const tr = useT()
  return (
    <div className="flex flex-col gap-1">
      <textarea {...common} rows={Math.min(18, Math.max(4, value.split('\n').length + 1))} spellCheck={false} wrap="off" className="field font-mono text-meta leading-5" value={value} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)} />
      <label className="btn btn-ghost w-fit cursor-pointer text-meta">
        <FileUp size={14} aria-hidden /> {tr('schema.loadFile')}
        <input
          type="file"
          className="sr-only"
          aria-label={`${tr('schema.loadFile')}: ${label}`}
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f && f.size <= 1 << 20) void f.text().then((txt) => onChange(txt))
            e.target.value = ''
          }}
        />
      </label>
    </div>
  )
}

/** A secret: masked by default, the mask the server sends stays as it is. */
function Secret({ common, cls, label, value, onChange }: { common: Common; cls: string; label: string; value: string; onChange: (v: unknown) => void }) {
  const tr = useT()
  const [show, setShow] = useState(false)
  return (
    <div className="flex items-center gap-1">
      <input {...common} type={show ? 'text' : 'password'} autoComplete="new-password" spellCheck={false} className={`${cls} font-mono`} value={value} onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)} />
      <button type="button" className="btn btn-ghost !h-8 px-2" aria-pressed={show} aria-label={`${tr(show ? 'schema.hide' : 'schema.show')}: ${label}`} onClick={() => setShow(!show)}>
        {show ? <EyeOff size={14} aria-hidden /> : <Eye size={14} aria-hidden />}
      </button>
    </div>
  )
}

function ObjectTable({ label, schema, value, onChange, errors, path }: { label: string; schema: JSONSchema; value: Obj[]; onChange: (v: Obj[]) => void; errors: Errors; path: string }) {
  const tr = useT()
  const item = schema.items!
  const cols = keysOf(item).map((k) => [k, item.properties![k]] as const)
  const blank = Object.fromEntries(cols.filter(([, s]) => s.default !== undefined).map(([k, s]) => [k, s.default]))
  return (
    <div>
      <div className="mb-1 text-body font-medium">{label}</div>
      {schema.description && <p className="mb-2 text-meta text-muted">{schema.description}</p>}
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[560px] text-left">
          <thead className="bg-surface-2 text-meta text-muted">
            <tr>
              {cols.map(([k, s]) => (
                <th key={k} scope="col" className="px-2 py-1.5 font-medium">
                  {s.title ?? k}
                </th>
              ))}
              <th className="w-10">
                <span className="sr-only">{tr('common.delete')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {value.map((row, i) => (
              <tr key={i} className="border-t border-line align-top">
                {cols.map(([k, s]) => {
                  const err = errors[`${path}/${i}/${k}`]
                  return (
                    <td key={k} className="px-1.5 py-1.5">
                      <Scalar s={s} compact invalid={!!err} label={tr('schema.row', { field: s.title ?? k, n: i + 1 })} value={row[k]} onChange={(v) => onChange(value.map((r, j) => (j === i ? { ...r, [k]: v } : r)))} />
                      {err && <div className="mt-0.5 text-micro font-medium text-bad">{err}</div>}
                    </td>
                  )
                })}
                <td className="px-1 py-1.5">
                  <button type="button" className="btn btn-ghost !h-8 px-2" aria-label={tr('schema.removeItem', { n: i + 1 })} onClick={() => onChange(value.filter((_, j) => j !== i))}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="btn btn-ghost mt-2 text-accent" onClick={() => onChange([...value, blank])}>
        <Plus size={14} aria-hidden /> {tr('schema.addItem')}
      </button>
    </div>
  )
}

function ObjectList({ label, schema, value, onChange, errors, path, idPrefix }: { label: string; schema: JSONSchema; value: Obj[]; onChange: (v: Obj[]) => void; errors: Errors; path: string; idPrefix: string }) {
  const tr = useT()
  const item = schema.items!
  return (
    <fieldset>
      <legend className="mb-1 text-body font-medium">{label}</legend>
      {schema.description && <p className="mb-2 text-meta text-muted">{schema.description}</p>}
      <div className="flex flex-col gap-3">
        {value.map((row, i) => (
          <div key={i} className="rounded-lg border border-line p-3">
            <div className="mb-2 flex justify-end">
              <button type="button" className="btn btn-ghost !h-7 px-2" aria-label={tr('schema.removeItem', { n: i + 1 })} onClick={() => onChange(value.filter((_, j) => j !== i))}>
                <Trash2 size={14} />
              </button>
            </div>
            <div className="flex flex-col gap-4">
              {keysOf(item).map((k) => (
                <Prop key={k} name={k} schema={item.properties![k]} value={row[k]} onChange={(v) => onChange(value.map((r, j) => (j === i ? { ...r, [k]: v } : r)))} errors={errors} path={`${path}/${i}/${k}`} required={item.required?.includes(k)} idPrefix={idPrefix} />
              ))}
            </div>
          </div>
        ))}
      </div>
      <button type="button" className="btn btn-ghost mt-2 text-accent" onClick={() => onChange([...value, {}])}>
        <Plus size={14} aria-hidden /> {tr('schema.addItem')}
      </button>
    </fieldset>
  )
}

function MapTable({ label, schema, value, onChange, errors, path }: { label: string; schema: JSONSchema; value: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void; errors: Errors; path: string }) {
  const tr = useT()
  const entries = Object.entries(value)
  const vs = schema.additionalProperties as JSONSchema
  const set = (i: number, k: string, v: unknown) => onChange(Object.fromEntries(entries.map(([ek, ev], j) => (j === i ? [k, v] : [ek, ev]))))
  return (
    <div>
      <div className="mb-1 text-body font-medium">{label}</div>
      {schema.description && <p className="mb-2 text-meta text-muted">{schema.description}</p>}
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[420px] text-left">
          <thead className="bg-surface-2 text-meta text-muted">
            <tr>
              <th scope="col" className="px-2 py-1.5 font-medium">
                {tr('schema.key')}
              </th>
              <th scope="col" className="px-2 py-1.5 font-medium">
                {tr('schema.value')}
              </th>
              <th className="w-10">
                <span className="sr-only">{tr('common.delete')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([k, v], i) => (
              <tr key={i} className="border-t border-line align-top">
                <td className="px-1.5 py-1.5">
                  <input className="field !h-8 !px-2 font-mono" aria-label={tr('schema.row', { field: tr('schema.key'), n: i + 1 })} value={k} onChange={(e) => set(i, e.target.value, v)} />
                </td>
                <td className="px-1.5 py-1.5">
                  {isScalar(vs) ? <Scalar s={vs} compact invalid={!!errors[`${path}/${k}`]} label={tr('schema.row', { field: tr('schema.value'), n: i + 1 })} value={v} onChange={(nv) => set(i, k, nv)} /> : <code className="text-meta text-muted">{JSON.stringify(v)}</code>}
                  {errors[`${path}/${k}`] && <div className="mt-0.5 text-micro font-medium text-bad">{errors[`${path}/${k}`]}</div>}
                </td>
                <td className="px-1 py-1.5">
                  <button type="button" className="btn btn-ghost !h-8 px-2" aria-label={tr('schema.removeItem', { n: i + 1 })} onClick={() => onChange(Object.fromEntries(entries.filter((_, j) => j !== i)))}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="btn btn-ghost mt-2 text-accent" onClick={() => onChange({ ...value, '': vs.type === 'string' ? '' : undefined })} disabled={'' in value}>
        <Plus size={14} aria-hidden /> {tr('schema.addKey')}
      </button>
    </div>
  )
}
