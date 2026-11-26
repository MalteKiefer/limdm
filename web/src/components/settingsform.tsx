// Building blocks of the settings pattern: one form per section with
// react-hook-form and zod, fields with label, help and error, a save bar
// only while there are unsaved changes, and dialogs for confirmations and
// secrets shown once. Used by the settings area and other areas.
import { zodResolver } from '@hookform/resolvers/zod'
import { Check, Copy, TriangleAlert } from 'lucide-react'
import { useEffect, useId, useState, type ReactNode } from 'react'
import type { z } from 'zod'
import { Controller, useForm, type DefaultValues, type FieldValues, type Path, type UseFormReturn } from 'react-hook-form'
import { ApiError } from '../api/client'
import { Field, SaveBar } from './form'
import { errorText } from './states'
import { toast } from './toast'
import { Modal, Switch } from './ui'
import { useT } from '../i18n'
import { cx } from '../lib/cx'

/** A section form: zod validation, server errors at the field (422 names it), save bar while dirty. */
export function SettingsForm<T extends FieldValues>({
  schema,
  values,
  onSave,
  readOnly,
  children,
  okText,
}: {
  schema: z.ZodType<T, T>
  values: T
  onSave: (v: T) => Promise<unknown>
  readOnly?: boolean
  children: (form: UseFormReturn<T>) => ReactNode
  okText?: string
}) {
  const t = useT()
  const form = useForm<T>({ resolver: zodResolver(schema), defaultValues: values as DefaultValues<T>, mode: 'onTouched' })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const key = JSON.stringify(values)
  useEffect(() => {
    form.reset(values)
    // values changes identity on every render; its content is the key
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  const submit = form.handleSubmit(async (v) => {
    setSaving(true)
    setError('')
    try {
      await onSave(v)
      form.reset(v)
      toast(okText ?? t('settings.saved'))
    } catch (e) {
      const field = e instanceof ApiError ? e.problem.field : undefined
      if (field && field in v) form.setError(field as Path<T>, { message: errorText(e) }, { shouldFocus: true })
      else setError(errorText(e))
    } finally {
      setSaving(false)
    }
  })
  return (
    <form onSubmit={(e) => void submit(e)} noValidate>
      <fieldset disabled={readOnly} className="contents">
        {children(form)}
      </fieldset>
      {error && (
        <p role="alert" className="mt-4 flex items-start gap-2 rounded-md bg-bad-soft p-3 text-[13px] text-bad">
          <TriangleAlert size={15} className="mt-0.5 shrink-0" aria-hidden /> {error}
        </p>
      )}
      {!readOnly && <SaveBar dirty={form.formState.isDirty} saving={saving} onDiscard={() => form.reset(values)} />}
    </form>
  )
}

const fieldErr = <T extends FieldValues>(form: UseFormReturn<T>, name: Path<T>) => {
  const e = name.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], form.formState.errors) as { message?: string } | undefined
  return typeof e?.message === 'string' ? e.message : undefined
}

export function TextField<T extends FieldValues>({ form, name, label, help, required, type = 'text', mono, placeholder, autoComplete, className }: { form: UseFormReturn<T>; name: Path<T>; label: ReactNode; help?: ReactNode; required?: boolean; type?: string; mono?: boolean; placeholder?: string; autoComplete?: string; className?: string }) {
  return (
    <Field label={label} help={help} required={required} error={fieldErr(form, name)}>
      {({ id, describedBy, invalid }) => (
        <input
          id={id}
          type={type}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          aria-required={required || undefined}
          placeholder={placeholder}
          autoComplete={autoComplete ?? 'off'}
          spellCheck={false}
          className={cx('field', mono && 'font-mono text-[12.5px]', className)}
          {...form.register(name, type === 'number' ? { valueAsNumber: true } : undefined)}
        />
      )}
    </Field>
  )
}

/** A text area whose lines are a string list (networks, recipients, acr values). */
export function ListField<T extends FieldValues>({ form, name, label, help, placeholder, rows = 3 }: { form: UseFormReturn<T>; name: Path<T>; label: ReactNode; help?: ReactNode; placeholder?: string; rows?: number }) {
  return (
    <Field label={label} help={help} error={fieldErr(form, name)}>
      {({ id, describedBy, invalid }) => <textarea id={id} rows={rows} aria-describedby={describedBy} aria-invalid={invalid || undefined} placeholder={placeholder} spellCheck={false} className="field font-mono text-[12.5px]" {...form.register(name)} />}
    </Field>
  )
}

export function SelectField<T extends FieldValues>({ form, name, label, help, options }: { form: UseFormReturn<T>; name: Path<T>; label: ReactNode; help?: ReactNode; options: { value: string; label: string }[] }) {
  return (
    <Field label={label} help={help} error={fieldErr(form, name)}>
      {({ id, describedBy, invalid }) => (
        <select id={id} aria-describedby={describedBy} aria-invalid={invalid || undefined} className="field" {...form.register(name)}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      )}
    </Field>
  )
}

/** An on/off setting: label and help left, switch right. */
export function Toggle<T extends FieldValues>({ form, name, label, help, disabled }: { form: UseFormReturn<T>; name: Path<T>; label: ReactNode; help?: ReactNode; disabled?: boolean }) {
  const id = useId()
  return (
    <div className="flex items-start justify-between gap-6">
      <div>
        <label htmlFor={id} className="text-[13px] font-medium">
          {label}
        </label>
        {help && (
          <p id={`${id}-help`} className="text-[12.5px] text-muted">
            {help}
          </p>
        )}
      </div>
      <Controller control={form.control} name={name} render={({ field }) => <Switch id={id} checked={!!field.value} onChange={field.onChange} disabled={disabled} />} />
    </div>
  )
}

/** A confirmation dialog; with reason, a reason or ticket field (four eyes approval). */
export function Confirm({ open, onClose, title, body, confirm, danger, reason, busy, onConfirm, children }: { open: boolean; onClose: () => void; title: ReactNode; body?: ReactNode; confirm: string; danger?: boolean; reason?: boolean; busy?: boolean; onConfirm: (reason: string) => void; children?: ReactNode }) {
  const t = useT()
  const [text, setText] = useState('')
  const id = useId()
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={body}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className={cx('btn', danger ? 'btn-danger' : 'btn-primary')} disabled={busy} onClick={() => onConfirm(text.trim())}>
            {confirm}
          </button>
        </>
      }
    >
      {children}
      {reason && (
        <div className="flex flex-col gap-1">
          <label htmlFor={id} className="text-[13px] font-medium">
            {t('settings.reason')}
          </label>
          <p id={`${id}-help`} className="text-[12.5px] text-muted">
            {t('settings.reasonHelp')}
          </p>
          <input id={id} aria-describedby={`${id}-help`} className="field" maxLength={500} value={text} onChange={(e) => setText(e.target.value)} />
        </div>
      )}
    </Modal>
  )
}

/** A secret shown once (credentials, tokens, recovery codes) with a copy button. */
export function OnceSecret({ title, value, onClose, note }: { title: ReactNode; value: string; onClose: () => void; note?: ReactNode }) {
  const t = useT()
  const [copied, setCopied] = useState(false)
  return (
    <Modal
      open
      wide
      onClose={onClose}
      title={title}
      description={note ?? t('settings.onceNote')}
      footer={
        <button type="button" className="btn btn-primary" onClick={onClose}>
          {t('common.done')}
        </button>
      }
    >
      <pre className="overflow-x-auto rounded-md bg-sunken p-3 font-mono text-[12.5px] whitespace-pre-wrap break-all" aria-label={t('settings.secret')}>
        {value}
      </pre>
      <button
        type="button"
        className="btn mt-3"
        onClick={() =>
          void navigator.clipboard.writeText(value).then(
            () => setCopied(true),
            () => toast(t('settings.copyFailed'), 'error'),
          )
        }
      >
        {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />} {copied ? t('settings.copied') : t('settings.copy')}
      </button>
    </Modal>
  )
}

/** A small key value list for read only facts. */
export function Facts({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(120px,auto)_1fr] gap-x-4 gap-y-1.5 text-[13px]">
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

/** The heading of a section page inside the settings card. */
export function SectionHead({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line py-5">
      <div className="min-w-0">
        <h2 className="text-[17px] font-semibold">{title}</h2>
        {sub && <p className="mt-1 max-w-3xl text-[13px] text-muted">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}
