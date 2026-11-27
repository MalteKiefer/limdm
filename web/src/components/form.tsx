// One form pattern for the whole console: label above the control, help
// under the label (aria-describedby), error under the control (aria-invalid,
// aria-describedby), required fields with a star and screen reader text, a
// save bar that appears only with unsaved changes. Works with
// react-hook-form (FormField) or with any state (Field).
import { OctagonX } from 'lucide-react'
import { useId, type ReactNode } from 'react'
import type { FieldPath, FieldValues, UseFormReturn } from 'react-hook-form'
import { useT } from '../i18n'

export type FieldIds = { id: string; describedBy?: string; invalid: boolean }

export function Field({ label, help, error, required, children, htmlFor }: { label: ReactNode; help?: ReactNode; error?: string; required?: boolean; children: (ids: FieldIds) => ReactNode; htmlFor?: string }) {
  const t = useT()
  const gen = useId()
  const id = htmlFor ?? gen
  const helpId = help ? `${id}-help` : undefined
  const errId = error ? `${id}-err` : undefined
  return (
    // In a container that holds only fields, three subgrid rows (label and
    // help, control, error) line up the controls of one row whatever the
    // texts above and below them. Next to other elements (filter bars) a
    // field stays a column whose label part grows, as before.
    <div className="lm-field flex flex-col gap-1 [:not(:has(>:not(.lm-field)))>&]:row-span-3 [:not(:has(>:not(.lm-field)))>&]:grid [:not(:has(>:not(.lm-field)))>&]:grid-rows-subgrid [:not(:has(>:not(.lm-field)))>&]:content-start">
      <div className="flex grow flex-col gap-1">
        <label htmlFor={id} className="text-body font-medium">
          {label}
          {required && (
            <>
              <span className="text-bad" aria-hidden>
                {' '}
                *
              </span>
              <span className="sr-only"> {t('common.required')}</span>
            </>
          )}
        </label>
        {help && (
          <p id={helpId} className="text-meta text-muted">
            {help}
          </p>
        )}
      </div>
      {children({ id, describedBy: [helpId, errId].filter(Boolean).join(' ') || undefined, invalid: !!error })}
      {error && (
        <p id={errId} className="flex items-center gap-1 text-meta font-medium text-bad">
          <OctagonX size={13} aria-hidden /> {error}
        </p>
      )}
    </div>
  )
}

/** A text input bound to react-hook-form, with the error of the field shown and announced. */
export function FormField<T extends FieldValues>({ form, name, label, help, required, type = 'text', mono, textarea, autoComplete }: { form: UseFormReturn<T>; name: FieldPath<T>; label: ReactNode; help?: ReactNode; required?: boolean; type?: string; mono?: boolean; textarea?: boolean; autoComplete?: string }) {
  const err = form.formState.errors[name]?.message
  return (
    <Field label={label} help={help} required={required} error={typeof err === 'string' ? err : undefined}>
      {({ id, describedBy, invalid }) => {
        const common = { id, 'aria-describedby': describedBy, 'aria-invalid': invalid || undefined, 'aria-required': required || undefined, className: mono ? 'field font-mono' : 'field', autoComplete, ...form.register(name) }
        return textarea ? <textarea rows={4} {...common} /> : <input type={type} {...common} />
      }}
    </Field>
  )
}

export function FormSection({ title, description, children }: { title: ReactNode; description?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid gap-4 border-b border-line py-6 last:border-0 md:grid-cols-[minmax(200px,280px)_1fr] md:gap-10">
      <div>
        <h3 className="font-semibold">{title}</h3>
        {description && <p className="mt-1 text-body text-muted">{description}</p>}
      </div>
      <div className="flex max-w-xl min-w-0 flex-col gap-5">{children}</div>
    </section>
  )
}

/** Sticky bar at the bottom while a form has unsaved changes. */
export function SaveBar({ dirty, saving, disabled, onDiscard, saveLabel }: { dirty: boolean; saving?: boolean; disabled?: boolean; onDiscard: () => void; saveLabel?: ReactNode }) {
  const t = useT()
  if (!dirty) return null
  return (
    <div className="fade-in sticky bottom-0 z-20 -mx-4 mt-4 flex items-center justify-end gap-2 border-t border-line bg-surface/95 px-4 py-3 backdrop-blur lg:-mx-6 lg:px-6" role="region" aria-label={t('form.unsaved')}>
      <span className="mr-auto text-body text-muted">{t('form.unsaved')}</span>
      <button type="button" className="btn" onClick={onDiscard}>
        {t('form.discard')}
      </button>
      <button type="submit" className="btn btn-primary" disabled={saving || disabled}>
        {saveLabel ?? t('common.save')}
      </button>
    </div>
  )
}
