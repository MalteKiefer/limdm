// Saved views of a list: apply, save the current one, share (admins),
// delete. The page hands in its current state and applies a chosen view.
import { Bookmark, BookmarkPlus, Trash2, Users } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../api/me'
import { useDeleteView, useSavedViews, useSaveView, type SavedView } from '../api/views'
import { useT } from '../i18n'
import { Field } from './form'
import { errorText } from './states'
import { toast } from './toast'
import { ActionMenu, Modal, Switch, type MenuEntry } from './ui'

export type ViewState = { query: string; sort?: string; columns?: string[] }

export function SavedViewsMenu({ list, current, onApply }: { list: string; current: ViewState; onApply: (v: SavedView) => void }) {
  const t = useT()
  const views = useSavedViews(list).data ?? []
  const del = useDeleteView(list)
  const canShare = useCan('admin')
  const [saving, setSaving] = useState(false)
  const mine = views.filter((v) => v.mine)
  const shared = views.filter((v) => !v.mine)
  const entry = (v: SavedView): MenuEntry => ({ label: v.name, icon: v.shared ? Users : Bookmark, hint: v.query, onClick: () => onApply(v) })
  const items: MenuEntry[] = [
    ...(mine.length ? [{ group: t('views.mine') }, ...mine.map(entry)] : []),
    ...(shared.length ? [{ group: t('views.shared') }, ...shared.map(entry)] : []),
    ...(!views.length ? [{ group: t('views.none') }] : []),
    'sep',
    { label: t('views.save'), icon: BookmarkPlus, onClick: () => setSaving(true) },
    ...mine.map((v) => ({
      label: `${t('common.delete')}: ${v.name}`,
      icon: Trash2,
      danger: true,
      onClick: () =>
        del.mutate(v.id, {
          onSuccess: () => toast(t('views.deleted')),
          onError: (e) => toast(errorText(e), 'error'),
        }),
    })),
  ]
  return (
    <>
      <ActionMenu
        trigger={
          <button type="button" className="btn">
            <Bookmark size={15} aria-hidden /> {t('views.title')}
          </button>
        }
        items={items}
      />
      {saving && <SaveViewDialog list={list} current={current} canShare={canShare} onClose={() => setSaving(false)} />}
    </>
  )
}

function SaveViewDialog({ list, current, canShare, onClose }: { list: string; current: ViewState; canShare: boolean; onClose: () => void }) {
  const t = useT()
  const save = useSaveView(list)
  const [name, setName] = useState('')
  const [shared, setShared] = useState(false)
  const [error, setError] = useState<string>()
  const submit = () =>
    save.mutate(
      { list, name, query: current.query, sort: current.sort ?? '', columns: current.columns ?? [], shared },
      {
        onSuccess: () => {
          toast(t('views.savedToast', { name }))
          onClose()
        },
        onError: (e) => setError(errorText(e)),
      },
    )
  return (
    <Modal
      open
      onClose={onClose}
      title={t('views.save')}
      description={<span className="font-mono text-[12.5px]">{current.query || '–'}</span>}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn btn-primary" disabled={!name.trim() || save.isPending} onClick={submit}>
            {t('common.save')}
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <Field label={t('views.name')} required error={error}>
          {({ id, describedBy, invalid }) => (
            <input id={id} className="field" aria-describedby={describedBy} aria-invalid={invalid || undefined} value={name} maxLength={100} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && submit()} />
          )}
        </Field>
        {canShare && (
          <div className="flex items-start justify-between gap-4">
            <div>
              <label htmlFor="view-share" className="text-[13px] font-medium">
                {t('views.share')}
              </label>
              <p className="text-[12.5px] text-muted">{t('views.shareHelp')}</p>
            </div>
            <Switch id="view-share" checked={shared} onChange={setShared} label={t('views.share')} />
          </div>
        )}
      </div>
    </Modal>
  )
}
