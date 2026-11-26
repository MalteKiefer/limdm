// Blueprint choice for every area (enrollment tokens, device assignment).
// It shares the query key of the config area, so both read one cache.
import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from '../api/client'
import { useT } from '../i18n'

/** Value 0 means none (default or the directory group decides); pilot copies are hidden. */
export function BlueprintSelect({ value, onChange, id, describedBy, noneLabel }: { value: number; onChange: (id: number) => void; id?: string; describedBy?: string; noneLabel?: string }) {
  const t = useT()
  const q = useQuery({ queryKey: ['config', 'blueprints'], queryFn: () => unwrap(api.GET('/api/v1/config/blueprints')) })
  return (
    <select id={id} aria-describedby={describedBy} className="field" value={value} onChange={(e) => onChange(Number(e.target.value))} disabled={!q.data}>
      <option value={0}>{noneLabel ?? t('config.defaultOnly')}</option>
      {(q.data?.items ?? [])
        .filter((b) => b.name !== 'default' && !b.pilot_of)
        .map((b) => (
          <option key={b.id} value={b.id}>
            {b.name}
            {b.description ? ` (${b.description})` : ''}
          </option>
        ))}
    </select>
  )
}
