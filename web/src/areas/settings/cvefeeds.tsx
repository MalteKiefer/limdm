// Settings section "CVE data": the daily import of the Debian and Ubuntu
// security data (off by default, it downloads from third parties). The
// state of the imports and "refresh now" are in Updates, Security.
import { Link } from '@tanstack/react-router'
import { FormSection } from '../../components/form'
import { SectionHead, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { ErrorState, LoadingState } from '../../components/states'
import { useCan } from '../../api/me'
import { useT } from '../../i18n'
import { z } from '../../lib/zod'
import { useSaveSection, useSettings } from './api'

const https = (v: string) => !v.trim() || /^https:\/\/[^\s/]+/.test(v.trim())

export function CVEFeeds() {
  const t = useT()
  const q = useSettings()
  const save = useSaveSection('cve_feeds')
  const admin = useCan('admin')
  if (q.isPending) return <LoadingState rows={4} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const c = q.data.cve_feeds ?? {}
  const schema = z.object({
    enabled: z.boolean(),
    debian_url: z.string().refine(https, t('updates.feeds.httpsOnly')),
    ubuntu_url: z.string().refine(https, t('updates.feeds.httpsOnly')),
    max_mb: z.string().refine((v) => /^\d*$/.test(v.trim()) && Number(v || 0) <= 4096, t('updates.feeds.maxRange')),
  })
  return (
    <>
      <SectionHead title={t('settings.nav.cve')} sub={t('updates.feeds.settingsSub')} />
      <SettingsForm
        readOnly={!admin}
        schema={schema}
        values={{ enabled: !!c.enabled, debian_url: c.debian_url ?? '', ubuntu_url: c.ubuntu_url ?? '', max_mb: c.max_mb ? String(c.max_mb) : '' }}
        onSave={(v) => save.mutateAsync({ cve_feeds: { enabled: v.enabled, debian_url: v.debian_url.trim(), ubuntu_url: v.ubuntu_url.trim(), max_mb: Number(v.max_mb || 0) } })}
      >
        {(f) => (
          <FormSection title={t('updates.feeds.title')} description={t('updates.feeds.help')}>
            <Toggle form={f} name="enabled" label={t('updates.feeds.enabled')} help={t('updates.feeds.enabledHelp')} />
            <TextField form={f} name="debian_url" mono label={t('updates.feeds.debianURL')} placeholder="https://security-tracker.debian.org/tracker/data/json" help={t('updates.feeds.urlHelp')} />
            <TextField form={f} name="ubuntu_url" mono label={t('updates.feeds.ubuntuURL')} placeholder="https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip" help={t('updates.feeds.urlHelp')} />
            <TextField form={f} name="max_mb" label={t('updates.feeds.maxMB')} placeholder="1024" help={t('updates.feeds.maxMBHelp')} />
          </FormSection>
        )}
      </SettingsForm>
      <Link to="/updates" search={{ tab: 'security' } as never} className="mt-3 inline-flex text-[13px] text-accent hover:underline">
        {t('updates.feeds.toState')}
      </Link>
    </>
  )
}
