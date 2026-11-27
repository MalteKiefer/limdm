// Settings section "CVE data": the daily import of the Debian, Ubuntu,
// Arch and Alpine security data and the CISA KEV list, each off by default
// (it downloads from third parties). The state of the imports and "refresh now" are in
// Updates, Security.
import { Link } from '@tanstack/react-router'
import { FormSection } from '../../components/form'
import { SectionHead, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { ErrorState, LoadingState } from '../../components/states'
import { useCan } from '../../api/me'
import { useT, type MessageKey } from '../../i18n'
import { z } from '../../lib/zod'
import { useSaveSection, useSettings } from './api'

const https = (v: string) => !v.trim() || /^https:\/\/[^\s/]+/.test(v.trim())

const feeds = [
  { id: 'debian', placeholder: 'https://security-tracker.debian.org/tracker/data/json' },
  { id: 'ubuntu', placeholder: 'https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip' },
  { id: 'arch', placeholder: 'https://security.archlinux.org/issues/all.json' },
  { id: 'alpine', placeholder: 'https://secdb.alpinelinux.org' },
  { id: 'kev', placeholder: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
] as const

export function CVEFeeds() {
  const t = useT()
  const q = useSettings()
  const save = useSaveSection('cve_feeds')
  const admin = useCan('admin')
  if (q.isPending) return <LoadingState rows={4} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const c = q.data.cve_feeds ?? {}
  const url = z.string().refine(https, t('updates.feeds.httpsOnly'))
  const schema = z.object({
    debian: z.boolean(),
    ubuntu: z.boolean(),
    arch: z.boolean(),
    alpine: z.boolean(),
    kev: z.boolean(),
    debian_url: url,
    ubuntu_url: url,
    arch_url: url,
    alpine_url: url,
    kev_url: url,
    max_mb: z.string().refine((v) => /^\d*$/.test(v.trim()) && Number(v || 0) <= 4096, t('updates.feeds.maxRange')),
  })
  const values = {
    debian: !!c.debian,
    ubuntu: !!c.ubuntu,
    arch: !!c.arch,
    alpine: !!c.alpine,
    kev: !!c.kev,
    debian_url: c.debian_url ?? '',
    ubuntu_url: c.ubuntu_url ?? '',
    arch_url: c.arch_url ?? '',
    alpine_url: c.alpine_url ?? '',
    kev_url: c.kev_url ?? '',
    max_mb: c.max_mb ? String(c.max_mb) : '',
  }
  return (
    <>
      <SectionHead title={t('settings.nav.cve')} sub={t('updates.feeds.settingsSub')} />
      <SettingsForm
        readOnly={!admin}
        schema={schema}
        values={values}
        onSave={(v) =>
          save.mutateAsync({
            cve_feeds: {
              ...v,
              debian_url: v.debian_url.trim(),
              ubuntu_url: v.ubuntu_url.trim(),
              arch_url: v.arch_url.trim(),
              alpine_url: v.alpine_url.trim(),
              kev_url: v.kev_url.trim(),
              max_mb: Number(v.max_mb || 0),
            },
          })
        }
      >
        {(f) => (
          <>
            {feeds.map((x) => (
              <FormSection key={x.id} title={t(`updates.feeds.distro.${x.id}` as MessageKey)} description={t(`updates.feeds.about.${x.id}` as MessageKey)}>
                <Toggle form={f} name={x.id} label={t('updates.feeds.enabled')} />
                <TextField form={f} name={`${x.id}_url`} mono label={t(`updates.feeds.url.${x.id}` as MessageKey)} placeholder={x.placeholder} help={t('updates.feeds.urlHelp')} />
              </FormSection>
            ))}
            <FormSection title={t('updates.feeds.title')} description={t('updates.feeds.help')}>
              <TextField form={f} name="max_mb" label={t('updates.feeds.maxMB')} placeholder="1024" help={t('updates.feeds.maxMBHelp')} />
            </FormSection>
          </>
        )}
      </SettingsForm>
      <Link to="/updates" search={{ tab: 'security' } as never} className="mt-3 inline-flex text-body text-accent hover:underline">
        {t('updates.feeds.toState')}
      </Link>
    </>
  )
}
