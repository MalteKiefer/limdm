// The own profile: account, appearance and language (kept in this
// browser), and for local accounts password, authenticator app and
// recovery codes. Help: glossary, device states, roles, action impact.
import { useQuery } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { z } from 'zod'
import { api, unwrap } from '../../api/client'
import { useMe } from '../../api/me'
import { FormSection } from '../../components/form'
import { ErrorState, LoadingState } from '../../components/states'
import { toast } from '../../components/toast'
import { Badge, Card, PageHeader, Segmented, StatusPill, type DeviceStatus } from '../../components/ui'
import { currentLocale, useT, type MessageKey } from '../../i18n'
import { setPrefs, usePrefs, type Density, type Theme } from '../../lib/prefs'
import { useAction, useProfile } from './api'
import { Facts, OnceSecret, SettingsForm, TextField } from '../../components/settingsform'

export function ProfilePage() {
  const t = useT()
  const me = useMe()
  const p = usePrefs()
  const q = useProfile()
  return (
    <div>
      <PageHeader title={t('settings.profile.title')} sub={me.login} />
      <div className="card px-[var(--pad-card)]">
        <FormSection title={t('settings.profile.account')}>
          <Facts
            rows={[
              [t('settings.users.login'), <span className="font-mono">{me.login}</span>],
              [t('settings.users.role'), t(`role.${me.role}` as MessageKey)],
              [t('settings.users.type'), q.data?.local ? t('settings.users.local') : 'OIDC'],
              ...(me.tenant ? [[t('settings.users.tenant'), me.tenant.name] as [string, string]] : []),
              ...(me.scope_tags.length || me.scope_groups.length ? [[t('settings.users.scope'), [...me.scope_tags, ...me.scope_groups].join(', ')] as [string, string]] : []),
            ]}
          />
          {q.data && !q.data.local && <p className="text-[12.5px] text-muted">{t('settings.profile.oidc')}</p>}
        </FormSection>
        <FormSection title={t('settings.profile.appearance')} description={t('settings.profile.appearanceHelp')}>
          <Segmented<'de' | 'en'> label={t('settings.profile.language')} value={currentLocale()} onChange={(v) => setPrefs({ locale: v })} options={[{ value: 'de', label: 'Deutsch' }, { value: 'en', label: 'English' }]} />
          <Segmented<Theme> label={t('settings.profile.theme')} value={p.theme} onChange={(v) => setPrefs({ theme: v })} options={[{ value: 'system', label: t('settings.profile.system') }, { value: 'light', label: t('settings.profile.light') }, { value: 'dark', label: t('settings.profile.dark') }]} />
          <Segmented<Density> label={t('settings.profile.density')} value={p.density} onChange={(v) => setPrefs({ density: v })} options={[{ value: 'comfortable', label: t('settings.profile.comfortable') }, { value: 'compact', label: t('settings.profile.compact') }]} />
        </FormSection>
        {q.isPending && <LoadingState rows={3} />}
        {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
        {q.data?.local && (
          <>
            <ChangePassword min={q.data.password_min} />
            <Authenticator pending={q.data.totp_pending} />
            <Recovery left={q.data.recovery_left} />
          </>
        )}
      </div>
    </div>
  )
}

function ChangePassword({ min }: { min: number }) {
  const t = useT()
  const save = useAction(['settings', 'profile'], (body: { current: string; new: string; repeat: string }) => unwrap(api.POST('/api/v1/profile/password', { body })))
  return (
    <SettingsForm
      schema={z
        .object({ current: z.string().min(1, t('settings.err.required')), new: z.string().min(min, t('settings.profile.tooShort', { n: min })).max(256), repeat: z.string() })
        .refine((v) => v.new === v.repeat, { path: ['repeat'], message: t('settings.profile.mismatch') })}
      values={{ current: '', new: '', repeat: '' }}
      okText={t('settings.profile.changed')}
      onSave={async (v) => {
        await save.mutateAsync(v)
      }}
    >
      {(f) => (
        <FormSection title={t('settings.profile.password')} description={t('settings.profile.passwordHelp', { n: min })}>
          <TextField form={f} name="current" type="password" autoComplete="current-password" label={t('settings.profile.current')} required />
          <TextField form={f} name="new" type="password" autoComplete="new-password" label={t('settings.profile.new')} required />
          <TextField form={f} name="repeat" type="password" autoComplete="new-password" label={t('settings.profile.repeat')} required />
        </FormSection>
      )}
    </SettingsForm>
  )
}

function Authenticator({ pending }: { pending: boolean }) {
  const t = useT()
  const [secret, setSecret] = useState<{ secret: string; uri: string } | null>(null)
  const [qrV, setQrV] = useState(0)
  const key = ['settings', 'profile']
  const start = useAction(key, (current: string) => unwrap(api.POST('/api/v1/profile/totp/{step}', { params: { path: { step: 'start' } }, body: { current } })))
  const confirm = useAction(key, (code: string) => unwrap(api.POST('/api/v1/profile/totp/{step}', { params: { path: { step: 'confirm' } }, body: { code } })), t('settings.profile.totpDone'))
  const cancel = useAction(key, () => unwrap(api.POST('/api/v1/profile/totp/{step}', { params: { path: { step: 'cancel' } }, body: {} })))
  const active = pending || !!secret
  return (
    <FormSection title={t('settings.profile.totp')} description={t('settings.profile.totpHelp')}>
      {!active ? (
        <SettingsForm
          schema={z.object({ current: z.string().min(1, t('settings.err.required')) })}
          values={{ current: '' }}
          okText={t('settings.profile.totpScan')}
          onSave={async (v) => {
            const r = await start.mutateAsync(v.current)
            setSecret(r as { secret: string; uri: string })
            setQrV((n) => n + 1)
          }}
        >
          {(f) => <TextField form={f} name="current" type="password" autoComplete="current-password" label={t('settings.profile.current')} help={t('settings.profile.totpStart')} required />}
        </SettingsForm>
      ) : (
        <>
          <img src={`/api/v1/profile/totp/qr.svg?v=${qrV}`} alt={t('settings.profile.qr')} className="size-48 rounded-md border border-line bg-white p-2" />
          {secret && <Facts rows={[[t('settings.profile.secret'), <code className="font-mono text-[12.5px] break-all">{secret.secret}</code>]]} />}
          <SettingsForm
            schema={z.object({ code: z.string().trim().regex(/^\d{6}$/, t('settings.profile.codeBad')) })}
            values={{ code: '' }}
            okText={t('settings.profile.totpDone')}
            onSave={async (v) => {
              await confirm.mutateAsync(v.code.trim())
              setSecret(null)
            }}
          >
            {(f) => <TextField form={f} name="code" label={t('settings.profile.code')} autoComplete="one-time-code" required />}
          </SettingsForm>
          <button
            type="button"
            className="btn self-start"
            onClick={() =>
              void cancel.mutateAsync(undefined).then(() => {
                setSecret(null)
                toast(t('settings.profile.totpCancelled'))
              })
            }
          >
            {t('common.cancel')}
          </button>
        </>
      )}
    </FormSection>
  )
}

function Recovery({ left }: { left: number }) {
  const t = useT()
  const [codes, setCodes] = useState('')
  const gen = useAction(['settings', 'profile'], (current: string) => unwrap(api.POST('/api/v1/profile/recovery-codes', { body: { current } })))
  return (
    <SettingsForm
      schema={z.object({ current: z.string().min(1, t('settings.err.required')) })}
      values={{ current: '' }}
      okText={t('settings.profile.codesNew')}
      onSave={async (v) => {
        const r = await gen.mutateAsync(v.current)
        setCodes(r.codes.join('\n'))
      }}
    >
      {(f) => (
        <FormSection title={t('settings.profile.recovery')} description={t('settings.profile.recoveryHelp')}>
          <p>
            <Badge tone={left > 2 ? 'ok' : 'warn'}>{t('settings.profile.left', { n: left })}</Badge>
          </p>
          <TextField form={f} name="current" type="password" autoComplete="current-password" label={t('settings.profile.current')} help={t('settings.profile.codesReplace')} required />
          {codes && <OnceSecret title={t('settings.profile.recovery')} value={codes} onClose={() => setCodes('')} />}
        </FormSection>
      )}
    </SettingsForm>
  )
}

// ---- help ----

const states: DeviceStatus[] = ['compliant', 'in grace', 'non-compliant', 'stale', 'pending', 'retired']

export function HelpPage() {
  const t = useT()
  const lang = currentLocale()
  const q = useQuery({ queryKey: ['settings', 'glossary', lang], queryFn: () => unwrap(api.GET('/api/v1/glossary', { params: { query: { lang } } })), staleTime: 300_000 })
  const [filter, setFilter] = useState('')
  const terms = (q.data?.terms ?? []).filter((x) => !filter || `${x.term} ${x.text}`.toLowerCase().includes(filter.toLowerCase()))
  return (
    <div>
      <PageHeader
        title={t('settings.help.title')}
        sub={t('settings.help.sub')}
        actions={
          <a className="btn" href={`${q.data?.docs ?? 'https://github.com/MalteKiefer/limdm/blob/main/docs/'}concepts.md`} target="_blank" rel="noopener noreferrer">
            <ExternalLink size={14} aria-hidden /> {t('settings.help.docs')}
          </a>
        }
      />
      <div className="grid gap-[var(--gap)] lg:grid-cols-[minmax(0,1fr)_380px]">
        <Card title={t('settings.help.glossary')}>
          <label className="mb-3 block">
            <span className="sr-only">{t('settings.help.filter')}</span>
            <input className="field" type="search" placeholder={t('settings.help.filter')} value={filter} onChange={(e) => setFilter(e.target.value)} />
          </label>
          {q.isPending && <LoadingState rows={6} />}
          {q.isError && <ErrorState error={q.error} onRetry={() => void q.refetch()} />}
          <dl className="flex flex-col gap-3">
            {terms.map((x) => (
              <div key={x.id} id={x.id} className="scroll-mt-20">
                <dt className="font-semibold">{x.term}</dt>
                <dd className="text-[13px] text-fg-2">
                  {x.text}{' '}
                  {x.doc && (
                    <a className="text-accent underline-offset-2 hover:underline" href={x.doc} target="_blank" rel="noopener noreferrer">
                      {t('settings.help.more')}
                    </a>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </Card>
        <div className="flex flex-col gap-[var(--gap)]">
          <Card title={t('settings.help.states')} id="status">
            <dl className="flex flex-col gap-2.5">
              {states.map((s) => (
                <div key={s}>
                  <dt>
                    <StatusPill status={s} />
                  </dt>
                  <dd className="mt-1 text-[13px] text-fg-2">{q.data?.states[s]}</dd>
                </div>
              ))}
            </dl>
          </Card>
          <Card title={t('settings.help.roles')} id="roles">
            <dl className="flex flex-col gap-2.5">
              {(['admin', 'helpdesk', 'auditor'] as const).map((r) => (
                <div key={r}>
                  <dt className="font-semibold">{t(`role.${r}` as MessageKey)}</dt>
                  <dd className="text-[13px] text-fg-2">{t(`settings.users.roleHelp.${r}` as MessageKey)}</dd>
                </div>
              ))}
            </dl>
          </Card>
          <Card title={t('settings.help.impact')}>
            <ol className="flex list-decimal flex-col gap-2 pl-5 text-[13px]">
              {(['lock', 'lost', 'retire', 'wipe'] as const).map((k) => (
                <li key={k}>
                  <strong>{t(`settings.help.impact.${k}` as MessageKey)}</strong> <span className="text-fg-2">{t(`settings.help.impactText.${k}` as MessageKey)}</span>
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>
    </div>
  )
}
