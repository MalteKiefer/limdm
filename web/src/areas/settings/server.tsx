// Server settings sections: general and branding, console networks,
// privacy, sign in, password policy, four eyes approval, remote shell,
// data retention and operations. Each form saves one section of
// PATCH /api/v1/settings/{section} with only its own fields.
import { ExternalLink, ImageUp, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { z } from '../../lib/zod'
import { useCan } from '../../api/me'
import { Field, FormSection } from '../../components/form'
import { ErrorState, LoadingState } from '../../components/states'
import { Badge } from '../../components/ui'
import { useT, type MessageKey } from '../../i18n'
import { useSaveSection, useSettings, type Section, type Settings, type SettingsInput } from './api'
import { Facts, ListField, SectionHead, SelectField, SettingsForm, TextField, Toggle } from '../../components/settingsform'
import { badNet, fileBase64, isPEM, isSyslog, lines, parseRoleGroups, roleGroupsText, unlines } from './logic'
import { blobURL } from '../../lib/blob'


/** Loads the settings once and hands them to a section. */
function WithSettings({ children }: { children: (s: Settings, save: (section: Section, body: SettingsInput) => Promise<unknown>, readOnly: boolean) => ReactNode }) {
  const q = useSettings()
  const admin = useCan('admin')
  const saves = {
    general: useSaveSection('general'),
    network: useSaveSection('network'),
    security: useSaveSection('security'),
    remote_shell: useSaveSection('remote_shell'),
    sso: useSaveSection('sso'),
    monitoring: useSaveSection('monitoring'),
    branding: useSaveSection('branding'),
    operations: useSaveSection('operations'),
    retention: useSaveSection('retention'),
    enrollment: useSaveSection('enrollment'),
    cve_feeds: useSaveSection('cve_feeds'),
  }
  if (q.isPending) return <LoadingState rows={6} />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  return <>{children(q.data, (section, body) => saves[section].mutateAsync(body), !admin)}</>
}

const netList = (msg: (bad: string) => string) =>
  z.string().superRefine((v, ctx) => {
    const bad = badNet(v)
    if (bad) ctx.addIssue({ code: 'custom', message: msg(bad) })
  })

export function General() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.general')} sub={t('settings.general.sub')} />
          <SettingsForm
            readOnly={ro}
            schema={z.object({ stale_hours: z.number({ message: t('settings.err.number') }).int().min(1, t('settings.general.staleRange')).max(2160, t('settings.general.staleRange')) })}
            values={{ stale_hours: s.stale_hours }}
            onSave={(v) => save('general', v)}
          >
            {(f) => (
              <FormSection title={t('settings.general.devices')} description={t('settings.general.devicesHelp')}>
                <TextField form={f} name="stale_hours" type="number" label={t('settings.general.stale')} help={t('settings.general.staleHelp')} required />
                <Facts rows={[[t('settings.general.publicUrl'), <span className="font-mono">{s.public_url}</span>]]} />
              </FormSection>
            )}
          </SettingsForm>
          <Branding s={s} save={save} ro={ro} />
        </>
      )}
    </WithSettings>
  )
}

function Branding({ s, save, ro }: { s: Settings; save: (section: Section, body: SettingsInput) => Promise<unknown>; ro: boolean }) {
  const t = useT()
  const [logo, setLogo] = useState<{ b64: string; url: string } | null>(null)
  const [remove, setRemove] = useState(false)
  const [v, setV] = useState(0) // reloads the logo preview after a save
  return (
    <SettingsForm
      readOnly={ro}
      schema={z.object({ company_name: z.string().max(80, t('settings.branding.nameLong')), logo: z.string() })}
      values={{ company_name: s.company_name ?? '', logo: '' }}
      onSave={async (x) => {
        await save('branding', { company_name: x.company_name, ...(logo ? { logo_png: logo.b64 } : {}), ...(remove ? { remove_logo: true } : {}) })
        setLogo(null)
        setRemove(false)
        setV((n) => n + 1)
      }}
    >
      {(f) => (
        <FormSection title={t('settings.branding.title')} description={t('settings.branding.help')}>
          <TextField form={f} name="company_name" label={t('settings.branding.name')} help={t('settings.branding.nameHelp')} />
          <Field label={t('settings.branding.logo')} help={t('settings.branding.logoHelp')}>
            {({ id, describedBy }) => (
              <div className="flex flex-wrap items-center gap-3">
                {(logo || (s.has_logo && !remove)) && <img src={blobURL(logo?.url) ?? `/branding/logo.png?v=${v}`} alt={t('settings.branding.preview')} className="size-14 rounded-md border border-line bg-surface-2 object-contain" />}
                <label className="btn cursor-pointer">
                  <ImageUp size={14} aria-hidden /> {t('settings.branding.choose')}
                  <input
                    id={id}
                    aria-describedby={describedBy}
                    type="file"
                    accept="image/png"
                    className="sr-only"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (!file) return
                      void fileBase64(file).then((b64) => {
                        setLogo({ b64, url: URL.createObjectURL(file) })
                        setRemove(false)
                        f.setValue('logo', file.name, { shouldDirty: true })
                      })
                    }}
                  />
                </label>
                {s.has_logo && !remove && !logo && (
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => {
                      setRemove(true)
                      f.setValue('logo', 'remove', { shouldDirty: true })
                    }}
                  >
                    <Trash2 size={14} aria-hidden /> {t('settings.branding.remove')}
                  </button>
                )}
              </div>
            )}
          </Field>
        </FormSection>
      )}
    </SettingsForm>
  )
}

export function Access() {
  const t = useT()
  const bad = (x: string) => t('settings.err.net', { value: x })
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.access')} sub={t('settings.access.sub')} />
          <SettingsForm
            readOnly={ro}
            schema={z.object({ console_allow: netList(bad), console_block: netList(bad), scim_allow: netList(bad) })}
            values={{ console_allow: unlines(s.console_allow), console_block: unlines(s.console_block), scim_allow: unlines(s.scim_allow) }}
            onSave={(v) => save('network', { console_allow: lines(v.console_allow), console_block: lines(v.console_block), scim_allow: lines(v.scim_allow) })}
          >
            {(f) => (
              <>
                <FormSection title={t('settings.access.console')} description={t('settings.access.consoleHelp', { ip: s.client_ip })}>
                  <ListField form={f} name="console_allow" label={t('settings.access.allow')} help={t('settings.access.allowHelp')} placeholder="10.0.0.0/8 2001:db8::/32" />
                  <ListField form={f} name="console_block" label={t('settings.access.block')} help={t('settings.access.blockHelp')} placeholder="203.0.113.0/24" />
                  <p className="text-meta text-muted">{t('settings.access.lockout')}</p>
                </FormSection>
                <FormSection title={t('settings.access.scim')} description={t('settings.access.scimHelp')}>
                  <ListField form={f} name="scim_allow" label={t('settings.access.scimAllow')} help={t('settings.access.empty')} placeholder="198.51.100.0/24" rows={2} />
                </FormSection>
              </>
            )}
          </SettingsForm>
        </>
      )}
    </WithSettings>
  )
}

/** Limits of new enrollment tokens and the TPM requirement. */
export function Enrollment() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => {
        const e = s.enrollment
        const n = (max: number) => z.number({ message: t('settings.err.number') }).int().min(1, t('settings.enroll.range', { max })).max(max, t('settings.enroll.range', { max }))
        return (
          <>
            <SectionHead title={t('settings.nav.enroll')} sub={t('settings.enroll.sub')} />
            <SettingsForm
              readOnly={ro}
              schema={z
                .object({ max_uses: n(500), max_days: n(30), default_uses: n(500), default_days: n(30), require_tpm: z.boolean() })
                .refine((v) => v.default_uses <= v.max_uses, { path: ['default_uses'], message: t('settings.enroll.aboveMax') })
                .refine((v) => v.default_days <= v.max_days, { path: ['default_days'], message: t('settings.enroll.aboveMax') })}
              values={{ max_uses: e.max_uses, max_days: e.max_days, default_uses: e.default_uses, default_days: e.default_days, require_tpm: e.require_tpm }}
              onSave={(v) => save('enrollment', { enrollment: v })}
            >
              {(f) => (
                <>
                  <FormSection title={t('settings.enroll.tokens')} description={t('settings.enroll.tokensHelp')}>
                    <TextField form={f} name="max_uses" type="number" label={t('settings.enroll.maxUses')} help={t('settings.enroll.range', { max: 500 })} required />
                    <TextField form={f} name="max_days" type="number" label={t('settings.enroll.maxDays')} help={t('settings.enroll.range', { max: 30 })} required />
                    <TextField form={f} name="default_uses" type="number" label={t('settings.enroll.defaultUses')} required />
                    <TextField form={f} name="default_days" type="number" label={t('settings.enroll.defaultDays')} required />
                  </FormSection>
                  <FormSection title={t('settings.enroll.tpm')} description={t('settings.enroll.tpmHelp')}>
                    <Toggle form={f} name="require_tpm" label={t('settings.enroll.requireTpm')} help={t('settings.enroll.requireTpmHelp')} />
                  </FormSection>
                </>
              )}
            </SettingsForm>
          </>
        )
      }}
    </WithSettings>
  )
}

export function Privacy() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.privacy')} sub={t('settings.privacy.sub')} />
          <SettingsForm readOnly={ro} schema={z.object({ geolocation: z.boolean(), fallback_dns: z.boolean() })} values={{ geolocation: !!s.geolocation, fallback_dns: !!s.fallback_dns }} onSave={(v) => save('security', v)}>
            {(f) => (
              <FormSection title={t('settings.privacy.title')} description={t('settings.privacy.help')}>
                <Toggle form={f} name="geolocation" label={t('settings.privacy.geo')} help={t('settings.privacy.geoHelp')} />
                <Toggle form={f} name="fallback_dns" label={t('settings.privacy.dns')} help={t('settings.privacy.dnsHelp')} />
              </FormSection>
            )}
          </SettingsForm>
        </>
      )}
    </WithSettings>
  )
}

export function SignIn() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.signin')} sub={t('settings.signin.sub')} />
          <SettingsForm readOnly={ro} schema={z.object({ local_login: z.boolean() })} values={{ local_login: !!s.local_login }} onSave={(v) => save('general', v)}>
            {(f) => (
              <FormSection title={t('settings.signin.local')} description={t('settings.signin.localHelp')}>
                <Toggle form={f} name="local_login" label={t('settings.signin.localToggle')} />
              </FormSection>
            )}
          </SettingsForm>
          <SettingsForm
            readOnly={ro}
            schema={z
              .object({
                oidc_issuer: z.string().refine((v) => !v.trim() || v.trim().startsWith('https://'), t('settings.signin.issuerHttps')),
                oidc_client_id: z.string(),
                oidc_client_secret: z.string(),
                clear_secret: z.boolean(),
                allowed_domain: z.string(),
                require_mfa: z.boolean(),
                mfa_acr: z.string(),
                role_groups: z.string().superRefine((v, ctx) => {
                  const r = parseRoleGroups(v)
                  if (r.error) ctx.addIssue({ code: 'custom', message: t('settings.signin.groupLine', { line: r.error }) })
                }),
              })
              .refine((v) => !v.oidc_issuer.trim() || v.oidc_client_id.trim(), { path: ['oidc_client_id'], message: t('settings.signin.clientNeeded') })}
            values={{
              oidc_issuer: s.oidc_issuer ?? '',
              oidc_client_id: s.oidc_client_id ?? '',
              oidc_client_secret: '',
              clear_secret: false,
              allowed_domain: s.allowed_domain ?? '',
              require_mfa: !!s.require_mfa,
              mfa_acr: (s.mfa_acr ?? []).join(' '),
              role_groups: roleGroupsText(s.role_groups),
            }}
            onSave={(v) =>
              save('sso', {
                oidc_issuer: v.oidc_issuer,
                oidc_client_id: v.oidc_client_id,
                allowed_domain: v.allowed_domain,
                require_mfa: v.require_mfa,
                mfa_acr: lines(v.mfa_acr),
                role_groups: parseRoleGroups(v.role_groups).groups,
                ...(v.oidc_client_secret ? { oidc_client_secret: v.oidc_client_secret } : {}),
                ...(v.clear_secret ? { clear_secret: true } : {}),
              })
            }
          >
            {(f) => (
              <>
                <FormSection title={t('settings.signin.oidc')} description={t('settings.signin.oidcHelp')}>
                  <Facts rows={[[t('settings.signin.redirect'), <code className="font-mono text-meta break-all">{s.redirect_uri}</code>]]} />
                  <TextField form={f} name="oidc_issuer" label={t('settings.signin.issuer')} placeholder="https://accounts.google.com" mono />
                  <TextField form={f} name="oidc_client_id" label={t('settings.signin.clientId')} mono />
                  <TextField form={f} name="oidc_client_secret" type="password" autoComplete="new-password" label={t('settings.signin.secret')} help={s.has_oidc_secret ? t('settings.signin.secretKept') : t('settings.signin.secretNone')} />
                  {s.has_oidc_secret && <Toggle form={f} name="clear_secret" label={t('settings.signin.secretClear')} />}
                  <TextField form={f} name="allowed_domain" label={t('settings.signin.domain')} help={t('settings.signin.domainHelp')} placeholder="example.com" />
                  <p className="text-meta text-muted">{t('settings.signin.checked')}</p>
                </FormSection>
                <FormSection title={t('settings.signin.mfa')} description={t('settings.signin.mfaHelp')}>
                  <Toggle form={f} name="require_mfa" label={t('settings.signin.mfaToggle')} help={t('settings.signin.mfaToggleHelp')} />
                  <TextField form={f} name="mfa_acr" label={t('settings.signin.acr')} help={t('settings.signin.acrHelp')} mono />
                </FormSection>
                <FormSection title={t('settings.signin.groups')} description={t('settings.signin.groupsHelp')}>
                  <ListField form={f} name="role_groups" label={t('settings.signin.groupsField')} help={t('settings.signin.groupsFormat')} placeholder={'it-admins; admin\nsupport; helpdesk; berlin,munich'} rows={4} />
                </FormSection>
              </>
            )}
          </SettingsForm>
          <FormSection title={t('settings.signin.scim')} description={t('settings.signin.scimHelp')}>
            <a className="btn self-start" href="/app/settings?s=directory">
              {t('settings.nav.directory')}
            </a>
          </FormSection>
        </>
      )}
    </WithSettings>
  )
}

export function Password() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.password')} sub={t('settings.password.sub')} />
          <SettingsForm
            readOnly={ro}
            schema={z.object({
              min_length: z.number({ message: t('settings.err.number') }).int().min(12, t('settings.password.range')).max(128, t('settings.password.range')),
              upper: z.boolean(),
              lower: z.boolean(),
              digit: z.boolean(),
              symbol: z.boolean(),
              no_name: z.boolean(),
            })}
            values={{ min_length: Math.max(s.password_policy.min_length ?? 0, 12), upper: !!s.password_policy.upper, lower: !!s.password_policy.lower, digit: !!s.password_policy.digit, symbol: !!s.password_policy.symbol, no_name: !!s.password_policy.no_name }}
            onSave={(v) => save('security', { password_policy: v })}
          >
            {(f) => (
              <FormSection title={t('settings.password.title')} description={t('settings.password.help')}>
                <TextField form={f} name="min_length" type="number" label={t('settings.password.min')} help={t('settings.password.range')} required />
                <Toggle form={f} name="upper" label={t('settings.password.upper')} />
                <Toggle form={f} name="lower" label={t('settings.password.lower')} />
                <Toggle form={f} name="digit" label={t('settings.password.digit')} />
                <Toggle form={f} name="symbol" label={t('settings.password.symbol')} />
                <Toggle form={f} name="no_name" label={t('settings.password.noName')} />
              </FormSection>
            )}
          </SettingsForm>
        </>
      )}
    </WithSettings>
  )
}

export function Approvals() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead title={t('settings.nav.approvals')} sub={t('settings.approvals.sub')} />
          <SettingsForm
            readOnly={ro}
            schema={z.object({ four_eyes: z.boolean(), four_eyes_recovery: z.boolean(), four_eyes_shell: z.boolean() })}
            values={{ four_eyes: !!s.four_eyes, four_eyes_recovery: !!s.four_eyes_recovery, four_eyes_shell: !!s.four_eyes_shell }}
            onSave={(v) => save('security', v)}
          >
            {(f) => {
              const on = f.watch('four_eyes')
              return (
                <FormSection title={t('settings.approvals.title')} description={t('settings.approvals.help')}>
                  <Toggle form={f} name="four_eyes" label={t('settings.approvals.toggle')} help={t('settings.approvals.twoAdmins')} />
                  <Toggle form={f} name="four_eyes_recovery" label={t('settings.approvals.recovery')} disabled={!on} />
                  <Toggle form={f} name="four_eyes_shell" label={t('settings.approvals.shell')} disabled={!on} />
                  <a className="text-body text-accent underline-offset-2 hover:underline" href="/app/inbox">
                    {t('settings.approvals.inbox')}
                  </a>
                </FormSection>
              )
            }}
          </SettingsForm>
        </>
      )}
    </WithSettings>
  )
}

export function RemoteShell() {
  const t = useT()
  const minutes = (lo: number, hi: number) =>
    z.union([z.nan(), z.number().int().min(lo, t('settings.shell.range', { lo, hi })).max(hi, t('settings.shell.range', { lo, hi }))])
  return (
    <WithSettings>
      {(s, save, ro) => {
        const rs = s.remote_shell ?? {}
        return (
          <>
            <SectionHead title={t('settings.nav.shell')} sub={t('settings.shell.sub')} />
            <SettingsForm
              readOnly={ro}
              schema={z.object({ enabled: z.boolean(), helpdesk: z.boolean(), allow_root: z.boolean(), max_minutes: minutes(5, 480), idle_minutes: minutes(1, 120) })}
              values={{ enabled: !!rs.enabled, helpdesk: !!rs.helpdesk, allow_root: !!rs.allow_root, max_minutes: rs.max_minutes || NaN, idle_minutes: rs.idle_minutes || NaN }}
              onSave={(v) => save('remote_shell', { remote_shell: { ...v, max_minutes: v.max_minutes || 0, idle_minutes: v.idle_minutes || 0 } })}
            >
              {(f) => (
                <FormSection title={t('settings.shell.title')} description={t('settings.shell.help')}>
                  <Toggle form={f} name="enabled" label={t('settings.shell.enabled')} />
                  <Toggle form={f} name="helpdesk" label={t('settings.shell.helpdesk')} />
                  <Toggle form={f} name="allow_root" label={t('settings.shell.root')} />
                  <TextField form={f} name="max_minutes" type="number" label={t('settings.shell.max')} placeholder="60" help={t('settings.shell.emptyDefault')} />
                  <TextField form={f} name="idle_minutes" type="number" label={t('settings.shell.idle')} placeholder="15" help={t('settings.shell.emptyDefault')} />
                </FormSection>
              )}
            </SettingsForm>
          </>
        )
      }}
    </WithSettings>
  )
}

const retentionKeys = ['audit', 'device_events', 'compliance', 'commands', 'script_results', 'diagnostics', 'shell_transcripts', 'metrics', 'notification_log'] as const

export function Retention() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => {
        const kinds = s.retention_kinds
        const shape = Object.fromEntries(
          kinds.map((k) => [
            k.key,
            z
              .number({ message: t('settings.err.number') })
              .int()
              .refine((d) => (k.forever && d === 0) || (d >= k.min && d <= k.max), t('settings.retention.range', { min: k.min, max: k.max })),
          ]),
        )
        return (
          <>
            <SectionHead title={t('settings.nav.retention')} sub={t('settings.retention.sub')} />
            <SettingsForm readOnly={ro} schema={z.object(shape) as z.ZodType<Record<string, number>, Record<string, number>>} values={Object.fromEntries(kinds.map((k) => [k.key, k.days]))} onSave={(v) => save('retention', { retention: v })}>
              {(f) => (
                <FormSection title={t('settings.retention.title')} description={t('settings.retention.help')}>
                  {kinds.map((k) => {
                    const known = (retentionKeys as readonly string[]).includes(k.key)
                    return (
                      <TextField
                        key={k.key}
                        form={f}
                        name={k.key}
                        type="number"
                        label={known ? t(`settings.retention.k.${k.key}` as MessageKey) : k.key}
                        help={
                          <>
                            {known && t(`settings.retention.h.${k.key}` as MessageKey)} {t('settings.retention.bounds', { min: k.min, max: k.max, def: k.default })}
                            {k.forever && ` ${t('settings.retention.forever')}`}
                          </>
                        }
                      />
                    )
                  })}
                  <p className="text-meta text-muted">{t('settings.retention.backups')}</p>
                </FormSection>
              )}
            </SettingsForm>
          </>
        )
      }}
    </WithSettings>
  )
}

export function Operations() {
  const t = useT()
  return (
    <WithSettings>
      {(s, save, ro) => (
        <>
          <SectionHead
            title={t('settings.nav.operations')}
            sub={t('settings.ops.sub')}
            actions={
              <a className="btn" href="/metrics">
                <ExternalLink size={14} aria-hidden /> /metrics
              </a>
            }
          />
          <SettingsForm
            readOnly={ro}
            schema={z.object({
              log_level: z.enum(['debug', 'info', 'warn', 'error']),
              access_log: z.boolean(),
              audit_api_reads: z.enum(['off', 'sensitive', 'all']),
              update_downloads: z.number({ message: t('settings.err.number') }).int().min(1, t('settings.ops.limit')).max(10000, t('settings.ops.limit')),
              max_checkins: z.number({ message: t('settings.err.number') }).int().min(1, t('settings.ops.limit')).max(10000, t('settings.ops.limit')),
              agent_proxy_protocol: netList((x) => t('settings.err.net', { value: x })),
              syslog: z.string().refine(isSyslog, t('settings.ops.syslogBad')),
              syslog_ca: z.string().refine(isPEM, t('settings.ops.pemBad')),
            })}
            values={{ ...s.ops, agent_proxy_protocol: unlines(s.ops.agent_proxy_protocol) }}
            onSave={(v) => save('operations', { ops: { ...v, agent_proxy_protocol: lines(v.agent_proxy_protocol) } })}
          >
            {(f) => (
              <>
                <FormSection title={t('settings.ops.logging')}>
                  <SelectField form={f} name="log_level" label={t('settings.ops.level')} options={['debug', 'info', 'warn', 'error'].map((x) => ({ value: x, label: x }))} />
                  <Toggle form={f} name="access_log" label={t('settings.ops.access')} />
                  <SelectField
                    form={f}
                    name="audit_api_reads"
                    label={t('settings.ops.reads')}
                    help={t('settings.ops.readsHelp')}
                    options={[
                      { value: 'off', label: t('settings.ops.readsOff') },
                      { value: 'sensitive', label: t('settings.ops.readsSensitive') },
                      { value: 'all', label: t('settings.ops.readsAll') },
                    ]}
                  />
                </FormSection>
                <FormSection title={t('settings.ops.limits')} description={t('settings.ops.limitsHelp')}>
                  <TextField form={f} name="update_downloads" type="number" label={t('settings.ops.downloads')} required />
                  <TextField form={f} name="max_checkins" type="number" label={t('settings.ops.checkins')} help={t('settings.ops.checkinsHelp')} required />
                </FormSection>
                <FormSection title={t('settings.ops.listener')}>
                  <ListField form={f} name="agent_proxy_protocol" label={t('settings.ops.proxy')} help={t('settings.ops.proxyHelp')} placeholder="10.0.0.5 10.0.0.6" rows={2} />
                </FormSection>
                <FormSection title={t('settings.ops.syslog')} description={t('settings.ops.syslogHelp')}>
                  <TextField form={f} name="syslog" label={t('settings.ops.target')} placeholder="tcp+tls://siem.example.com:6514" mono />
                  <ListField form={f} name="syslog_ca" label={t('settings.ops.ca')} help={t('settings.ops.caHelp')} placeholder="-----BEGIN CERTIFICATE-----" rows={4} />
                </FormSection>
              </>
            )}
          </SettingsForm>
        </>
      )}
    </WithSettings>
  )
}

/** The compliance webhook and the private network switch (section monitoring). */
export function Monitoring({ s, save, ro }: { s: Settings; save: (section: Section, body: SettingsInput) => Promise<unknown>; ro: boolean }) {
  const t = useT()
  return (
    <SettingsForm
      readOnly={ro}
      schema={z.object({ webhook_url: z.string().refine((v) => !v.trim() || v.trim().startsWith('https://'), t('settings.monitor.https')), notify_private_networks: z.boolean() })}
      values={{ webhook_url: s.webhook_url ?? '', notify_private_networks: !!s.notify_private_networks }}
      onSave={(v) => save('monitoring', v)}
    >
      {(f) => (
        <FormSection title={t('settings.monitor.title')} description={t('settings.monitor.help')}>
          <TextField form={f} name="webhook_url" label="URL" placeholder="https://hooks.example.com/limdm" mono />
          {s.webhook_secret && (
            <Facts
              rows={[
                [t('settings.monitor.key'), <code className="font-mono text-meta break-all">{s.webhook_secret}</code>],
                [t('settings.monitor.header'), <code className="font-mono text-meta">X-LiMDM-Signature: sha256=HMAC-SHA256(key, timestamp + "." + body)</code>],
              ]}
            />
          )}
          <Toggle form={f} name="notify_private_networks" label={t('settings.monitor.private')} help={t('settings.monitor.privateHelp')} />
          {s.notify_private_networks && <Badge tone="warn">{t('settings.monitor.privateOn')}</Badge>}
        </FormSection>
      )}
    </SettingsForm>
  )
}
