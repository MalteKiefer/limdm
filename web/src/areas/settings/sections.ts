// The sections of the settings page, in navigation order. tenant:
// "only-global" hides a section from tenant accounts and accounts with a
// device scope (the server refuses them too), "multi" shows it only with
// multi tenancy; admin hides it from auditors.
import { Archive, Bell, Building2, Cpu, DatabaseBackup, Fingerprint, FolderTree, Gauge, Globe, KeyRound, LockKeyhole, Network, ShieldAlert, ShieldCheck, SquareTerminal, Stamp, TicketCheck, UserCog, Users, Wifi, type LucideIcon } from 'lucide-react'

export type SectionId =
  | 'general'
  | 'access'
  | 'privacy'
  | 'signin'
  | 'password'
  | 'approvals'
  | 'shell'
  | 'enroll'
  | 'keys'
  | 'users'
  | 'tenants'
  | 'tokens'
  | 'notifications'
  | 'backup'
  | 'retention'
  | 'operations'
  | 'directory'
  | 'network'
  | 'agents'
  | 'cve'

export type SectionMeta = { id: SectionId; icon: LucideIcon; group: 'base' | 'security' | 'people' | 'ops' | 'fleet'; tenant?: 'only-global' | 'multi'; admin?: boolean }

export const sections: SectionMeta[] = [
  { id: 'general', icon: Globe, group: 'base', tenant: 'only-global' },
  { id: 'access', icon: Network, group: 'base', tenant: 'only-global' },
  { id: 'privacy', icon: Fingerprint, group: 'base', tenant: 'only-global' },
  { id: 'signin', icon: ShieldCheck, group: 'security', tenant: 'only-global' },
  { id: 'password', icon: LockKeyhole, group: 'security', tenant: 'only-global' },
  { id: 'approvals', icon: Stamp, group: 'security', tenant: 'only-global' },
  { id: 'shell', icon: SquareTerminal, group: 'security', tenant: 'only-global' },
  { id: 'enroll', icon: TicketCheck, group: 'security', tenant: 'only-global' },
  { id: 'keys', icon: KeyRound, group: 'security', tenant: 'only-global', admin: true },
  { id: 'users', icon: Users, group: 'people' },
  { id: 'tenants', icon: Building2, group: 'people', tenant: 'multi' },
  { id: 'tokens', icon: UserCog, group: 'people' },
  { id: 'notifications', icon: Bell, group: 'ops' },
  { id: 'backup', icon: DatabaseBackup, group: 'ops', tenant: 'only-global', admin: true },
  { id: 'retention', icon: Archive, group: 'ops', tenant: 'only-global' },
  { id: 'operations', icon: Gauge, group: 'ops', tenant: 'only-global' },
  { id: 'directory', icon: FolderTree, group: 'fleet', tenant: 'only-global' },
  { id: 'network', icon: Wifi, group: 'fleet' },
  { id: 'agents', icon: Cpu, group: 'fleet', tenant: 'only-global' },
  { id: 'cve', icon: ShieldAlert, group: 'fleet', tenant: 'only-global' },
]
