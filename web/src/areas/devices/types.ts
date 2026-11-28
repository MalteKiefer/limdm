// The device inventory as the agent reports it (internal/api Inventory).
// The API serves it as a free object; these are the fields the pages read.
export type Inventory = Partial<{
  source: string
  hostname: string
  hostname_info: HostnameInfo
  os_name: string
  os_version: string
  os_codename: string
  kernel: string
  arch: string
  cpu: string
  cpu_cores: number
  cpu_threads: number
  memory_mb: number
  swap_mb: number
  disk_gb: number
  vendor: string
  model: string
  serial: string
  bios_vendor: string
  bios_version: string
  boot_time: number
  desktop: string
  display_manager: string
  disks: { name: string; model: string; size_gb: number; type: string }[]
  volumes: { device: string; mount: string; fs: string; size_gb: number; free_gb: number; encrypted: boolean; encryption?: string; role?: string; removable?: boolean }[]
  accounts: { name: string; uid: number; gid?: number; home?: string; gecos?: string; source?: string; system?: boolean; shell?: string; admin: boolean; sso?: boolean; last_sso?: string; pwd_locked?: boolean }[]
  repos: { type: string; name: string; url: string; suites: string; components: string; enabled: boolean; signed: boolean; file: string }[]
  flatpaks: { id: string; name?: string; version?: string; branch?: string; origin?: string; installation: string }[]
  flatpak_remotes: { name: string; url: string; title?: string; installation: string; disabled?: boolean }[]
  snaps: { name: string; version: string; publisher: string; notes: string }[]
  appimages: { path: string; owner: string; size_mb: number }[]
  certificates: { name: string; subject: string; issuer: string; not_before: string; not_after: string; sha256: string }[]
  apps: { id: string; installed: boolean; via?: string; error?: string }[]
  interfaces: { name: string; mac?: string; ips?: string[]; kind?: string; state?: string; mtu?: number; vpn?: string }[]
  dns: { scope: string; servers?: string[]; domains?: string[] }[]
  routes: { dst: string; gateway?: string; dev?: string; proto?: string; metric?: number; family?: string }[]
  vpns: { name: string; service: string; active: boolean; interface?: string }[]
  wireguard_keys: { profile: string; interface: string; public_key: string }[]
  groups: { name: string; gid: number; members?: string[]; source?: string; system?: boolean }[]
  logged_in_users: string[]
  tpm: { present: boolean; version?: string; luks_bound?: string[] }
}>

/** Facts and result of com.limdm.hostname (internal/api HostnameInfo). */
export type HostnameInfo = Partial<{
  address: string
  mac: string
  ptr: string
  fqdn: string
  target: string
  source: string
  result: 'unchanged' | 'changed' | 'waiting' | 'failed'
  detail: string
  previous: string
  changed_at: string
  warning: string
}>
