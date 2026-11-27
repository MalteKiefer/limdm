// Pure logic of the devices area: who may send which command, the desktop
// user rows of the edit dialog, the package filter, script parameters, the
// health cards, the notice order and the shapes of the timeline. Mirrors the server rules so the page hides
// what a role cannot do; the server checks again.

/** Commands the helpdesk may send (helpdeskCommands in internal/server/web.go). */
export const helpdeskCommands = ['sync', 'update', 'reboot', 'shutdown', 'lock', 'unlock', 'message', 'user_password', 'user_lock', 'user_unlock', 'diagnostics']

export function mayCommand(type: string, can: { admin: boolean; commands: boolean }) {
  if (can.admin) return true
  return can.commands && helpdeskCommands.includes(type)
}

export type DesktopUser = { username: string; email: string; admin: boolean }

const userRe = /^[a-z_][a-z0-9_-]{0,31}$/
const emailRe = /^[^\s@]+@[^\s@]+$/

/** What is wrong with row i of the desktop users (the server's parseUsers rules), if anything. */
export function userError(all: DesktopUser[], i: number): 'name' | 'email' | 'dup' | undefined {
  const u = all[i]
  if (!userRe.test(u.username) || u.username === 'root') return 'name'
  if (!emailRe.test(u.email)) return 'email'
  if (all.findIndex((x) => x.username === u.username) !== i) return 'dup'
}

/** A user name proposed from the local part of a mail address. */
export const suggestUsername = (email: string) =>
  email
    .split('@')[0]
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .replace(/^[^a-z_]+/, '')
    .slice(0, 32)

export type Tone = 'ok' | 'warn' | 'bad' | 'off'
type CheckLike = { id: string; status: string; detail?: string }

/** The updates card: missing security updates are bad, a pending reboot or manual updates warn. */
export function updatesHealth(checks: CheckLike[]): { tone: Tone; state: 'unknown' | 'pending' | 'reboot' | 'manual' | 'current'; detail?: string } {
  const by = (id: string) => checks.find((c) => c.id === id)
  const sec = by('updates.security')
  const reboot = by('updates.reboot')
  const auto = by('updates.auto')
  if (!sec && !reboot && !auto) return { tone: 'off', state: 'unknown' }
  if (sec?.status === 'fail') return { tone: 'bad', state: 'pending', detail: sec.detail }
  if (reboot?.status === 'fail') return { tone: 'warn', state: 'reboot', detail: reboot.detail }
  if (auto?.status === 'fail') return { tone: 'warn', state: 'manual', detail: auto.detail }
  return { tone: 'ok', state: 'current', detail: auto?.detail || sec?.detail }
}

/** The firewall card from the firewall.active check and whether a firewall declaration applies. */
export function firewallHealth(checks: CheckLike[], decls: { type: string }[]): { tone: Tone; state: 'unknown' | 'active' | 'inactive' | 'excepted'; managed: boolean } {
  const s = checks.find((c) => c.id === 'firewall.active')?.status
  const managed = decls.some((x) => x.type === 'com.limdm.firewall')
  if (s === 'pass') return { tone: 'ok', state: 'active', managed }
  if (s === 'fail') return { tone: 'bad', state: 'inactive', managed }
  if (s === 'excepted') return { tone: 'warn', state: 'excepted', managed }
  return { tone: 'off', state: 'unknown', managed }
}

/** The connection card: never seen, stale (past the stale limit) or connected. */
export const connectionState = (lastSeen: string | null, status: string): { tone: Tone; state: 'never' | 'stale' | 'online' } =>
  !lastSeen ? { tone: 'off', state: 'never' } : status === 'stale' ? { tone: 'warn', state: 'stale' } : { tone: 'ok', state: 'online' }

/** Notices of the device page in priority order: security, then compliance, then information. */
export const noticeRank = { security: 0, compliance: 1, info: 2 } as const
export const orderNotices = <T extends { level: keyof typeof noticeRank }>(list: T[]) => [...list].sort((a, b) => noticeRank[a.level] - noticeRank[b.level])

/** Comma separated tags, lower case, without repeats (parseTags). */
export function parseTags(text: string): { tags: string[]; error?: string } {
  const tags: string[] = []
  for (const raw of text.split(',')) {
    const t = raw.trim().toLowerCase()
    if (!t || tags.includes(t)) continue
    if (!/^[a-z0-9._-]{1,32}$/.test(t)) return { tags, error: t }
    tags.push(t)
  }
  return { tags }
}

/** Custom attributes for templates: one name=value per line (api.ValidateAttributes). */
export function parseAttrs(text: string): { attrs: Record<string, string>; error?: string } {
  const attrs: Record<string, string> = {}
  for (const line of text.split('\n')) {
    if (!line.trim()) continue
    const i = line.indexOf('=')
    const k = line.slice(0, i).trim()
    if (i < 0 || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(k) || k in attrs) return { attrs, error: line.trim() }
    attrs[k] = line.slice(i + 1).trim()
  }
  return { attrs }
}

export const formatAttrs = (a: Record<string, string> = {}) =>
  Object.entries(a)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n')

/** Script parameters: one NAME=value per line; the first bad line is returned. */
export function badParamLine(text: string) {
  return text.split('\n').find((l) => l.trim() !== '' && !/^\s*[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l))
}

/** The pkg filter value of "openssl < 3.0.13": spaces dropped, so it stays one term. */
export const pkgValue = (text: string) => text.trim().replace(/\s+/g, '')

export function filterByName<T extends { name: string }>(list: T[], q: string) {
  const s = q.trim().toLowerCase()
  return s ? list.filter((p) => p.name.toLowerCase().includes(s)) : list
}

/** Tone of a command or session status. */
export function statusTone(status: string): 'ok' | 'bad' | 'warn' | 'off' {
  if (status === 'ok' || status === 'ended' || status === '0') return 'ok'
  if (status === 'failed' || status === 'expired' || status === 'interrupted') return 'bad'
  if (/^\d+$/.test(status)) return 'bad' // script exit code other than 0
  if (status === '') return 'off'
  return 'warn'
}

/** Tone of a compliance check result. */
export const checkTone = (s: string): Tone => (s === 'pass' ? 'ok' : s === 'fail' ? 'bad' : s === 'excepted' || s === 'advisory' ? 'warn' : 'off')

/** Percent used of a volume. */
export const usedPct = (size: number, free: number) => (size > 0 ? Math.round(((size - free) * 100) / size) : 0)

/** The protective action notices: lock, lost and wipe are alarms, the rest information. */
export const protectiveAlarm = (type: string) => type === 'lock' || type === 'lost' || type === 'wipe'

/** Accounts the helpdesk and admins may act on (the console hides the rest). */
export const accountActionable = (a: { name: string; system?: boolean; source?: string }) => !a.system && a.name !== 'root' && a.source !== 'nss'
