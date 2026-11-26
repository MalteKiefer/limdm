// Pure logic of the devices area: who may send which command, the desktop
// users text of the edit dialog, the package filter, script parameters and
// the shapes of the timeline. Mirrors the server rules so the page hides
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

/** Parses "username email [admin]" lines as the console does (parseUsers). */
export function parseUsers(text: string): { users: DesktopUser[]; error?: string } {
  const users: DesktopUser[] = []
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/).filter(Boolean)
    if (!f.length) continue
    if (f.length < 2 || f.length > 3 || (f.length === 3 && f[2] !== 'admin')) return { users, error: line.trim() }
    const u = { username: f[0], email: f[1].toLowerCase(), admin: f.length === 3 }
    if (!userRe.test(u.username) || u.username === 'root' || !emailRe.test(u.email) || users.some((x) => x.username === u.username)) return { users, error: line.trim() }
    users.push(u)
  }
  return { users }
}

export const formatUsers = (users: DesktopUser[]) => users.map((u) => `${u.username} ${u.email}${u.admin ? ' admin' : ''}`).join('\n')

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

/** Percent used of a volume. */
export const usedPct = (size: number, free: number) => (size > 0 ? Math.round(((size - free) * 100) / size) : 0)

/** The protective action notices: lock, lost and wipe are alarms, the rest information. */
export const protectiveAlarm = (type: string) => type === 'lock' || type === 'lost' || type === 'wipe'

/** Accounts the helpdesk and admins may act on (the console hides the rest). */
export const accountActionable = (a: { name: string; system?: boolean; source?: string }) => !a.system && a.name !== 'root' && a.source !== 'nss'
