// Locale aware formatting of numbers, percentages, dates and relative times.
import { currentLocale, t } from '.'
import { getPrefs, type DateFormat } from '../lib/prefs'

const tag = () => (currentLocale() === 'de' ? 'de-DE' : 'en-GB')
const toDate = (v: string | number | Date) => (v instanceof Date ? v : new Date(v))

export const fmt = (n: number) => new Intl.NumberFormat(tag()).format(n)
export const fmt1 = (n: number) => new Intl.NumberFormat(tag(), { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(n)
export const pct = (n: number) => `${fmt1(n)} %`
const pad = (n: number) => String(n).padStart(2, '0')

/** Date and time in the notation picked in the profile, else the language's own. */
export function dateTime(v: string | number | Date, f: DateFormat | null = getPrefs().dateFormat) {
  const d = toDate(v)
  const [y, mo, day, h, mi] = [d.getFullYear(), pad(d.getMonth() + 1), pad(d.getDate()), d.getHours(), pad(d.getMinutes())]
  switch (f) {
    case 'iso':
      return `${y}-${mo}-${day} ${pad(h)}:${mi}`
    case 'de':
      return `${day}.${mo}.${y} ${pad(h)}:${mi}`
    case 'uk':
      return `${day}/${mo}/${y} ${pad(h)}:${mi}`
    case 'us':
      return `${mo}/${day}/${y} ${h % 12 || 12}:${mi} ${h < 12 ? 'AM' : 'PM'}`
  }
  return new Intl.DateTimeFormat(tag(), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(d)
}
export const dateShort = (v: string | number | Date) => new Intl.DateTimeFormat(tag(), { day: '2-digit', month: 'short' }).format(toDate(v))
export const dateLong = (v: string | number | Date) => new Intl.DateTimeFormat(tag(), { weekday: 'long', day: 'numeric', month: 'long' }).format(toDate(v))

/** Binary size: 1.5 GB, 320 MB. */
export function bytes(n: number) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${i ? fmt1(n) : fmt(n)} ${units[i]}`
}

/** "5 min ago", "yesterday"; future times count as now. */
export function ago(v: string | number | Date, now = Date.now()) {
  const s = Math.max(0, (now - toDate(v).getTime()) / 1000)
  if (s < 60) return t('time.justNow')
  if (s < 3600) return t('time.minutes', { count: Math.floor(s / 60) })
  if (s < 86400) return t('time.hours', { count: Math.floor(s / 3600) })
  return t('time.days', { count: Math.floor(s / 86400) })
}
