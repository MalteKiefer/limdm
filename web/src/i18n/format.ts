// Locale aware formatting of numbers, percentages, dates and relative times.
import { currentLocale, t } from '.'

const tag = () => (currentLocale() === 'de' ? 'de-DE' : 'en-GB')
const toDate = (v: string | number | Date) => (v instanceof Date ? v : new Date(v))

export const fmt = (n: number) => new Intl.NumberFormat(tag()).format(n)
export const fmt1 = (n: number) => new Intl.NumberFormat(tag(), { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(n)
export const pct = (n: number) => `${fmt1(n)} %`
export const dateTime = (v: string | number | Date) =>
  new Intl.DateTimeFormat(tag(), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(toDate(v))
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
