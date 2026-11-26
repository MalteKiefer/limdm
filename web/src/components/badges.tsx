// Badges of compliance check results and severities, shared by the
// compliance and device pages. Icon and text, never color alone.
import { CheckCircle2, CircleDashed, OctagonX, ShieldOff } from 'lucide-react'
import { useT, type MessageKey } from '../i18n'
import { Badge } from './ui'

const resultTone = { pass: 'ok', fail: 'bad', excepted: 'info', advisory: 'warn' } as const
const resultIcon = { pass: CheckCircle2, fail: OctagonX, excepted: ShieldOff }

/** A check result: pass, fail, na, excepted, advisory or removed. */
export function ResultBadge({ status }: { status: string }) {
  const t = useT()
  const I = resultIcon[status as keyof typeof resultIcon] ?? CircleDashed
  return (
    <Badge tone={resultTone[status as keyof typeof resultTone] ?? 'off'}>
      <I size={12} aria-hidden /> {t(`result.${status}` as MessageKey)}
    </Badge>
  )
}

const sevTone = { low: 'neutral', medium: 'warn', high: 'bad', critical: 'bad' } as const

/** Severity of a custom check: low, medium, high or critical; nothing without one. */
export function SeverityBadge({ severity }: { severity?: string }) {
  const t = useT()
  if (!severity) return null
  return <Badge tone={sevTone[severity as keyof typeof sevTone] ?? 'neutral'}>{t(`severity.${severity}` as MessageKey)}</Badge>
}
