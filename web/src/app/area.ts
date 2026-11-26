// An area of the console: its routes, its navigation entry and its command
// palette entries. Each feature stream owns one area directory
// (src/areas/<id>/) and registers it once in src/app/areas.ts.
import type { AnyRoute } from '@tanstack/react-router'
import type { LucideIcon } from 'lucide-react'
import type { Permission } from '../api/me'
import type { MessageKey } from '../i18n'

export type PaletteCommand = {
  id: string
  label: string
  icon: LucideIcon
  /** Extra words the palette matches on. */
  keywords?: string
  run: (go: (to: string, search?: Record<string, string>) => void) => void
}

export type Area = {
  id: string
  /** Navigation entry; omitted for areas without one. Lower order comes first. */
  nav?: {
    to: string
    icon: LucideIcon
    label: MessageKey
    order: number
    bottom?: boolean
    permission?: Permission
    /** Saved views of this list appear under the entry and open as to?q=<query>&sort=<sort>. */
    views?: string
  }
  /** Child routes of the shell route. */
  routes: (shell: AnyRoute) => AnyRoute[]
  /** Static palette entries (pages, actions) of the area. */
  commands?: () => PaletteCommand[]
}
