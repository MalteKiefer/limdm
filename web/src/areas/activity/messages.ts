// Texts of the activity area; keys start with "activity.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'activity.title': 'Aktivität',
  'activity.sub': 'Befehle, Änderungen, Freigaben und Anmeldungen in einem Strom',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'activity.title': 'Activity',
  'activity.sub': 'Commands, changes, approvals and sign ins in one stream',
}
