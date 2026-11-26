// Texts of the inbox area; keys start with "inbox.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'inbox.title': 'Eingang',
  'inbox.sub': 'Freigaben, Warnungen und fehlgeschlagene Befehle, nach Risiko sortiert',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'inbox.title': 'Inbox',
  'inbox.sub': 'Approvals, warnings and failed commands, by risk',
}
