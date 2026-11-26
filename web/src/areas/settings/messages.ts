// Texts of the settings area; keys start with "settings.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'settings.title': 'Einstellungen',
  'settings.sub': 'Allgemein, Anmeldung, Rollen, Sicherung, Benachrichtigungen, Mandanten, API',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'settings.title': 'Settings',
  'settings.sub': 'General, sign in, roles, backup, notifications, tenants, API',
}
