// Texts of the reports area; keys start with "reports.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'reports.title': 'Berichte',
  'reports.sub': 'Katalog, Export und Zeitplan',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'reports.title': 'Reports',
  'reports.sub': 'Catalog, export and schedule',
}
