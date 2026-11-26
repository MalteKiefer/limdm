// Texts of the devices area; keys start with "devices.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'devices.title': 'Geräte',
  'devices.sub': 'Abfrage, Facetten und Seitenblatt',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'devices.title': 'Devices',
  'devices.sub': 'Query, facets and side sheet',
}
