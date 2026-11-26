// Texts of the config area; keys start with "config.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'config.title': 'Konfiguration',
  'config.sub': 'Blueprints, Bibliothek und Software',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'config.title': 'Configuration',
  'config.sub': 'Blueprints, library and software',
}
