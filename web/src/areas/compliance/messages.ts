// Texts of the compliance area; keys start with "compliance.".
import type { Catalog, Msg } from '../../i18n/types'

export const de = {
  'compliance.title': 'Compliance',
  'compliance.sub': 'Score, Frameworks, Controls und Nachweis',
} satisfies Catalog

export const en: Record<keyof typeof de, Msg> = {
  'compliance.title': 'Compliance',
  'compliance.sub': 'Score, frameworks, controls and evidence',
}
