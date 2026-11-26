// Pages of the config area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function ConfigPage() {
  const t = useT()
  return <Stub title={t('config.title')} sub={t('config.sub')} oldPath="/blueprints" />
}

export function LibraryItemPage() {
  const t = useT()
  return <Stub title={t('config.title')} sub={t('config.sub')} oldPath="/blueprints" />
}
