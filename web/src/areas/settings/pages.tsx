// Pages of the settings area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function SettingsPage() {
  const t = useT()
  return <Stub title={t('settings.title')} sub={t('settings.sub')} oldPath="/settings" />
}
