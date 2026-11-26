// Pages of the activity area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function ActivityPage() {
  const t = useT()
  return <Stub title={t('activity.title')} sub={t('activity.sub')} oldPath="/audit" />
}
