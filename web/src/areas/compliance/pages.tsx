// Pages of the compliance area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function CompliancePage() {
  const t = useT()
  return <Stub title={t('compliance.title')} sub={t('compliance.sub')} oldPath="/compliance" />
}
