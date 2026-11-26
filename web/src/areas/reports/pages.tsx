// Pages of the reports area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function ReportsPage() {
  const t = useT()
  return <Stub title={t('reports.title')} sub={t('reports.sub')} oldPath="/compliance" />
}
