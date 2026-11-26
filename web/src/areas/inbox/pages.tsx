// Pages of the inbox area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function InboxPage() {
  const t = useT()
  return <Stub title={t('inbox.title')} sub={t('inbox.sub')} oldPath="/approvals" />
}
