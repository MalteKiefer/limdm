// Pages of the devices area. Stub until the feature stream builds them.
import { Stub } from '../../app/Stub'
import { useT } from '../../i18n'

export function DevicePage() {
  const t = useT()
  return <Stub title={t('devices.title')} sub={t('devices.sub')} oldPath="/devices" />
}

export function DevicesPage() {
  const t = useT()
  return <Stub title={t('devices.title')} sub={t('devices.sub')} oldPath="/devices" />
}
