// The Logs tab of the device page: the search of the Logs page for one
// device. Its filter stays in the tab (the device page owns the URL).
import { useCallback, useState } from 'react'
import { LogExplorer } from './pages'
import type { LogSearch } from './logic'

export function LogsTab({ d }: { d: { id: string } }) {
  const [s, setS] = useState<LogSearch>({})
  const go = useCallback((p: Partial<LogSearch>) => setS((prev) => ({ ...prev, ...p })), [])
  return <LogExplorer s={s} go={go} deviceId={d.id} />
}
