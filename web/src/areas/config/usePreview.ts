// Debounced review of an edit: the server validates it like a save and
// answers diff, devices and expected effect. Only the latest answer counts.
import { useEffect, useRef, useState } from 'react'
import type { Preview } from './api'

export function usePreview<T>(input: T | undefined, run: (v: T) => Promise<Preview>, delay = 600) {
  const [state, setState] = useState<{ data?: Preview; error?: unknown; busy: boolean }>({ busy: false })
  const seq = useRef(0)
  const key = input === undefined ? '' : JSON.stringify(input)
  useEffect(() => {
    if (!key) return
    const n = ++seq.current
    const timer = setTimeout(() => {
      setState((s) => ({ ...s, busy: true }))
      run(JSON.parse(key) as T).then(
        (data) => n === seq.current && setState({ data, busy: false }),
        (error: unknown) => n === seq.current && setState({ error, busy: false }),
      )
    }, delay)
    return () => clearTimeout(timer)
  }, [key, run, delay])
  return key ? state : { busy: false }
}
