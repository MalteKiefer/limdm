// zod 4 compiles parsers with new Function unless told not to; the CSP
// forbids eval. Every area imports z from here (eslint refuses 'zod'
// directly), so the setting is made before any schema exists, and zod
// stays out of the first load.
import { z } from 'zod'

z.config({ jitless: true })

export { z }
