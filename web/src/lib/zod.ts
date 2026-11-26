// zod 4 compiles parsers with new Function unless told not to; the CSP
// forbids eval. Imported first by main.tsx (and the test setup), so every
// schema of every area runs jitless.
import { z } from 'zod'

z.config({ jitless: true })
