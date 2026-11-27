import '../lib/zod'
import { loadAllCatalogs } from '../i18n/catalog'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => cleanup())

await loadAllCatalogs() // components under test use the catalogs of their areas
