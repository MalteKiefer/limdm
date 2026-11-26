import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, setCsrfToken, unwrap } from './client'

afterEach(() => vi.restoreAllMocks())

describe('api client', () => {
  it('sends the CSRF header on state changes only', async () => {
    const seen: Request[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      seen.push(input as Request)
      return new Response('{"items":[]}', { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    setCsrfToken('tok')
    await api.GET('/api/v1/views')
    await api.POST('/api/v1/views', { body: { list: 'devices', name: 'x' } })
    expect(seen[0].headers.get('X-CSRF-Token')).toBeNull()
    expect(seen[1].headers.get('X-CSRF-Token')).toBe('tok')
  })
  it('turns problem details into an ApiError', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{"status":422,"detail":"1 to 100 characters","field":"name"}', {
        status: 422,
        headers: { 'Content-Type': 'application/problem+json', 'X-Request-ID': 'r1' },
      }),
    )
    const err = await unwrap(api.POST('/api/v1/views', { body: { list: 'devices', name: '' } })).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).problem.field).toBe('name')
    expect((err as ApiError).requestId).toBe('r1')
  })
})
