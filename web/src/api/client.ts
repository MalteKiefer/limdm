// Typed client of the admin API. Types come from internal/server/openapi.json
// (`npm run api` regenerates src/api/schema.d.ts). The console session
// cookie authenticates; state changes carry the CSRF token from /api/v1/me.
import createClient, { type Middleware } from 'openapi-fetch'
import type { components, paths } from './schema'

export type Schemas = components['schemas']

let csrfToken = ''
/** Set once /api/v1/me answered; every non GET request sends it. */
export const setCsrfToken = (t: string) => {
  csrfToken = t
}
export const getCsrfToken = () => csrfToken

/** RFC 9457 problem details of a failed request. */
export type Problem = { type?: string; title?: string; status?: number; detail?: string; code?: string; field?: string }

export class ApiError extends Error {
  readonly status: number
  readonly problem: Problem
  readonly requestId: string | null
  constructor(status: number, problem: Problem, requestId: string | null) {
    super(problem.detail || problem.title || `HTTP ${status}`)
    this.status = status
    this.problem = problem
    this.requestId = requestId
  }
}

const safe = new Set(['GET', 'HEAD', 'OPTIONS'])

export const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (!safe.has(request.method)) request.headers.set('X-CSRF-Token', csrfToken)
    return request
  },
}

/** A 401 means the session ended: back to the login page. */
export const sessionMiddleware: Middleware = {
  onResponse({ response }) {
    if (response.status === 401 && typeof location !== 'undefined') location.assign('/login')
    return response
  },
}

export const api = createClient<paths>({
  baseUrl: typeof location === 'undefined' ? '' : location.origin,
  credentials: 'same-origin',
  fetch: (r) => globalThis.fetch(r), // looked up per request (tests replace it)
})
api.use(csrfMiddleware, sessionMiddleware)

type Result<T> = { data?: T; error?: unknown; response: Response }

/** Unwraps an openapi-fetch result: the data, or an ApiError with the problem details. */
export async function unwrap<T>(p: Promise<Result<T>>): Promise<T> {
  const r = await p
  if (!r.response.ok || r.error !== undefined) {
    const problem = (typeof r.error === 'object' && r.error) || { detail: String(r.error ?? r.response.statusText) }
    throw new ApiError(r.response.status, problem as Problem, r.response.headers.get('X-Request-ID'))
  }
  return r.data as T
}

/** Posts a server form (sign out) with the CSRF field. */
export async function postForm(path: string, fields: Record<string, string> = {}) {
  const body = new URLSearchParams({ ...fields, csrf: csrfToken })
  const res = await fetch(path, { method: 'POST', body, credentials: 'same-origin', redirect: 'manual' })
  if (res.status >= 400) throw new ApiError(res.status, { detail: res.statusText }, res.headers.get('X-Request-ID'))
}
