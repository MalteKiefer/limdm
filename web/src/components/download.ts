// Downloads through the admin API: the export comes as a blob (session and
// CSRF handled by the client), is saved under its file name, and its
// SHA-256 is returned so a page can show it next to the export.done audit
// entry the server writes for exactly these bytes.
import { api, unwrap } from '../api/client'

export type ExportKind =
  | 'compliance.csv'
  | 'compliance-history.csv'
  | 'exceptions.csv'
  | 'inventory.csv'
  | 'packages.csv'
  | 'audit.csv'
  | 'audit.jsonl'
  | 'evidence.json'
  | 'evidence.pdf'

export type ExportQuery = { at?: string; device?: string; days?: number }

/** Hex SHA-256 of some bytes. */
export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Saves a blob under a file name (an object URL is same origin, the CSP allows it). */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.append(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const fetchExport = (kind: ExportKind, query: ExportQuery = {}) =>
  unwrap(api.GET('/api/v1/exports/{kind}', { params: { path: { kind }, query }, parseAs: 'blob' })) as Promise<unknown> as Promise<Blob>

const today = () => {
  const d = new Date()
  return `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`
}

/** Downloads an export, saves it as limdm-<date>-<kind> and returns its SHA-256. */
export async function downloadExport(kind: ExportKind, query: ExportQuery = {}) {
  const blob = await fetchExport(kind, query)
  const sha = await sha256Hex(await blob.arrayBuffer())
  saveBlob(blob, `limdm-${today()}-${kind}`)
  return sha
}
