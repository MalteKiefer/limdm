import { describe, expect, it } from 'vitest'
import { validate, type JSONSchema } from '../../components/schemaform'
import { fromForm } from './software'
import { move, newIf, treeItems, treeProblems } from './tree'

const fields = { tag: ['has', 'not_has'], desktop: ['present', 'absent', 'contains'] }

describe('blueprint map', () => {
  it('lists every item once, also inside branches and else', () => {
    const tree = [
      { kind: 'assign' as const, items: [1, 2] },
      { kind: 'if' as const, branches: [{ match: 'all' as const, rules: [{ field: 'tag', op: 'has', value: 'x' }], nodes: [{ kind: 'assign' as const, items: [2, 3] }] }], else: [{ kind: 'assign' as const, items: [4] }] },
    ]
    expect(treeItems(tree)).toEqual([1, 2, 3, 4])
  })
  it('moves within bounds only', () => {
    expect(move([1, 2, 3], 0, 1)).toEqual([2, 1, 3])
    expect(move([1, 2, 3], 0, -1)).toEqual([1, 2, 3])
  })
  it('marks rules the server would refuse', () => {
    const n = newIf(fields)
    expect(treeProblems([n], fields)).toEqual({})
    n.branches![0].rules[0] = { field: 'tag', op: 'has', value: ' ' }
    expect(treeProblems([n], fields)).toEqual({ 'tree.0.b0.r0': 'noValue' })
    n.branches![0].rules[0] = { field: 'tag', op: 'present', value: '' }
    expect(treeProblems([n], fields)).toEqual({ 'tree.0.b0.r0': 'badRule' })
    expect(treeProblems([{ kind: 'if', branches: [], else: [] }], fields)).toEqual({ 'tree.0': 'noBranch' })
  })
})

describe('catalog app form', () => {
  const base = { id: 'code', name: 'Code', summary: '', category: '', mode: 'available' as const, enabled: true, flatpak: 'com.visualstudio.code', remote: 'flathub', debian: 'code', fedora: '', prefer: 'package' as const, detect: 'code-insiders  code-oss', scope: [], repoName: '', debUrl: 'https://packages.microsoft.com/repos/code', debSuite: 'stable', debComponents: 'main', debKey: 'KEY', rpmUrl: '', rpmKey: '', rpmSigned: false }
  it('maps sources: packages first, vendor repo named after the app', () => {
    const app = fromForm(base)
    expect(app.sources.map((s) => s.kind)).toEqual(['package', 'flatpak'])
    expect(app.sources[0].repos?.[0]).toMatchObject({ name: 'code', family: 'debian', suites: 'stable' })
    expect(app.sources[1].remote).toBeUndefined()
    expect(app.detect).toEqual(['code-insiders', 'code-oss'])
  })
})

describe('schema form values', () => {
  it('validates integer choices and limits as numbers', () => {
    const s: JSONSchema = { type: 'object', properties: { level: { type: 'integer', enum: [1, 2] }, pcrs: { type: 'array', items: { type: 'integer' } }, n: { type: 'integer', minimum: 30 } } }
    expect(validate(s, { level: 2, pcrs: [7], n: 30 })).toEqual({})
    expect(Object.keys(validate(s, { level: '2', pcrs: ['7'], n: 5 })).sort()).toEqual(['/level', '/n', '/pcrs/0'])
  })
})
