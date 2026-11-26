import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { setPrefs } from '../lib/prefs'
import { diffRows } from './diff'
import { parseJSON } from './jsoneditor'
import { validate, type JSONSchema } from './schemaform'
import { Field } from './form'

setPrefs({ locale: 'en' })

const firewall: JSONSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['enforce'],
  properties: {
    enforce: { type: 'boolean' },
    port: { type: 'integer', minimum: 1, maximum: 65535 },
    allow: { type: 'array', items: { type: 'string', pattern: '^\\d+/(tcp|udp)$', 'x-patternHint': 'port/protocol' } },
  },
}

describe('schema form validation', () => {
  it('maps errors to JSON pointers with readable messages', () => {
    const e = validate(firewall, { port: 0, allow: ['22/tcp', 'ssh'], extra: 1 })
    expect(e['/enforce']).toBe('Required')
    expect(e['/port']).toBe('At least 1')
    expect(e['/allow/1']).toBe('port/protocol')
  })
  it('passes a valid payload', () => {
    expect(validate(firewall, { enforce: true, allow: ['22/tcp'] })).toEqual({})
  })
})

describe('json editor', () => {
  it('names line and column of a syntax error', () => {
    const r = parseJSON('{\n  "a": 1,\n  "b": }')
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.line).toBe(3)
  })
})

describe('diff', () => {
  it('numbers old and new lines', () => {
    const rows = diffRows('a\nb\nc\n', 'a\nB\nc\n')
    expect(rows.map((r) => r.kind).join('')).toBe(' -+ ')
    expect(rows[2]).toEqual({ kind: '+', text: 'B', b: 2 })
  })
})

describe('field', () => {
  it('wires label, help and error for assistive technology', () => {
    render(
      <Field label="Name" help="Shown in lists" error="Must not be empty" required>
        {({ id, describedBy, invalid }) => <input id={id} aria-describedby={describedBy} aria-invalid={invalid} />}
      </Field>,
    )
    const input = screen.getByLabelText(/Name/)
    expect(input.getAttribute('aria-invalid')).toBe('true')
    const ids = input.getAttribute('aria-describedby')!.split(' ')
    expect(ids.map((i) => document.getElementById(i)?.textContent)).toEqual(['Shown in lists', ' Must not be empty'])
  })
})
