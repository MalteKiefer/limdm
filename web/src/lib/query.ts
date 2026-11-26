// The list query language, client side (same grammar as the server's
// parseFilterTokens in internal/server/devicelist.go): free words and
// key:value or key:"quoted value" tokens; every token must match.

export type Token = { key: string | null; value: string }

const tokenRe = /(?:([a-z_]+):)?("[^"]*"|\S+)/g

export function tokenize(q: string): Token[] {
  const out: Token[] = []
  for (const m of q.matchAll(tokenRe)) {
    let v = m[2]
    if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1)
    v = v.trim()
    if (v) out.push({ key: m[1] ?? null, value: v })
  }
  return out
}

const quote = (v: string) => (/[\s"]/.test(v) ? `"${v.replaceAll('"', '')}"` : v)

export const formatToken = (t: Token) => (t.key ? `${t.key}:${quote(t.value)}` : quote(t.value))

export const serialize = (tokens: Token[]) => tokens.map(formatToken).join(' ')

const same = (a: Token, b: Token) => a.key === b.key && a.value.toLowerCase() === b.value.toLowerCase()

/** Adds key:value unless it is there already. */
export function addToken(q: string, t: Token) {
  const tokens = tokenize(q)
  return tokens.some((x) => same(x, t)) ? serialize(tokens) : serialize([...tokens, t])
}

export function removeToken(q: string, t: Token) {
  return serialize(tokenize(q).filter((x) => !same(x, t)))
}

export const hasToken = (q: string, t: Token) => tokenize(q).some((x) => same(x, t))

/** The key being typed at the end of q ("sta" or "status:" with partial value). */
export function trailing(q: string): { key: string; value: string } | null {
  const m = /(?:^|\s)([a-z_]*)(?::("?[^\s"]*))?$/.exec(q)
  if (!m) return null
  return { key: m[1], value: (m[2] ?? '').replace(/^"/, '') }
}
