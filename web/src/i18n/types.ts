/** A message: text with {name} placeholders, or plural forms chosen by {count}. */
export type Msg = string | { one: string; other: string }
export type Catalog = Record<string, Msg>
