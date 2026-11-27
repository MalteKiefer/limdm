/**
 * A message: text with {name} placeholders, or plural forms chosen by {count}
 * with the CLDR categories of the language (Russian needs one, few, many).
 */
export type Msg = string | { one: string; few?: string; many?: string; other: string }
export type Catalog = Record<string, Msg>
