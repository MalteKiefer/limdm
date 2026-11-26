// Shared helper of the route modules.

/** Reads an optional string search parameter. */
export const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined)
