/** The URL if it is an object URL made by this page (blob:), else undefined: keeps a preview from loading anything else. */
export function blobURL(u: string | undefined): string | undefined {
  return u && u.startsWith(`blob:${location.origin}/`) ? u : undefined
}
