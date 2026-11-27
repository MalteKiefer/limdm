import { useEffect, useRef } from 'react'

/**
 * Preview of an image file the user picked, drawn on a canvas from the
 * file itself: no URL made from the file ever reaches an img src (nothing
 * to inject, and no blob: or data: source the CSP would have to allow).
 */
export function FilePreview({ file, label, className }: { file: Blob; label: string; className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    let live = true
    void createImageBitmap(file).then(
      (bmp) => {
        const c = ref.current
        if (!live || !c) return bmp.close()
        c.width = bmp.width
        c.height = bmp.height
        c.getContext('2d')?.drawImage(bmp, 0, 0)
        bmp.close()
      },
      () => undefined, // not an image: the server refuses it on save
    )
    return () => {
      live = false
    }
  }, [file])
  return <canvas ref={ref} role="img" aria-label={label} className={className} />
}
