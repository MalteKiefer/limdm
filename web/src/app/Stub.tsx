// Placeholder of a page a feature stream has not built yet: names it and
// links to the same page of the classic console.
import { Construction, ExternalLink } from 'lucide-react'
import type { ReactNode } from 'react'
import { EmptyState } from '../components/states'
import { PageHeader } from '../components/ui'
import { useT } from '../i18n'

export function Stub({ title, sub, oldPath, children }: { title: string; sub?: ReactNode; oldPath: string; children?: ReactNode }) {
  const t = useT()
  return (
    <div>
      <PageHeader title={title} sub={sub} />
      <div className="card">
        <EmptyState
          icon={Construction}
          title={t('state.stubTitle')}
          action={
            <a className="btn" href={oldPath}>
              <ExternalLink size={14} aria-hidden /> {t('state.openOld')}
            </a>
          }
        >
          {t('state.stubBody')}
        </EmptyState>
        {children}
      </div>
    </div>
  )
}

/** Reads an optional string search parameter. */
export const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined)
