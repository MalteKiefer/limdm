// Component gallery (/app/dev/components, not in the navigation): every
// shared component with sample data. Feature streams look things up here,
// and the CSP end to end test renders it to prove each one runs under the
// console's policy.
import { useQuery } from '@tanstack/react-query'
import { Activity, Play, RefreshCw } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { api, unwrap } from '../api/client'
import { axisX, axisY, baseOption, ChartFrame, EChart, FleetGrid, StackBar, type Colors } from '../components/charts'
import { BulkActionBar, ColumnChooser, DataGrid, useColumnVisibility, type GridColumn, type RowSelectionState } from '../components/datagrid'
import { DiffViewer } from '../components/diff'
import { Field, FormSection } from '../components/form'
import { JsonEditor } from '../components/jsoneditor'
import { KpiCard } from '../components/kpi'
import { SideSheet, SplitView, TabBar, TabPanel, Wizard } from '../components/layout'
import { Facets, QueryBar } from '../components/querybar'
import { SavedViewsMenu } from '../components/savedviews'
import { SchemaForm, validate, type JSONSchema } from '../components/schemaform'
import { EmptyState, ErrorState, LoadingState } from '../components/states'
import { Timeline } from '../components/timeline'
import { toast } from '../components/toast'
import { Badge, Card, Delta, Modal, PageHeader, StatusPill, type DeviceStatus } from '../components/ui'
import { ApiError } from '../api/client'

type Row = { id: string; hostname: string; status: DeviceStatus; os: string }
const statuses: DeviceStatus[] = ['compliant', 'compliant', 'compliant', 'in grace', 'non-compliant', 'stale', 'pending']
const rows: Row[] = Array.from({ length: 2000 }, (_, i) => ({ id: `d${i}`, hostname: `host-${String(i).padStart(4, '0')}`, status: statuses[i % statuses.length], os: i % 3 ? 'Ubuntu 24.04' : 'Debian 12' }))
const columns: GridColumn<Row>[] = [
  { id: 'hostname', header: 'Host', accessorKey: 'hostname', meta: { sortKey: 'hostname' }, cell: (c) => <span className="font-mono">{c.getValue<string>()}</span> },
  { id: 'status', header: 'Status', accessorKey: 'status', cell: (c) => <StatusPill status={c.getValue<DeviceStatus>()} /> },
  { id: 'os', header: 'OS', accessorKey: 'os', meta: { sortKey: 'os' } },
]

export function Gallery() {
  const [q, setQ] = useState('status:non-compliant')
  const [sort, setSort] = useState('hostname')
  const [sel, setSel] = useState<RowSelectionState>({})
  const [active, setActive] = useState<string>()
  const [vis, setVis] = useColumnVisibility('gallery')
  const [tab, setTab] = useState<'a' | 'b'>('a')
  const [step, setStep] = useState(0)
  const [modal, setModal] = useState(false)
  const [json, setJson] = useState('{\n  "enforce": true,\n  "allow": ["22/tcp"]\n}')
  const schema = useQuery({ queryKey: ['schema', 'com.limdm.firewall'], queryFn: () => unwrap(api.GET('/api/v1/schemas/{type}', { params: { path: { type: 'com.limdm.firewall' } } })) as Promise<JSONSchema> })
  const [payload, setPayload] = useState<Record<string, unknown>>({ enforce: true, allow: ['22/tcp'] })
  const errors = useMemo(() => (schema.data ? validate(schema.data, payload) : {}), [schema.data, payload])
  const sorted = useMemo(() => [...rows].sort((a, b) => (sort.startsWith('-') ? -1 : 1) * a[sort.replace('-', '') as 'hostname'].localeCompare(b[sort.replace('-', '') as 'hostname'])), [sort])
  const idx = rows.findIndex((r) => r.id === active)
  const build = useCallback((c: Colors) => ({ ...baseOption(c), xAxis: { type: 'category', data: ['Mo', 'Di', 'Mi', 'Do', 'Fr'], ...axisX(c) }, yAxis: { type: 'value', ...axisY(c) }, series: [{ type: 'bar', data: [5, 8, 3, 9, 4], itemStyle: { color: c.accent } }] }), [])
  return (
    <div className="flex flex-col gap-[var(--gap)]">
      <PageHeader title="Components" sub="Shared building blocks with sample data" actions={<button className="btn" onClick={() => toast('Saved')}>Toast</button>} />
      <div className="grid grid-cols-2 gap-[var(--gap)] md:grid-cols-4">
        <KpiCard to="/" label="Score" value="93,7 %" delta={<Delta value={0.4} label="7 d" />} spark={[90, 91, 93, 92, 94]} />
        <KpiCard to="/" label="Failed" value="3" spark={[1, 4, 2, 3]} tone="bad" />
        <Card title="Badges">
          <div className="flex flex-wrap gap-1">
            <Badge>neutral</Badge> <Badge tone="ok">ok</Badge> <Badge tone="bad">bad</Badge> <StatusPill status="in grace" />
          </div>
        </Card>
        <Card title="Stack bar">
          <StackBar label="Agents" parts={[{ label: '0.17', value: 30, color: 'var(--c-s1)' }, { label: '0.16', value: 10, color: 'var(--c-s2)' }]} />
        </Card>
      </div>
      <Card title="Query bar, facets, grid, side sheet">
        <div className="flex flex-col gap-3">
          <QueryBar value={q} onChange={setQ} keys={[{ key: 'status', help: 'compliant, non-compliant' }, { key: 'tag', help: 'device tag' }]} />
          <div className="flex gap-2">
            <ColumnChooser columns={columns.map((c) => ({ id: c.id!, label: String(c.header) }))} value={vis} onChange={setVis} />
            <SavedViewsMenu list="gallery" current={{ query: q, sort }} onApply={(v) => setQ(v.query)} />
          </div>
          <div className="grid gap-3 md:grid-cols-[200px_1fr]">
            <Facets value={q} onChange={setQ} facets={[{ key: 'status', title: 'Status', values: [{ value: 'compliant', count: 3 }, { value: 'non-compliant', count: 1 }] }]} />
            <SplitView
              list={<DataGrid label="Devices" data={sorted} columns={columns} getRowId={(r) => r.id} sort={sort} onSortChange={setSort} selection={sel} onSelectionChange={setSel} columnVisibility={vis} activeId={active} onRowClick={(r) => setActive(r.id)} maxHeight="360px" card={(r) => <span className="font-mono">{r.hostname}</span>} />}
              detail={active && <SideSheet title={rows[idx].hostname} onClose={() => setActive(undefined)} onNext={() => setActive(rows[Math.min(idx + 1, rows.length - 1)].id)} onPrev={() => setActive(rows[Math.max(idx - 1, 0)].id)}>Details of {rows[idx].hostname}</SideSheet>}
            />
          </div>
          <BulkActionBar count={Object.keys(sel).length} onClear={() => setSel({})}>
            <button className="btn"><RefreshCw size={14} /> Sync</button>
          </BulkActionBar>
        </div>
      </Card>
      <div className="grid gap-[var(--gap)] lg:grid-cols-2">
        <Card title="Fleet grid">
          <FleetGrid cells={rows.slice(0, 300)} />
        </Card>
        <Card title="Chart with table">
          <ChartFrame chart={<EChart build={build} label="Bars" height={180} />} table={{ head: ['Day', 'Value'], rows: [['Mo', 5], ['Di', 8]] }} caption="Bars" />
        </Card>
      </div>
      <Card title="Tabs, wizard, modal">
        <TabBar idBase="g" label="Tabs" value={tab} onChange={setTab} tabs={[{ value: 'a', label: 'First' }, { value: 'b', label: 'Second', count: 2 }]} />
        <TabPanel idBase="g" value={tab}>
          <Wizard step={step} onStep={setStep} onFinish={() => setModal(true)} steps={[{ id: 'a', title: 'Choose', content: <p>Step one</p> }, { id: 'b', title: 'Confirm', content: <p>Step two</p> }]} />
        </TabPanel>
        <Modal open={modal} onClose={() => setModal(false)} title="Modal" footer={<button className="btn" onClick={() => setModal(false)}>Close</button>}>
          Content
        </Modal>
      </Card>
      <Card title="Forms">
        <FormSection title="Section" description="Help on the left, fields on the right">
          <Field label="Name" help="Shown in lists" required error="Must not be empty">
            {({ id, describedBy, invalid }) => <input id={id} className="field" aria-describedby={describedBy} aria-invalid={invalid} />}
          </Field>
        </FormSection>
        {schema.data && <SchemaForm schema={schema.data} value={payload} onChange={setPayload} errors={errors} />}
      </Card>
      <div className="grid gap-[var(--gap)] lg:grid-cols-2">
        <Card title="JSON and diff">
          <JsonEditor value={json} onChange={(text) => setJson(text)} rows={6} />
          <div className="mt-3">
            <DiffViewer before={'{\n  "enforce": false\n}'} after={json} />
          </div>
        </Card>
        <Card title="Timeline and states">
          <Timeline label="Events" items={[{ id: 1, at: Date.UTC(2026, 10, 26, 9), title: 'Command sent', meta: 'admin', icon: <Play size={6} /> }, { id: 2, at: Date.UTC(2026, 10, 25, 9), title: 'Device enrolled', icon: <Activity size={6} /> }]} />
          <EmptyState title="Nothing here">Explains what appears here.</EmptyState>
          <ErrorState error={new ApiError(500, { detail: 'internal error' }, 'abc123')} onRetry={() => {}} />
          <LoadingState rows={2} />
        </Card>
      </div>
    </div>
  )
}
