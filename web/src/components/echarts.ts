// Only the ECharts parts the console uses, as its own lazy chunk. Canvas
// renderer: it sets no style attributes in markup (CSP). A chart type a page
// needs is added here once.
import { BarChart, HeatmapChart, LineChart, PieChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, MarkAreaComponent, MarkLineComponent, TooltipComponent, VisualMapComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([LineChart, BarChart, HeatmapChart, PieChart, GridComponent, LegendComponent, TooltipComponent, MarkAreaComponent, MarkLineComponent, VisualMapComponent, AriaComponent, CanvasRenderer])
export default echarts
