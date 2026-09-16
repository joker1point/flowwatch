import { rate } from '../format'
import type { HistoryPoint } from '../types'

interface Props {
  history: HistoryPoint[]
}

const W = 100 // 用百分比坐标画，交给 CSS 拉伸，避免依赖容器像素尺寸
const H = 40

function line(values: number[], peak: number): string {
  if (values.length < 2 || peak <= 0) return ''
  const step = W / Math.max(1, values.length - 1)
  return values
    .map((value, index) => `${index === 0 ? 'M' : 'L'}${(index * step).toFixed(2)},${(H - (value / peak) * H).toFixed(2)}`)
    .join(' ')
}

function area(values: number[], peak: number): string {
  const path = line(values, peak)
  if (!path) return ''
  const step = W / Math.max(1, values.length - 1)
  return `${path} L${((values.length - 1) * step).toFixed(2)},${H} L0,${H} Z`
}

export function ThroughputChart({ history }: Props) {
  const inSeries = history.map((point) => point.in_bps)
  const outSeries = history.map((point) => point.out_bps)
  const peak = Math.max(...inSeries, ...outSeries, 1)
  const current = history[history.length - 1]

  return (
    <section className="panel">
      <div className="panel__head">
        <h2 className="panel__title">本机总吞吐</h2>
        <span className="panel__hint">
          {history.length} 个窗口（每窗口 1 秒）
          {current ? ` · 峰值 ${rate(peak)}` : ''}
        </span>
      </div>

      <div className="chart">
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label="总吞吐趋势">
          <path className="chart__area" d={area(inSeries, peak)} />
          <path className="chart__line chart__line--in" d={line(inSeries, peak)} />
          <path className="chart__line chart__line--out" d={line(outSeries, peak)} />
        </svg>
        <div className="chart__legend">
          <span className="legend legend--in">接收 {current ? rate(current.in_bps) : '—'}</span>
          <span className="legend legend--out">发送 {current ? rate(current.out_bps) : '—'}</span>
        </div>
      </div>
    </section>
  )
}
