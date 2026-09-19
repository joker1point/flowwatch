import { useEffect, useMemo, useState } from 'react'
import { fetchEvents, fetchTimeline, fetchTopDomains, fetchTopProcesses } from '../api'
import { ago, bytes, rate, stampLabel } from '../format'
import type {
  ChangeEvent,
  DomainTop,
  Health,
  ProcessTop,
  TimelinePoint,
  TimelineResponse,
} from '../types'

interface Props {
  health: Health | null
}

/** 时间范围 → 查询分钟数 + 重采样桶宽（后端桶宽上限 60 分钟）。 */
const RANGES = [
  { key: '1h', label: '1 小时', minutes: 60, bucket: 1 },
  { key: '6h', label: '6 小时', minutes: 360, bucket: 5 },
  { key: '24h', label: '24 小时', minutes: 1440, bucket: 15 },
  { key: '7d', label: '7 天', minutes: 10080, bucket: 60 },
  { key: '30d', label: '30 天', minutes: 43200, bucket: 60 },
] as const

type RangeKey = (typeof RANGES)[number]['key']
const FALLBACK_RANGE = { key: '24h', label: '24 小时', minutes: 1440, bucket: 15 } as const

const KIND_LABEL: Record<string, string> = { appear: '出现', vanish: '消失', spike: '尖峰' }

/** 区间事件最多渲染这么多条：30 天区间可能有几十条，全列出来会把页面拉成一条长龙 */
const EVENT_LIMIT = 20

const CHART_H = 44 // viewBox 高度；宽度固定 100，横轴按真实时间定位

interface StackedChartProps {
  series: TimelinePoint[]
  /** 查询区间起点（后端 since）：横轴以它为 0 */
  sinceTs: number
  spanMinutes: number
  bucketSeconds: number
  hover: number | null
  onHover: (index: number | null) => void
}

/**
 * 整机分层柱：本机流量按归属堆叠三层（已归因 / 属主受限 / 未归因），别人的流量单独一条细柱。
 *
 * 横轴按**真实时间**定位，而不是"第几个桶" —— 历史层不补零，没落库的时段必须留白：
 * 实测 30 天视图里 1.6 天的停摆空洞曾被压缩掉，看起来像是有连续数据。
 */
function StackedChart({
  series,
  sinceTs,
  spanMinutes,
  bucketSeconds,
  hover,
  onHover,
}: StackedChartProps) {
  const spanMs = Math.max(1, spanMinutes * 60_000)
  const columnWidth = Math.max(0.12, ((bucketSeconds * 1000) / spanMs) * 100)
  const stackTotals = series.map(
    (point) => point.own_out_bps + point.own_in_bps + point.masked_bps + point.unattributed_bps,
  )
  const peak = Math.max(...stackTotals, ...series.map((point) => point.foreign_bps), 1)
  const y = (value: number) => CHART_H - (value / peak) * CHART_H
  const xOf = (ts: string) => ((new Date(ts).getTime() - sinceTs) / spanMs) * 100
  const hoverPoint = hover !== null ? series.at(hover) : undefined

  if (series.length === 0) {
    return <p className="panel__hint panel__hint--pad">这个区间还没有历史数据。</p>
  }

  return (
    <div className="chart">
      <svg
        viewBox={`0 0 100 ${CHART_H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="整机流量分层趋势"
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect()
          if (rect.width <= 0) return
          const ratio = (event.clientX - rect.left) / rect.width
          const target = sinceTs + ratio * spanMs
          let best = -1
          let bestDiff = Number.POSITIVE_INFINITY
          series.forEach((point, index) => {
            const diff = Math.abs(new Date(point.ts).getTime() - target)
            if (diff < bestDiff) {
              bestDiff = diff
              best = index
            }
          })
          // 鼠标停在空洞上时不硬报远处的桶：以半个桶宽为界
          const limit = Math.max(bucketSeconds * 1000, spanMs * 0.005)
          onHover(best >= 0 && bestDiff <= limit ? best : null)
        }}
        onMouseLeave={() => onHover(null)}
      >
        {series.map((point) => {
          const x = xOf(point.ts)
          const own = point.own_out_bps + point.own_in_bps
          const ownTop = y(own)
          const maskedTop = y(own + point.masked_bps)
          const unattrTop = y(own + point.masked_bps + point.unattributed_bps)
          return (
            <g key={point.ts}>
              <rect
                className="chart__band chart__band--own"
                x={x}
                y={ownTop}
                width={columnWidth}
                height={CHART_H - ownTop}
              />
              <rect
                className="chart__band chart__band--masked"
                x={x}
                y={maskedTop}
                width={columnWidth}
                height={ownTop - maskedTop}
              />
              <rect
                className="chart__band chart__band--unattributed"
                x={x}
                y={unattrTop}
                width={columnWidth}
                height={maskedTop - unattrTop}
              />
              <rect
                className="chart__foreign"
                x={x}
                y={y(point.foreign_bps)}
                width={columnWidth}
                height={Math.max(0.6, CHART_H - y(point.foreign_bps))}
              />
            </g>
          )
        })}
        {hoverPoint ? (
          <line
            className="chart__cursor"
            x1={xOf(hoverPoint.ts)}
            x2={xOf(hoverPoint.ts)}
            y1={0}
            y2={CHART_H}
          />
        ) : null}
      </svg>
    </div>
  )
}

export function HistoryView({ health }: Props) {
  const [range, setRange] = useState<RangeKey>('24h')
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null)
  const [processes, setProcesses] = useState<ProcessTop[]>([])
  const [domains, setDomains] = useState<DomainTop[]>([])
  const [events, setEvents] = useState<ChangeEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hover, setHover] = useState<number | null>(null)

  const config = RANGES.find((item) => item.key === range) ?? FALLBACK_RANGE
  /** 跨天区间带上日期：30 天视图里只显示 HH:MM 会分不清是哪天 */
  const stamp = (iso: string | null | undefined) => stampLabel(iso, config.minutes >= 1440)

  useEffect(() => {
    let alive = true
    setLoading(true)
    const load = () => {
      Promise.all([
        fetchTimeline(config.minutes, config.bucket),
        fetchTopProcesses(config.minutes, 10),
        fetchTopDomains(config.minutes, 10),
        fetchEvents(80),
      ])
        .then(([nextTimeline, nextProcesses, nextDomains, nextEvents]) => {
          if (!alive) return
          setTimeline(nextTimeline)
          setProcesses(nextProcesses.items)
          setDomains(nextDomains.items)
          // /api/events 没有时间范围参数：按当前区间在前端过滤
          const since = Date.now() - config.minutes * 60_000
          setEvents(nextEvents.items.filter((item) => new Date(item.ts).getTime() >= since))
          setError(null)
        })
        .catch((err: unknown) => {
          // 刷新失败保留上次结果：stale 好过空白，错误单独如实显示
          if (alive) setError(err instanceof Error ? err.message : String(err))
        })
        .finally(() => {
          if (alive) setLoading(false)
        })
    }
    load()
    const id = window.setInterval(load, 60_000) // 历史层按分钟落桶，1 分钟一刷足够
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [config.minutes, config.bucket])

  useEffect(() => {
    setHover(null) // 换区间后旧索引指向别的时刻，先清掉
  }, [range])

  const series = timeline?.series ?? []
  const bucketSeconds = timeline?.bucket_seconds ?? config.bucket * 60
  const sinceTs = timeline
    ? new Date(timeline.since).getTime()
    : Date.now() - config.minutes * 60_000
  /**
   * 区间内的桶位总数：有数据的桶比它少，就说明中间有空档（服务没跑或超出保留期）。
   * 后端的 since 是 `当前桶 - minutes*60`，**含当前桶**，所以是 +1 个桶位（实测 1 小时视图返回 61 桶）。
   */
  const slots = Math.max(1, Math.round((config.minutes * 60) / bucketSeconds) + 1)
  const firstPoint = series.at(0)
  const lastPoint = series.at(-1)

  const summary = useMemo(() => {
    const totals = { own: 0, masked: 0, unattributed: 0, foreign: 0 }
    let peakBps = 0
    let peakTs: string | null = null
    for (const point of series) {
      totals.own += (point.own_out_bps + point.own_in_bps) * bucketSeconds
      totals.masked += point.masked_bps * bucketSeconds
      totals.unattributed += point.unattributed_bps * bucketSeconds
      totals.foreign += point.foreign_bps * bucketSeconds
      const stacked =
        point.own_out_bps + point.own_in_bps + point.masked_bps + point.unattributed_bps
      if (stacked > peakBps) {
        peakBps = stacked
        peakTs = point.ts
      }
    }
    const machine = totals.own + totals.masked + totals.unattributed
    const spanSeconds = Math.max(1, series.length * bucketSeconds)
    return { totals, machine, avgBps: machine / spanSeconds, peakBps, peakTs }
  }, [series, bucketSeconds])

  const hoverPoint = hover !== null ? (series.at(hover) ?? null) : null
  const processPeak = Math.max(...processes.map((item) => item.total_bytes), 1)
  const domainPeak = Math.max(...domains.map((item) => item.total_bytes), 1)
  const share = (value: number) => (summary.machine > 0 ? (value / summary.machine) * 100 : 0)
  const coverage = health?.history

  return (
    <main className="hist">
      <div className="hist__bar">
        <div className="tabs" role="tablist" aria-label="历史时间范围">
          {RANGES.map((item) => (
            <button
              key={item.key}
              type="button"
              role="tab"
              aria-selected={range === item.key}
              className={range === item.key ? 'is-active' : ''}
              onClick={() => setRange(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
        <span className="hist__meta">
          {timeline
            ? `桶宽 ${Math.round(bucketSeconds / 60)} 分钟 · ${series.length} 个桶`
            : '读取中…'}
          {coverage?.oldest ? ` · 库中最早数据：${ago(coverage.oldest)}（保留 ${coverage.retention_days} 天）` : ''}
        </span>
        <span className="hist__state">
          {error ? `刷新失败：${error}（以下为上次结果）` : loading ? '读取中…' : ''}
        </span>
      </div>

      <div className="hist__summary">
        <div className="stat">
          <dt>本机流量（区间累计）</dt>
          <dd className="mono">{bytes(summary.machine)}</dd>
        </div>
        <div className="stat">
          <dt>平均速率</dt>
          <dd className="mono">{rate(summary.avgBps)}</dd>
        </div>
        <div className="stat stat--accent">
          <dt>峰值速率</dt>
          <dd className="mono">{rate(summary.peakBps)}</dd>
        </div>
        <div className="stat">
          <dt>峰值时刻</dt>
          <dd className="mono">{summary.peakTs ? stamp(summary.peakTs) : '—'}</dd>
        </div>
        <div className="stat">
          <dt>
            数据覆盖（{series.length}/{slots} 桶）
          </dt>
          <dd className="mono">
            {firstPoint && lastPoint
              ? `${stamp(firstPoint.ts)} → ${stamp(lastPoint.ts)}`
              : '—'}
          </dd>
        </div>
      </div>

      <section className="panel">
        <div className="panel__head">
          <h2 className="panel__title">整机流量 · 分层</h2>
          <span className="panel__hint">
            {hoverPoint ? (
              <>
                {stamp(hoverPoint.ts)} · 本机 {rate(hoverPoint.own_out_bps + hoverPoint.own_in_bps)} ·
                受限 {rate(hoverPoint.masked_bps)} · 未归因 {rate(hoverPoint.unattributed_bps)} · 他人{' '}
                {rate(hoverPoint.foreign_bps)}
              </>
            ) : summary.peakTs ? (
              `峰值 ${rate(summary.peakBps)} @ ${stamp(summary.peakTs)} · 悬停查看某时刻的分层`
            ) : (
              '按分钟落桶'
            )}
          </span>
        </div>
        <StackedChart
          series={series}
          sinceTs={sinceTs}
          spanMinutes={config.minutes}
          bucketSeconds={bucketSeconds}
          hover={hover}
          onHover={setHover}
        />
        <div className="chart__legend">
          <span className="legend legend--own">本机已归因</span>
          <span className="legend legend--masked">属主受限</span>
          <span className="legend legend--unattr">未归因</span>
          <span className="legend legend--foreign">别人的流量（不计入本机）</span>
        </div>
        {series.length > 0 && series.length < slots ? (
          <p className="panel__hint panel__hint--pad">
            空白 = 没有落库数据（服务未运行，或已超出保留期）：这个区间只有 {series.length}/{slots}{' '}
            个桶位有数据。
          </p>
        ) : null}
        <div className="mix">
          <div className="mix__bar" role="img" aria-label="区间内本机流量的归属构成">
            <span className="mix__seg mix__seg--own" style={{ width: `${share(summary.totals.own)}%` }} />
            <span
              className="mix__seg mix__seg--masked"
              style={{ width: `${share(summary.totals.masked)}%` }}
            />
            <span
              className="mix__seg mix__seg--unattr"
              style={{ width: `${share(summary.totals.unattributed)}%` }}
            />
          </div>
          <p className="panel__note">
            已归因 <b className="mono">{bytes(summary.totals.own)}</b>（{share(summary.totals.own).toFixed(1)}%）
            · 属主受限 <b className="mono">{bytes(summary.totals.masked)}</b>（
            {share(summary.totals.masked).toFixed(1)}%）· 未归因{' '}
            <b className="mono">{bytes(summary.totals.unattributed)}</b>（
            {share(summary.totals.unattributed).toFixed(1)}%）
            <br />
            未归因 = 说不清是谁的；属主受限 = 端点已知但非提权拿不到 PID —— 两者都单独记账，不混进进程排行。
          </p>
        </div>
      </section>

      <div className="hist__columns">
        <section className="panel">
          <div className="panel__head">
            <h2 className="panel__title">进程排行 · Top 10</h2>
            <span className="panel__hint">按区间累计字节（只统计 pid &gt; 0）</span>
          </div>
          {processes.length === 0 ? (
            <p className="panel__hint panel__hint--pad">这个区间还没有进程数据。</p>
          ) : (
            <ol className="rank">
              {processes.map((item, index) => (
                <li className="rank__row" key={item.pid}>
                  <span className="rank__no mono dim">{index + 1}</span>
                  <span className="rank__name" title={`${item.process} #${item.pid}`}>
                    {item.process} <span className="dim mono">#{item.pid}</span>
                  </span>
                  <span className="rank__bar">
                    <span
                      className="rank__fill"
                      style={{ width: `${(item.total_bytes / processPeak) * 100}%` }}
                    />
                  </span>
                  <span className="rank__val mono">{bytes(item.total_bytes)}</span>
                  <span className="rank__sub mono dim">
                    ↑{bytes(item.out_bytes)} ↓{bytes(item.in_bytes)}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </section>

        <section className="panel">
          <div className="panel__head">
            <h2 className="panel__title">域名排行 · Top 10</h2>
            <span className="panel__hint">含未识别来源（kind=ip）</span>
          </div>
          {domains.length === 0 ? (
            <p className="panel__hint panel__hint--pad">这个区间还没有域名记录。</p>
          ) : (
            <ol className="rank">
              {domains.map((item, index) => (
                <li className="rank__row" key={`${item.name}-${item.kind}`}>
                  <span className="rank__no mono dim">{index + 1}</span>
                  <span className="rank__name" title={`${item.name}（来源 ${item.kind}）`}>
                    {item.name}
                  </span>
                  <span className="rank__bar">
                    <span
                      className="rank__fill"
                      style={{ width: `${(item.total_bytes / domainPeak) * 100}%` }}
                    />
                  </span>
                  <span className="rank__val mono">{bytes(item.total_bytes)}</span>
                  <span className="rank__sub mono dim">{item.conns} 连接</span>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel__head">
          <h2 className="panel__title">区间内变化事件</h2>
          <span className="panel__hint">
            共 {events.length} 条，最多显示最近 {EVENT_LIMIT} 条 · 只由落库观测值派生
          </span>
        </div>
        {events.length === 0 ? (
          <p className="panel__hint panel__hint--pad">
            这个区间没有事件。出现 / 消失 / 尖峰都只在桶定稿时由已落库的数据比较得出。
          </p>
        ) : (
          <ul className="events">
            {events.slice(0, EVENT_LIMIT).map((event) => (
              <li className="event" key={`${event.ts}-${event.kind}-${event.pid}`}>
                <span className="mono dim">{stamp(event.ts)}</span>
                <span className={`badge badge--${event.kind}`}>{KIND_LABEL[event.kind] ?? event.kind}</span>
                <span className="event__process">{event.process}</span>
                <span className="mono dim">#{event.pid}</span>
                <span className="event__detail">{event.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  )
}
