import { ago, bytes, minuteLabel, rate } from '../format'
import type { ChangeEvent, ProcessHistory } from '../types'

interface Props {
  history: ProcessHistory | null
  events: ChangeEvent[]
  loading: boolean
}

const KIND_LABEL: Record<string, string> = {
  appear: '出现',
  vanish: '消失',
  spike: '尖峰',
}

/** 每分钟一根柱：琥珀=发送、蓝=接收，堆叠高度按区间峰值归一。 */
function Bars({ history }: { history: ProcessHistory }) {
  const peak = Math.max(...history.series.map((item) => item.out_bps + item.in_bps), 1)
  return (
    <div className="bars" role="img" aria-label="历史流量柱状图">
      {history.series.map((item) => {
        const total = item.out_bps + item.in_bps
        const height = (total / peak) * 100
        const outShare = total > 0 ? (item.out_bps / total) * 100 : 0
        return (
          <span
            className="bars__col"
            key={item.ts}
            title={`${minuteLabel(item.ts)} 发送 ${rate(item.out_bps)} / 接收 ${rate(item.in_bps)}`}
          >
            <span className="bars__stack" style={{ height: `${Math.max(height, total > 0 ? 2 : 0)}%` }}>
              <span className="bars__in" style={{ height: `${100 - outShare}%` }} />
              <span className="bars__out" style={{ height: `${outShare}%` }} />
            </span>
          </span>
        )
      })}
    </div>
  )
}

export function HistoryPanel({ history, events, loading }: Props) {
  if (!history || history.series.length === 0) {
    return (
      <section className="panel">
        <div className="panel__head">
          <h2 className="panel__title">历史 · 近 60 分钟</h2>
          <span className="panel__hint">按分钟聚合</span>
        </div>
        <p className="panel__hint panel__hint--pad">
          {loading ? '读取历史中…' : '还没有这个进程的历史：历史层按分钟落桶，攒够一分钟才出图。'}
        </p>
      </section>
    )
  }

  return (
    <section className="panel">
      <div className="panel__head">
        <h2 className="panel__title">历史 · {history.process}</h2>
        <span className="panel__hint">
          {minuteLabel(history.since)} 起 · {history.series.length} 个分钟桶
        </span>
      </div>

      <Bars history={history} />

      <div className="history__stats">
        <div>
          <span className="detail__label">区间累计</span>
          <span className="mono">{bytes(history.total_bytes)}</span>
        </div>
        <div>
          <span className="detail__label">峰值</span>
          <span className="mono accent">{rate(history.peak_bps)}</span>
        </div>
        <div>
          <span className="detail__label">首次出现</span>
          <span className="mono">{ago(history.first_seen)}</span>
        </div>
        <div>
          <span className="detail__label">最近观测</span>
          <span className="mono">{ago(history.last_seen)}</span>
        </div>
      </div>

      <div className="history__events">
        <span className="detail__label">这个进程的变化</span>
        {events.length === 0 ? (
          <p className="panel__hint">
            暂无事件。出现 / 消失 / 尖峰都只在**桶定稿**时由已落库的观测值比较得出。
          </p>
        ) : (
          <ul className="events events--compact">
            {events.map((event) => (
              <li className="event" key={`${event.ts}-${event.kind}`}>
                <span className="mono dim">{minuteLabel(event.ts)}</span>
                <span className={`badge badge--${event.kind}`}>{KIND_LABEL[event.kind] ?? event.kind}</span>
                <span className="event__detail">{event.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
