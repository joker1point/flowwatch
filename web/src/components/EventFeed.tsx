import { clock } from '../format'
import type { ChangeEvent } from '../types'

interface Props {
  events: ChangeEvent[]
  selectedPid: number | null
  onSelect: (pid: number) => void
}

const KIND_LABEL: Record<string, string> = {
  appear: '出现',
  vanish: '消失',
  spike: '尖峰',
}

export function EventFeed({ events, selectedPid, onSelect }: Props) {
  return (
    <section className="panel panel--events">
      <div className="panel__head">
        <h2 className="panel__title">变化事件</h2>
        <span className="panel__hint">出现 / 消失 / 尖峰 —— 全部来自已落库的观测值比较</span>
      </div>

      {events.length === 0 ? (
        <p className="panel__hint panel__hint--pad">
          暂无事件。事件在**分钟桶定稿**时派生，所以刚启动的几分钟里是空的。
        </p>
      ) : (
        <ul className="events">
          {events.map((event) => (
            <li key={`${event.ts}-${event.kind}-${event.pid}`}>
              <button
                type="button"
                className={`event event--clickable ${selectedPid === event.pid ? 'is-selected' : ''}`}
                onClick={() => event.pid > 0 && onSelect(event.pid)}
              >
                <span className="mono dim">{clock(event.ts)}</span>
                <span className={`badge badge--${event.kind}`}>{KIND_LABEL[event.kind] ?? event.kind}</span>
                <span className="event__process">{event.process}</span>
                <span className="mono dim event__pid">{event.pid > 0 ? event.pid : ''}</span>
                <span className="event__detail">{event.detail}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
