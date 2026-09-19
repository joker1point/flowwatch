import { rate, splitRemote } from '../format'
import type { PidRate } from '../types'

export type SortKey = 'total' | 'out' | 'in'

interface Props {
  rows: PidRate[]
  selectedPid: number | null
  onSelect: (pid: number) => void
  sortKey: SortKey
  onSort: (key: SortKey) => void
  hasFilter: boolean
  /** pid → 指向本机的连接数（连接表快照）。有值时行内标出"本机 N 连"——
   *  用来一眼看出"谁在用代理 / 本地服务"，这是抓包视角看不到的那一层。 */
  localConns?: Record<number, number>
}

function sortValue(row: PidRate, key: SortKey): number {
  if (key === 'out') return row.out_bps
  if (key === 'in') return row.in_bps
  return row.out_bps + row.in_bps
}

export function ProcessList({
  rows,
  selectedPid,
  onSelect,
  sortKey,
  onSort,
  hasFilter,
  localConns,
}: Props) {
  if (rows.length === 0) {
    return (
      <div className="empty">
        <span className="empty__glyph">[ : : ]</span>
        <p className="empty__title">{hasFilter ? '没有匹配的进程' : '等待第一个速率窗口'}</p>
        <p className="empty__hint">
          {hasFilter ? '试试放宽搜索词' : '采集层正在聚合，1 秒后出现数据'}
        </p>
      </div>
    )
  }

  const peak = Math.max(...rows.map((row) => row.out_bps + row.in_bps), 1)
  const sorted = [...rows].sort((a, b) => sortValue(b, sortKey) - sortValue(a, sortKey))

  return (
    <div className="list" role="table" aria-label="进程流量排行">
      <div className="list__head" role="row">
        <span role="columnheader">进程</span>
        <button
          type="button"
          className={`sort ${sortKey === 'out' ? 'is-active' : ''}`}
          onClick={() => onSort('out')}
        >
          发送
        </button>
        <button
          type="button"
          className={`sort ${sortKey === 'in' ? 'is-active' : ''}`}
          onClick={() => onSort('in')}
        >
          接收
        </button>
        <button
          type="button"
          className={`sort ${sortKey === 'total' ? 'is-active' : ''}`}
          onClick={() => onSort('total')}
        >
          合计
        </button>
        <span role="columnheader" className="list__col-remote">
          主要对端
        </span>
      </div>

      {sorted.map((row) => {
        const total = row.out_bps + row.in_bps
        const width = (total / peak) * 100
        const outShare = total > 0 ? (row.out_bps / total) * 100 : 0
        const top = row.conns[0]
        const remote = top ? splitRemote(top.remote) : null
        return (
          <button
            type="button"
            key={row.pid}
            role="row"
            className={`row ${selectedPid === row.pid ? 'is-selected' : ''}`}
            onClick={() => onSelect(row.pid)}
          >
            <span className="row__proc" role="cell">
              <span className="row__name">{row.process}</span>
              <span className="row__pid mono">{row.pid}</span>
            </span>

            <span className="row__rate mono" role="cell">
              {rate(row.out_bps)}
            </span>
            <span className="row__rate mono dim" role="cell">
              {rate(row.in_bps)}
            </span>
            <span className="row__rate mono" role="cell">
              {rate(total)}
            </span>

            <span className="row__remote" role="cell">
              {remote ? (
                <>
                  {top?.name ? (
                    // 有域名就优先显示域名：IP 放进 title，明细面板里还能看到完整 IP:端口
                    <span className="remote__name" title={`${remote.host}:${remote.port}`}>
                      {top.name}
                    </span>
                  ) : (
                    <>
                      <span className="mono remote__host">{remote.host}</span>
                      <span className="mono dim">:{remote.port}</span>
                    </>
                  )}
                  {row.conns.length > 1 ? <span className="more">+{row.conns.length - 1}</span> : null}
                  {localConns?.[row.pid] ? (
                    <span className="more" title="指向本机服务 / 代理的连接数（抓包看不到这一层）">
                      本机 {localConns[row.pid]} 连
                    </span>
                  ) : null}
                </>
              ) : (
                <span className="dim">—</span>
              )}
              <span className="bar" aria-hidden="true">
                <span className="bar__fill" style={{ width: `${width}%` }}>
                  <span className="bar__out" style={{ width: `${outShare}%` }} />
                </span>
              </span>
            </span>
          </button>
        )
      })}
    </div>
  )
}
