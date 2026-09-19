import type { LocalConns } from '../types'

interface Props {
  data?: LocalConns
  selectedPid: number | null
  onSelect: (pid: number) => void
}

/**
 * 本机连接归属：抓包只看得见代理进程，这一层补上"谁在连本机服务 / 代理"。
 *
 * 存在的理由（2026-09-19）：走本地代理的流量在网卡上只剩代理进程，真实发起方看不见。
 * 出事时按连接数排在最前面的那个进程就是元凶 —— 此前要靠手工跑
 * `Get-NetTCPConnection -RemotePort 7890 | Group-Object OwningProcess`，
 * 现在打开面板就能看到（见后端 localconn.py）。
 */
export function LocalConnPanel({ data, selectedPid, onSelect }: Props) {
  const rows = (data?.by_pid ?? []).filter((row) => row.local_conns > 0)
  const services = data?.services ?? []

  if (!data || (rows.length === 0 && services.length === 0)) {
    return (
      <section className="panel">
        <div className="panel__head">
          <span>本机连接</span>
          <span className="panel__hint">等待连接表快照</span>
        </div>
        <div className="empty">
          <p className="empty__title">没有指向本机的连接</p>
          <p className="empty__hint">
            应用走本地代理 / 连本地服务时，这里会列出发起方（抓包看不到这一层）
          </p>
        </div>
      </section>
    )
  }

  return (
    <section className="panel">
      <div className="panel__head">
        <span>本机连接</span>
        <span className="panel__hint">
          连本机 {data.local_conns} / 全部 {data.total_conns} 条 · 表 {data.refresh_ms}ms
        </span>
      </div>

      <div className="list list--local" role="table" aria-label="谁在连本机服务或代理">
        <div className="list__head" role="row">
          <span role="columnheader">发起方</span>
          <span role="columnheader">连本机</span>
          <span role="columnheader">目标端口</span>
          <span role="columnheader">新建/s</span>
        </div>
        {rows.slice(0, 12).map((row) => (
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
              {row.local_conns}
            </span>
            <span className="row__rate mono dim" role="cell">
              {row.top_peers.map((peer) => `:${peer.port}`).join(' ')}
            </span>
            <span className="row__rate mono" role="cell">
              {row.new_per_sec > 0 ? row.new_per_sec.toFixed(1) : '—'}
            </span>
          </button>
        ))}
      </div>

      {services.length > 0 ? (
        <div className="list list--local" role="table" aria-label="本机监听的服务">
          <div className="list__head" role="row">
            <span role="columnheader">本机服务（监听方）</span>
            <span role="columnheader">客户端</span>
            <span role="columnheader">连接</span>
            <span role="columnheader">端口</span>
          </div>
          {services.slice(0, 8).map((service) => (
            <div className="row" role="row" key={service.port}>
              <span className="row__proc" role="cell">
                <span className="row__name">{service.process ?? '未知进程'}</span>
                {service.pid ? <span className="row__pid mono">{service.pid}</span> : null}
              </span>
              <span className="row__rate mono" role="cell">
                {service.clients}
              </span>
              <span className="row__rate mono" role="cell">
                {service.conns}
              </span>
              <span className="row__rate mono dim" role="cell">
                :{service.port}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  )
}
