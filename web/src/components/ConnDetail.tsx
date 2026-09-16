import { rate, splitRemote } from '../format'
import type { PidRate } from '../types'

interface Props {
  row: PidRate | null
}

export function ConnDetail({ row }: Props) {
  if (!row) {
    return (
      <section className="panel panel--detail">
        <div className="panel__head">
          <h2 className="panel__title">连接明细</h2>
        </div>
        <p className="panel__hint">点击左侧任一进程，查看它在跟谁通信。</p>
      </section>
    )
  }

  const peak = Math.max(...row.conns.map((conn) => conn.out_bps + conn.in_bps), 1)

  return (
    <section className="panel panel--detail">
      <div className="panel__head">
        <h2 className="panel__title">{row.process}</h2>
        <span className="panel__hint mono">PID {row.pid}</span>
      </div>

      <div className="detail__totals">
        <div>
          <span className="detail__label">发送</span>
          <span className="mono accent">{rate(row.out_bps)}</span>
        </div>
        <div>
          <span className="detail__label">接收</span>
          <span className="mono">{rate(row.in_bps)}</span>
        </div>
        <div>
          <span className="detail__label">包数</span>
          <span className="mono">{row.packets.toLocaleString()}</span>
        </div>
        <div>
          <span className="detail__label">连接</span>
          <span className="mono">{row.conns.length}</span>
        </div>
      </div>

      {row.conns.length === 0 ? (
        <p className="panel__hint">本窗口没有可归因的连接明细。</p>
      ) : (
        <ul className="conns">
          {row.conns.map((conn) => {
            const { host, port } = splitRemote(conn.remote)
            const total = conn.out_bps + conn.in_bps
            return (
              <li className="conn" key={conn.remote}>
                <span className="conn__host">
                  {conn.name ? (
                    <>
                      <span className="conn__name">{conn.name}</span>
                      <span className="mono dim conn__ip">
                        {host}:{port}
                      </span>
                      <span className="src-tag" title={conn.name_source === 'sni' ? '来自 TLS SNI' : '来自 DNS 应答'}>
                        {conn.name_source}
                      </span>
                    </>
                  ) : (
                    <span className="mono conn__plain">
                      {host}
                      <span className="dim">:{port}</span>
                    </span>
                  )}
                </span>
                <span className="mono conn__rate">{rate(conn.in_bps)}</span>
                <span className="mono conn__rate accent">{rate(conn.out_bps)}</span>
                <span className="bar bar--thin" aria-hidden="true">
                  <span className="bar__fill" style={{ width: `${(total / peak) * 100}%` }} />
                </span>
              </li>
            )
          })}
        </ul>
      )}

      <p className="panel__note">
        只统计元数据（对端 IP / 端口 / 字节数），<b>不保存包体</b> —— 需要看内容请用 Wireshark 这类抓包分析工具。
        <br />
        域名来自 <b>DNS 应答</b> 与 <b>TLS ClientHello 的 SNI</b>（都是明文元数据，不读证书）；
        DoH / DoT / ECH / QUIC 拿不到域名，这里就只会显示 IP —— 不猜、不联网反查。
      </p>
    </section>
  )
}
