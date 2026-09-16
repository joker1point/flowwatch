import { bytes, rate } from '../format'
import type { DomainEntry, DomainTop } from '../types'

interface Props {
  entries: DomainEntry[]
  hourTop: DomainTop[]
}

const KIND_LABEL: Record<string, string> = { sni: 'SNI', dns: 'DNS', ip: 'IP', other: '其他' }

export function DomainList({ entries, hourTop }: Props) {
  if (entries.length === 0) {
    return (
      <div className="empty">
        <span className="empty__glyph">[ : : ]</span>
        <p className="empty__title">本窗口还没有可归类的连接</p>
        <p className="empty__hint">域名来自 DNS 应答与 TLS SNI，拿不到时按 IP 归类</p>
      </div>
    )
  }

  const peak = Math.max(...entries.map((item) => item.out_bytes + item.in_bytes), 1)

  return (
    <>
      <div className="list list--domains">
        <div className="list__head" role="row">
          <span>域名 / 对端</span>
          <span>来源</span>
          <span>发送</span>
          <span>接收</span>
          <span>合计</span>
        </div>
        {entries.map((entry) => {
          const total = entry.out_bytes + entry.in_bytes
          const width = (total / peak) * 100
          const outShare = total > 0 ? (entry.out_bytes / total) * 100 : 0
          return (
            <div className="row row--static" key={`${entry.kind}:${entry.name}`} role="row">
              <span className="row__proc" role="cell">
                <span className="row__name" title={entry.name}>
                  {entry.name}
                </span>
                <span className="row__pid mono">{entry.conns} 连接</span>
              </span>
              <span role="cell">
                <span className={`src-tag src-tag--${entry.kind}`}>{KIND_LABEL[entry.kind] ?? entry.kind}</span>
              </span>
              <span className="row__rate mono" role="cell">
                {rate(entry.out_bytes)}
              </span>
              <span className="row__rate mono dim" role="cell">
                {rate(entry.in_bytes)}
              </span>
              <span className="row__rate mono" role="cell">
                {rate(total)}
                <span className="bar bar--inline" aria-hidden="true">
                  <span className="bar__fill" style={{ width: `${width}%` }}>
                    <span className="bar__out" style={{ width: `${outShare}%` }} />
                  </span>
                </span>
              </span>
            </div>
          )
        })}
      </div>

      <p className="panel__note">
        {hourTop.length === 0
          ? '近 1 小时还没有域名记录（历史层按分钟落桶）。'
          : `近 1 小时 Top：${hourTop
              .map((item) => `${item.name} ${bytes(item.total_bytes)}`)
              .join(' · ')}`}
        <br />
        未识别（来源 <b>IP</b>）多来自 DoH / DoT / ECH / QUIC 或被代理转发的连接 —— 拿不到就是拿不到。
      </p>
    </>
  )
}
