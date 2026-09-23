import { clock, rate } from '../format'
import type { Health, RateFrame } from '../types'
import { AutostartToggle } from './AutostartToggle'

interface Props {
  frame: RateFrame | null
  health: Health | null
  connected: boolean
  beats: number
}

function shortDevice(device: string): string {
  // \Device\NPF_{GUID} → NPF{GUID 前 8 位}
  const matched = /\{([0-9A-Fa-f-]{8})/.exec(device)
  if (matched) return `NPF_${matched[1]}`
  return device.replace(/^\\Device\\/, '').slice(0, 18)
}

export function Header({ frame, health, connected, beats }: Props) {
  const totals = frame?.totals
  return (
    <header className="head">
      <div className="head__top">
        <div className="head__brand">
          <span className="head__mark">flowwatch</span>
          <span className="head__sub">本机流量实时监控 · 按进程归因（只统计元数据）</span>
        </div>

        <div className="head__actions">
          <AutostartToggle />
          <div className={`pulse ${connected ? 'is-on' : 'is-off'}`} key={beats} title="每秒一帧速率窗口">
            <span className="pulse__dot" />
            <span className="pulse__text">
              {connected ? `实时 · ${frame ? clock(frame.ts) : ''}` : '连接中断'}
            </span>
          </div>
        </div>
      </div>

      <dl className="stats">
        <div className="stat stat--accent">
          <dt>发送速率</dt>
          <dd className="mono">{totals ? rate(totals.out_bps) : '—'}</dd>
        </div>
        <div className="stat">
          <dt>接收速率</dt>
          <dd className="mono">{totals ? rate(totals.in_bps) : '—'}</dd>
        </div>
        <div className="stat">
          <dt>本窗口包数</dt>
          <dd className="mono">{totals ? totals.packets_window.toLocaleString() : '—'}</dd>
        </div>
        <div className="stat">
          <dt>累计字节</dt>
          <dd className="mono">{health ? `${(health.bytes / 1048576).toFixed(1)} MiB` : '—'}</dd>
        </div>
        <div className={`stat ${totals && totals.unknown_ratio_rolling > 0.05 ? 'stat--warn' : ''}`}>
          {/* 用滚动口径：单窗口比率在空闲窗口会因为分母太小而剧烈波动（实测 1%~99%） */}
          <dt>未归因 · 滚动 {totals?.rolling_windows ?? 0}s</dt>
          <dd className="mono">{totals ? `${(totals.unknown_ratio_rolling * 100).toFixed(1)}%` : '—'}</dd>
        </div>
        <div className="stat">
          <dt>端点表</dt>
          <dd className="mono">
            {health ? `${health.endpoint.count} · ${health.endpoint.source} ${health.endpoint.refresh_ms.toFixed(0)}ms` : '—'}
          </dd>
        </div>
        <div className={`stat stat--wide ${health?.error ? 'stat--warn' : ''}`}>
          <dt>抓包设备</dt>
          <dd className="mono dim">
            {health?.device
              ? shortDevice(health.device)
              : health?.error
                ? '未启用采集'      // 有 error 时别再说"正在挑选网卡…" —— 那会让人一直等
                : '正在挑选网卡…'}
          </dd>
        </div>
      </dl>
    </header>
  )
}
