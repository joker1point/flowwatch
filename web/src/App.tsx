import { useEffect, useMemo, useState } from 'react'
import { fetchEvents, fetchHealth, fetchProcessHistory, fetchTopDomains } from './api'
import { ConnDetail } from './components/ConnDetail'
import { DomainList } from './components/DomainList'
import { EventFeed } from './components/EventFeed'
import { Header } from './components/Header'
import { HistoryPanel } from './components/HistoryPanel'
import { HistoryView } from './components/HistoryView'
import { ProcessList } from './components/ProcessList'
import type { SortKey } from './components/ProcessList'
import { ThroughputChart } from './components/ThroughputChart'
import { bytes } from './format'
import { useRateStream } from './hooks/useRateStream'
import type { ChangeEvent, DomainTop, Health, ProcessHistory } from './types'

export default function App() {
  // 实时流里的 history 是"本机总吞吐"的环形缓冲，与历史层无关，这里改名避免撞车
  const { frame, history: throughput, connected, beats, error } = useRateStream()
  const [health, setHealth] = useState<Health | null>(null)
  const [query, setQuery] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('total')
  const [selectedPid, setSelectedPid] = useState<number | null>(null)
  const [events, setEvents] = useState<ChangeEvent[]>([])
  const [processEvents, setProcessEvents] = useState<ChangeEvent[]>([])
  const [processHistory, setProcessHistory] = useState<ProcessHistory | null>(null)
  const [historyLoading, setHistoryLoading] = useState(false)
  const [view, setView] = useState<'process' | 'domain'>('process')
  const [page, setPage] = useState<'live' | 'history'>('live')
  const [hourTopDomains, setHourTopDomains] = useState<DomainTop[]>([])

  // 近 1 小时的域名排行（历史库）：与实时域名列表互补 —— 一个看"此刻"，一个看"这一小时"
  useEffect(() => {
    let alive = true
    const load = () => {
      fetchTopDomains(60, 5)
        .then((data) => {
          if (alive) setHourTopDomains(data.items)
        })
        .catch(() => undefined)
    }
    load()
    const id = window.setInterval(load, 15000)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])

  // health 变化慢（端点表成本、累计包数），5 秒一次就够，不必挤进每秒的速率帧
  useEffect(() => {
    let alive = true
    const load = () => {
      fetchHealth()
        .then((value) => {
          if (alive) setHealth(value)
        })
        .catch(() => undefined)
    }
    load()
    const id = window.setInterval(load, 5000)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])

  // 事件流：历史层按分钟落桶，15 秒拉一次足够，别跟每秒的速率帧抢资源
  useEffect(() => {
    let alive = true
    const load = () => {
      fetchEvents(30)
        .then((data) => {
          if (alive) setEvents(data.items)
        })
        .catch(() => undefined)
    }
    load()
    const id = window.setInterval(load, 15000)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [])

  // 选中进程：历史曲线 + 它自己的变化事件
  useEffect(() => {
    if (selectedPid === null) {
      setProcessHistory(null)
      setProcessEvents([])
      return
    }
    let alive = true
    setHistoryLoading(true)
    const load = () => {
      Promise.all([fetchProcessHistory(selectedPid, 60, 1), fetchEvents(20, selectedPid)])
        .then(([series, own]) => {
          if (!alive) return
          setProcessHistory(series)
          setProcessEvents(own.items)
        })
        .catch(() => undefined)
        .finally(() => {
          if (alive) setHistoryLoading(false)
        })
    }
    load()
    const id = window.setInterval(load, 15000)
    return () => {
      alive = false
      window.clearInterval(id)
    }
  }, [selectedPid])

  const rows = useMemo(() => {
    const all = frame?.by_pid ?? []
    const keyword = query.trim().toLowerCase()
    if (!keyword) return all
    return all.filter(
      (row) =>
        row.process.toLowerCase().includes(keyword) ||
        String(row.pid) === keyword ||
        row.conns.some((conn) => conn.remote.toLowerCase().includes(keyword)),
    )
  }, [frame, query])

  const selected = useMemo(
    () => rows.find((row) => row.pid === selectedPid) ?? null,
    [rows, selectedPid],
  )

  const flows = rows.filter((row) => row.out_bps + row.in_bps > 0).length

  return (
    <div className="page">
      <Header frame={frame} health={health} connected={connected} beats={beats} />

      {!connected && error ? <div className="banner">连接中断：{error} —— 正在自动重连…</div> : null}

      <nav className="viewSwitch" role="tablist" aria-label="视图">
        <button
          type="button"
          role="tab"
          aria-selected={page === 'live'}
          className={page === 'live' ? 'is-active' : ''}
          onClick={() => setPage('live')}
        >
          实时
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={page === 'history'}
          className={page === 'history' ? 'is-active' : ''}
          onClick={() => setPage('history')}
        >
          历史与分析
        </button>
      </nav>

      {page === 'history' ? (
        <HistoryView health={health} />
      ) : (
        <>
      <div className="toolbar">
        <input
          className="search"
          type="search"
          placeholder="搜索进程名 / PID / 对端 IP"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="搜索进程或对端"
        />
        <span className="toolbar__count">
          <b>{flows}</b> 个进程正在收发
          {frame ? ` · 本帧 ${frame.by_pid.length} 条` : ''}
        </span>
        <span className="toolbar__hint">点任意行看连接明细 · 点表头切换排序</span>
      </div>

      <main className="grid">
        <div className="column">
          <section className="panel panel--list">
            <div className="panel__head">
              <div className="tabs" role="tablist">
                <button
                  type="button"
                  role="tab"
                  aria-selected={view === 'process'}
                  className={view === 'process' ? 'is-active' : ''}
                  onClick={() => setView('process')}
                >
                  进程
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={view === 'domain'}
                  className={view === 'domain' ? 'is-active' : ''}
                  onClick={() => setView('domain')}
                >
                  域名
                </button>
              </div>
              <span className="panel__hint">
                {frame ? `窗口 ${frame.window.toFixed(1)}s · ${frame.ts.slice(11)}` : '等待数据'}
              </span>
            </div>
            {view === 'process' ? (
              <ProcessList
                rows={rows}
                selectedPid={selectedPid}
                onSelect={setSelectedPid}
                sortKey={sortKey}
                onSort={setSortKey}
                hasFilter={query.trim().length > 0}
              />
            ) : (
              <DomainList entries={frame?.domains ?? []} hourTop={hourTopDomains} />
            )}
          </section>
          <EventFeed events={events} selectedPid={selectedPid} onSelect={setSelectedPid} />
        </div>

        <div className="column">
          <ThroughputChart history={throughput} />
          <ConnDetail row={selected} />
          <HistoryPanel
            history={processHistory}
            events={processEvents}
            loading={historyLoading}
          />
        </div>
      </main>
        </>
      )}

      <footer className="footer">
        <span>flowwatch · 只统计元数据（IP / 端口 / 字节数），不保存包体 · 只统计本机流量</span>
        <span className="mono">
          {[
            frame?.totals
              ? `未归因 近${frame.totals.rolling_windows}s ${(frame.totals.unknown_ratio_rolling * 100).toFixed(
                  1,
                )}%（本窗口 ${(frame.totals.unknown_ratio * 100).toFixed(1)}%）`
              : '正在连接采集层…',
            frame?.totals ? `属主受限 ${bytes(frame.totals.masked_bytes)}` : '',
            frame?.totals ? `别人的流量 ${frame.totals.foreign_packets.toLocaleString()} 包` : '',
            frame?.totals ? `非 TCP/UDP ${frame.totals.skipped_packets.toLocaleString()} 包` : '',
            health
              ? `域名解析 DNS ${health.names.dns_records} / SNI ${health.names.sni_records}（覆盖 ${(
                  health.names.hit_ratio * 100
                ).toFixed(0)}%）`
              : '',
            health
              ? health.etw.state === 'running'
                ? `ETW 归因 运行中（学到 ${health.etw.learned} 条连接）`
                : `ETW 归因 未启用（${
                    health.etw.state === 'denied' ? '需管理员' : health.etw.state
                  }）`
              : '',
          ]
            .filter(Boolean)
            .join(' · ')}
        </span>
      </footer>
    </div>
  )
}
