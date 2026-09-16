/** 与 API 层对齐的类型（flowwatch/v1）。 */

export interface ConnRate {
  remote: string
  /** 域名（来自 DNS 应答或 TLS SNI）；拿不到就是 null —— 不猜、不用第三方库查 */
  name: string | null
  name_source: 'sni' | 'dns' | null
  out_bps: number
  in_bps: number
}

export interface PidRate {
  pid: number
  process: string
  out_bps: number
  in_bps: number
  packets: number
  conns: ConnRate[]
}

/** 未归因明细：诊断"说不清是谁的流量"到底长什么样。 */
export interface UnknownFlow {
  flow: string
  out_bytes: number
  in_bytes: number
  packets: number
}

export interface Totals {
  packets: number
  bytes: number
  packets_window: number
  unknown_bytes_window: number
  unknown_ratio: number
  /** 滚动口径：近 N 个窗口的合计比率（单窗口比率在空闲窗口会因分母太小而剧烈波动） */
  unknown_ratio_rolling: number
  masked_ratio_rolling: number
  rolling_windows: number
  /** 端点已知、但属主受权限限制（非提权运行）的那部分字节 */
  masked_bytes: number
  out_bps: number
  in_bps: number
  /** 广播域里别人的帧：不算本机流量，也不算归因失败 */
  foreign_packets: number
  /** 非 TCP/UDP 或头部不全：不参与统计 */
  skipped_packets: number
}

/** 域名维度条目（本窗口内按全部连接汇总；`kind='ip'` 表示还没拿到域名）。 */
export interface DomainEntry {
  name: string
  kind: 'sni' | 'dns' | 'ip' | 'other' | string
  out_bytes: number
  in_bytes: number
  conns: number
}

export interface DomainTop extends DomainEntry {
  total_bytes: number
}

export interface RateFrame {
  schema: string
  ts: string
  window: number
  totals: Totals
  unknown_flows?: UnknownFlow[]
  /** 本窗口域名排行（采集层按全部连接汇总，超出上限的并入 "(其他域名)"） */
  domains?: DomainEntry[]
  by_pid: PidRate[]
}

export interface Meta {
  schema: string
  flush_interval: number
  top_n: number
  endpoint_refresh: number
  devices: string
  snaplen: number
  privacy: string
}

export interface Health {
  status: string
  device: string
  error: string | null
  packets: number
  bytes: number
  parse_errors: number
  endpoint: {
    source: string
    count: number
    refresh_ms: number
    refresh_interval: number
  }
  subscribers: number
  frames: number
  /** 增强归因层（ETW）：拿不到权限就如实降级，主链路照常 */
  etw: {
    state: string
    detail: string
    events: number
    learned: number
    forgotten: number
    sanity_failures: number
  }
  names: {
    dns_records: number
    sni_records: number
    ips_known: number
    endpoints_known: number
    lookups: number
    hits: number
    hit_ratio: number
    parse_errors: number
    coverage_note: string
  }
  ts: string
}

export interface HistoryPoint {
  ts: string
  in_bps: number
  out_bps: number
}

/** 历史层（时间桶聚合）返回的样本：速率 = 桶内字节 / 桶宽。 */
export interface HistorySample {
  ts: string
  out_bps: number
  in_bps: number
  bytes: number
  packets: number
}

export interface ProcessHistory {
  pid: number
  process: string
  bucket_seconds: number
  since: string
  first_seen: string | null
  last_seen: string | null
  total_bytes: number
  peak_bps: number
  series: HistorySample[]
}

export type EventKind = 'appear' | 'vanish' | 'spike'

export interface ChangeEvent {
  ts: string
  kind: EventKind | string
  pid: number
  process: string
  detail: string
}
