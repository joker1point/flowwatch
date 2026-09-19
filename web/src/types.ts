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

/** 本机连接归属：系统连接表快照 —— 抓包看不到环回与代理那一层，这里补上。 */
export interface LocalConnRow {
  pid: number
  process: string
  /** 活动连接总数（ESTABLISHED） */
  conns: number
  /** 其中指向「本机地址」的条数：= 在用本机的代理/本地服务 */
  local_conns: number
  /** 新出现的本机侧端点速率：短连接风暴（重试循环）会在这里爆表 */
  new_per_sec: number
  /** 在连哪些本机端口（Top N） */
  top_peers: { port: number; conns: number }[]
}

/** 本机监听端口 ← 有哪些进程在连它。 */
export interface LocalService {
  port: number
  pid: number | null
  process: string | null
  /** 不同客户端进程数 */
  clients: number
  conns: number
}

export interface LocalConns {
  source: string
  error: string
  refresh_ms: number
  refresh_interval: number
  total_conns: number
  local_conns: number
  by_pid: LocalConnRow[]
  services: LocalService[]
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
  /** 本机连接归属（连接表快照）：回答"谁在连代理/本地服务"，抓包视角看不见 */
  local_conns?: LocalConns
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
  /** 历史层自述：库多大、攒了多久、有没有丢样本 —— 历史分析视图用它交代数据覆盖面 */
  history: {
    enabled: boolean
    path: string
    bucket_seconds: number
    retention_days: number
    buckets: number
    events: number
    domain_rows: number
    /** 库里最早的一桶（数据覆盖从这里开始） */
    oldest: string | null
    writes: number
    events_written: number
    cold_start_skipped: number
    queued: number
    dropped: number
    errors: number
    last_error: string
    last_write_ms: number
    size_kb: number
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

/** 整机分层时间序列（`/api/history/timeline`）：本机流量按归属拆三层，别人的流量单独给。 */
export interface TimelinePoint {
  ts: string
  own_out_bps: number
  own_in_bps: number
  /** 端点已知、但属主受权限限制（非提权运行） */
  masked_bps: number
  /** 说不清是谁的 */
  unattributed_bps: number
  /** 广播域里别人的帧：物理上不属于本机，单独看 */
  foreign_bps: number
}

export interface TimelineResponse {
  bucket_seconds: number
  since: string
  series: TimelinePoint[]
}

/** 区间内按累计字节排行的进程（`/api/history/top`）。 */
export interface ProcessTop {
  pid: number
  process: string
  total_bytes: number
  out_bytes: number
  in_bytes: number
  first_seen: string
  last_seen: string
}

/** 流量助手的长期记忆块（对齐 Letta 的 Memory Block：label 寻址 + 容量契约）。 */
export interface AssistantBlock {
  label: string
  description: string
  value: string
  limit: number
  read_only: boolean
  chars_current: number
}

export interface AssistantStatus {
  schema: string
  configured: boolean
  provider: string
  provider_label: string
  model: string
  routing: { default_scope: string; detail_triggers: string[] }
  tools: { name: string; scope: string; description: string }[]
  memory: { sessions: number; messages: number; compacted: number; blocks: AssistantBlock[] }
  privacy: string
}

export type EventKind = 'appear' | 'vanish' | 'spike'

export interface ChangeEvent {
  ts: string
  kind: EventKind | string
  pid: number
  process: string
  detail: string
}
