import type {
  AssistantStatus,
  ChangeEvent,
  DomainTop,
  Health,
  Meta,
  ProcessHistory,
  ProcessTop,
  RateFrame,
  TimelineResponse,
} from './types'

/** 默认直连本机 API；构建时可用 VITE_API_BASE=/ 改成同源（单端口部署）。 */
const RAW_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? 'http://127.0.0.1:8788'

export const API_BASE = RAW_BASE.replace(/\/+$/, '')
export const STREAM_URL = `${API_BASE}/api/stream`

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(`${path} → HTTP ${response.status}`)
  return (await response.json()) as T
}

export const fetchMeta = () => getJson<Meta>('/api/meta')
export const fetchHealth = () => getJson<Health>('/api/health')

export async function fetchRates(limit = 50): Promise<RateFrame> {
  return getJson<RateFrame>(`/api/rates?limit=${limit}`)
}

/* 历史层查询：数据按分钟聚合，所以前端也别按秒拉（15s 一次足够） */

export const fetchProcessHistory = (pid: number, minutes = 60, bucket = 1) =>
  getJson<ProcessHistory>(`/api/history/process?pid=${pid}&minutes=${minutes}&bucket=${bucket}`)

export const fetchEvents = (limit = 30, pid?: number) =>
  getJson<{ items: ChangeEvent[] }>(
    `/api/events?limit=${limit}${pid === undefined ? '' : `&pid=${pid}`}`,
  )

export const fetchTopDomains = (minutes = 60, limit = 5) =>
  getJson<{ minutes: number; items: DomainTop[] }>(
    `/api/history/domains?minutes=${minutes}&limit=${limit}`,
  )

/* 历史分析视图用的三个查询：整机分层曲线、进程排行、区间内事件（前端按时间过滤） */

export const fetchTimeline = (minutes: number, bucket: number) =>
  getJson<TimelineResponse>(`/api/history/timeline?minutes=${minutes}&bucket=${bucket}`)

/* 流量助手：状态查询 + SSE 对话（POST，所以不能用 EventSource，手写流解析） */

export const fetchAssistantStatus = () => getJson<AssistantStatus>('/api/assistant/status')

export async function assistantReset(
  kind: 'session' | 'blocks',
  sessionId: string,
): Promise<void> {
  const path =
    kind === 'session' ? `/api/assistant/session/${encodeURIComponent(sessionId)}` : '/api/assistant/memory'
  const response = await fetch(`${API_BASE}${path}`, { method: 'DELETE' })
  if (!response.ok) throw new Error(`${path} → HTTP ${response.status}`)
}

export interface AssistantEvent {
  event: string
  data: Record<string, unknown>
}

/** 逐事件把 SSE 流交给调用方；流异常时抛错，由面板显示。 */
export async function askAssistant(
  question: string,
  sessionId: string,
  onEvent: (item: AssistantEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${API_BASE}/api/assistant/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question, session_id: sessionId }),
    signal,
  })
  if (!response.ok || !response.body) throw new Error(`助手接口 HTTP ${response.status}`)

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const frames = buffer.split('\n\n')
    buffer = frames.pop() ?? ''
    for (const frame of frames) {
      const name = /^event:\s*(.+)$/m.exec(frame)?.[1]?.trim()
      const payload = /^data:\s*(.+)$/m.exec(frame)?.[1]
      if (!name) continue
      let data: Record<string, unknown> = {}
      if (payload) {
        try {
          data = JSON.parse(payload) as Record<string, unknown>
        } catch {
          data = { raw: payload }
        }
      }
      onEvent({ event: name, data })
    }
  }
}

export const fetchTopProcesses = (minutes: number, limit = 10) =>
  getJson<{ minutes: number; items: ProcessTop[] }>(
    `/api/history/top?minutes=${minutes}&limit=${limit}`,
  )
