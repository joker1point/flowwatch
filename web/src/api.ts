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

/* 笔记区：用户笔记（落盘）+ AI 每日流量笔记 + 人设 */

export interface UserNotes {
  content: string
  path: string
}

export interface Persona {
  id: string
  name: string
  prompt: string
  builtin?: boolean
}

export interface AiNote {
  date: string
  persona_id: string
  persona_name: string
  content: string
  generated_at: number
}

export const fetchUserNotes = () => getJson<UserNotes>('/api/notes/user')

export async function saveUserNotes(content: string): Promise<{ ok: boolean; bytes: number }> {
  const response = await fetch(`${API_BASE}/api/notes/user`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  })
  if (!response.ok) throw new Error(`保存失败 HTTP ${response.status}`)
  return (await response.json()) as { ok: boolean; bytes: number }
}

export const fetchPersonas = () => getJson<{ items: Persona[] }>('/api/notes/personas')

export async function savePersona(payload: {
  id?: string
  name: string
  prompt: string
}): Promise<Persona> {
  const response = await fetch(`${API_BASE}/api/notes/personas`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(`保存人设失败 HTTP ${response.status}`)
  return ((await response.json()) as { item: Persona }).item
}

export async function deletePersona(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/notes/personas/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw new Error(`删除人设失败 HTTP ${response.status}`)
}

export const fetchAiNotes = () => getJson<{ items: AiNote[] }>('/api/notes/ai')

export async function generateAiNote(personaId: string, date?: string): Promise<AiNote> {
  const response = await fetch(`${API_BASE}/api/notes/ai/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ persona_id: personaId, date: date ?? null }),
  })
  if (!response.ok) throw new Error(`生成失败 HTTP ${response.status}`)
  return (await response.json()) as AiNote
}

export async function deleteAiNote(date: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/notes/ai/${encodeURIComponent(date)}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw new Error(`删除笔记失败 HTTP ${response.status}`)
}

/* 模型设置：开源用户在自己的机器上填接口 / Key；保存到 assistant_config.json 后立即生效 */

export interface AssistantConfig {
  configured: boolean
  provider: string
  base_url: string
  model: string
  /** 只回显前 6 位的掩码（如 sk-abc***）；提交时留空 = 不修改 */
  api_key_masked: string
  source: 'file' | 'env' | 'none' | string
  config_path: string
}

export interface AssistantConfigIn {
  provider: 'openai' | 'ollama' | 'mock'
  base_url: string
  api_key: string
  model: string
}

export const fetchAssistantConfig = () => getJson<AssistantConfig>('/api/assistant/config')

export async function saveAssistantConfig(
  payload: AssistantConfigIn,
): Promise<{ ok: boolean; provider_label: string }> {
  const response = await fetch(`${API_BASE}/api/assistant/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const detail = (await response.json().catch(() => null)) as { detail?: string } | null
    throw new Error(detail?.detail ?? `保存失败 HTTP ${response.status}`)
  }
  return (await response.json()) as { ok: boolean; provider_label: string }
}

export async function testAssistantConfig(
  payload: AssistantConfigIn,
): Promise<{ ok: boolean; detail: string }> {
  const response = await fetch(`${API_BASE}/api/assistant/config/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(`测试失败 HTTP ${response.status}`)
  return (await response.json()) as { ok: boolean; detail: string }
}

/* 开机自启：Windows 走 HKCU Run 键（免管理员、可逆）；不支持时前端整个开关不渲染 */

export interface Autostart {
  supported: boolean
  enabled: boolean
  /** 启用后会写入注册表的命令（= 当前这条启动命令原样记下） */
  command: string
  detail: string
}

export const fetchAutostart = () => getJson<Autostart>('/api/autostart')

export async function setAutostart(enabled: boolean): Promise<Autostart> {
  const response = await fetch(`${API_BASE}/api/autostart`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  })
  if (!response.ok) throw new Error(`设置失败 HTTP ${response.status}`)
  return (await response.json()) as Autostart
}
