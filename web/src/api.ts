import type { ChangeEvent, DomainTop, Health, Meta, ProcessHistory, RateFrame } from './types'

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
