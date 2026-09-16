import { useEffect, useReducer, useRef } from 'react'
import { STREAM_URL, fetchRates } from '../api'
import type { HistoryPoint, RateFrame } from '../types'

/**
 * SSE 状态机。
 *
 * 与 portwatch 的差别：那里推的是**事件增量**（added/removed/changed，前端做局部增删），
 * 这里推的是**窗口速率快照**（每秒一帧全量 Top-N）——流量是连续量，没有"增量"可言，
 * 局部更新反而会和真实值漂移。所以：snapshot 灌全量，rates 直接替换，history 只追加。
 */

const HISTORY = 120 // 保留 120 个窗口（默认 1s 一帧 = 2 分钟）

export interface StreamState {
  frame: RateFrame | null
  history: HistoryPoint[]
  connected: boolean
  beats: number
  lastFrameAt: number
  error: string | null
}

type Action =
  | { type: 'frame'; frame: RateFrame }
  | { type: 'heartbeat' }
  | { type: 'offline'; error: string }

const initial: StreamState = {
  frame: null,
  history: [],
  connected: false,
  beats: 0,
  lastFrameAt: 0,
  error: null,
}

function reducer(state: StreamState, action: Action): StreamState {
  switch (action.type) {
    case 'frame': {
      const { totals, ts } = action.frame
      const point: HistoryPoint = { ts, in_bps: totals.in_bps, out_bps: totals.out_bps }
      const history = [...state.history, point].slice(-HISTORY)
      return {
        ...state,
        frame: action.frame,
        history,
        connected: true,
        beats: state.beats + 1,
        lastFrameAt: Date.now(),
        error: null,
      }
    }
    case 'heartbeat':
      return { ...state, connected: true }
    case 'offline':
      return { ...state, connected: false, error: action.error }
    default:
      return state
  }
}

export function useRateStream(): StreamState {
  const [state, dispatch] = useReducer(reducer, initial)
  const retry = useRef(0)

  useEffect(() => {
    let source: EventSource | null = null
    let timer: number | undefined
    let stopped = false

    const connect = () => {
      if (stopped) return
      source = new EventSource(STREAM_URL)

      source.addEventListener('snapshot', (event) => {
        retry.current = 0
        dispatch({ type: 'frame', frame: JSON.parse((event as MessageEvent).data) as RateFrame })
      })
      source.addEventListener('rates', (event) => {
        retry.current = 0
        dispatch({ type: 'frame', frame: JSON.parse((event as MessageEvent).data) as RateFrame })
      })
      source.addEventListener('heartbeat', () => dispatch({ type: 'heartbeat' }))

      source.onerror = () => {
        source?.close()
        dispatch({ type: 'offline', error: 'SSE 连接中断' })
        // 指数退避重连（上限 8 秒），避免服务重启时刷屏
        retry.current = Math.min(retry.current + 1, 3)
        const delay = Math.min(8000, 500 * 2 ** retry.current)
        timer = window.setTimeout(connect, delay)
      }
    }

    // 先用一次 REST 拿首帧：SSE 首帧可能来自上一个窗口，避免开局空屏
    fetchRates(50)
      .then((frame) => dispatch({ type: 'frame', frame }))
      .catch(() => undefined)
      .finally(connect)

    return () => {
      stopped = true
      if (timer) window.clearTimeout(timer)
      source?.close()
    }
  }, [])

  // 长时间没有帧（服务挂了/被防火墙拦）：把连接状态改成离线
  useEffect(() => {
    const id = window.setInterval(() => {
      if (state.lastFrameAt && Date.now() - state.lastFrameAt > 4000) {
        dispatch({ type: 'offline', error: '超过 4 秒没有收到速率帧' })
      }
    }, 2000)
    return () => window.clearInterval(id)
  }, [state.lastFrameAt])

  return state
}
