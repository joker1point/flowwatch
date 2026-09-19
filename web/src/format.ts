/** 展示层格式化：流量监控里数字密度很高，统一在这里处理，避免各组件各写一套。 */

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']

export function bytes(value: number): string {
  let v = value
  let unit = 0
  while (v >= 1024 && unit < UNITS.length - 1) {
    v /= 1024
    unit += 1
  }
  const digits = unit === 0 ? 0 : v < 10 ? 2 : v < 100 ? 1 : 0
  return `${v.toFixed(digits)} ${UNITS[unit]}`
}

export function rate(value: number): string {
  return `${bytes(value)}/s`
}

/** 把 "203.0.113.9:443" 拆成主机与端口，便于分别排版（文档示例地址，RFC 5737）。 */
export function splitRemote(remote: string): { host: string; port: string } {
  const index = remote.lastIndexOf(':')
  if (index <= 0) return { host: remote, port: '' }
  return { host: remote.slice(0, index), port: remote.slice(index + 1) }
}

export function clock(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '--:--:--'
  return date.toLocaleTimeString('zh-CN', { hour12: false })
}

/** 历史桶只需要到分钟。 */
export function minuteLabel(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '--:--'
  return `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
}

/** 跨天的区间只给 HH:MM 会分不清是哪天：宽区间带上 MM-DD。 */
export function stampLabel(iso: string | null | undefined, withDate: boolean): string {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  const hhmm = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
  if (!withDate) return hhmm
  return `${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${hhmm}`
}

/** "12 分钟前" —— 回答"从什么时候开始的"时，相对时间比时间戳好读。 */
export function ago(iso: string | null): string {
  if (!iso) return '未知'
  const stamp = new Date(iso).getTime()
  if (Number.isNaN(stamp)) return '未知'
  const seconds = Math.max(0, (Date.now() - stamp) / 1000)
  if (seconds < 60) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}
