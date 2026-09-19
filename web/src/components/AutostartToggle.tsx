import { useEffect, useState } from 'react'
import { fetchAutostart, setAutostart } from '../api'
import type { Autostart } from '../api'

/**
 * 开机自启开关（布尔）。
 *
 * Windows 走 HKCU 的 Run 键：免管理员、一行写入一行删除、完全可逆；
 * 写进去的命令就是"现在这条启动命令"（解释器 + server.py + 当前参数）。
 * 后端不支持时整个开关不渲染（不占位、不假装）。
 */
export function AutostartToggle() {
  const [state, setState] = useState<Autostart | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    fetchAutostart()
      .then((value) => {
        if (alive) setState(value)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])

  if (!state || !state.supported) return null

  const toggle = async () => {
    if (busy) return
    setBusy(true)
    try {
      setState(await setAutostart(!state.enabled))
    } catch {
      // 失败保持原状，下一次点击再试
    } finally {
      setBusy(false)
    }
  }

  return (
    <button
      type="button"
      className={`autostart ${state.enabled ? 'is-on' : ''}`}
      onClick={toggle}
      disabled={busy}
      role="switch"
      aria-checked={state.enabled}
      title={`${state.detail}\n启用后写入：${state.command}`}
    >
      <span className="autostart__track" aria-hidden="true">
        <span className="autostart__knob" />
      </span>
      开机自启{state.enabled ? ' 已开' : ' 已关'}
    </button>
  )
}
