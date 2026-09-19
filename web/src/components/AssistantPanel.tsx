import { useEffect, useMemo, useRef, useState } from 'react'
import {
  askAssistant,
  assistantReset,
  fetchAssistantConfig,
  fetchAssistantStatus,
  saveAssistantConfig,
  testAssistantConfig,
} from '../api'
import type { AssistantConfig, AssistantConfigIn } from '../api'
import type { AssistantStatus } from '../types'

/** 面板里的一行：用户提问 / 助手回答 / 工具调用过程 / 系统提示。 */
type Item =
  | { kind: 'user'; text: string }
  | { kind: 'assistant'; text: string; scope: string; tools: string[] }
  | { kind: 'tool'; name: string; effect: string }
  | { kind: 'notice'; text: string }

const SESSION_KEY = 'flowwatch-assistant-session'

/** 会话 id 落在 localStorage：刷新页面也接着上一轮聊，记忆层才连贯。 */
function sessionId(): string {
  try {
    const saved = window.localStorage.getItem(SESSION_KEY)
    if (saved) return saved
    const fresh = `web-${Math.random().toString(36).slice(2, 10)}`
    window.localStorage.setItem(SESSION_KEY, fresh)
    return fresh
  } catch {
    return 'web-anon'
  }
}

const SUGGESTIONS = [
  '现在谁在占带宽？',
  '排行第一那个进程是怎么回事',
  '近 24 小时有哪些变化事件',
]

function Row({ item }: { item: Item }) {
  if (item.kind === 'user') {
    return <p className="msg msg--user">{item.text}</p>
  }
  if (item.kind === 'tool') {
    return (
      <p className="msg msg--tool mono">
        <span className="dim">调用</span> {item.name} <span className="dim">· {item.effect}</span>
      </p>
    )
  }
  if (item.kind === 'notice') {
    return <p className="msg msg--notice">{item.text}</p>
  }
  return (
    <div className="msg msg--assistant">
      <p className="msg__text">{item.text}</p>
      <p className="msg__meta mono">
        {item.scope === 'detail' ? '明细档' : '聚合档'}
        {item.tools.length > 0 ? ` · 工具 ${item.tools.length} 次` : ''}
      </p>
    </div>
  )
}

export function AssistantPanel() {
  const [status, setStatus] = useState<AssistantStatus | null>(null)
  const [items, setItems] = useState<Item[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // ---- 模型设置（开源用户开箱可配：写 assistant_config.json，保存即生效）----
  const [showSettings, setShowSettings] = useState(false)
  const [config, setConfig] = useState<AssistantConfig | null>(null)
  const [form, setForm] = useState<AssistantConfigIn>({
    provider: 'openai',
    base_url: '',
    api_key: '',
    model: '',
  })
  const [cfgBusy, setCfgBusy] = useState<'save' | 'test' | null>(null)
  const [cfgNotice, setCfgNotice] = useState<string | null>(null)
  const [cfgOk, setCfgOk] = useState<boolean | null>(null)
  const sid = useMemo(sessionId, [])
  const listRef = useRef<HTMLDivElement | null>(null)

  const refresh = () => {
    fetchAssistantStatus()
      .then(setStatus)
      .catch(() => undefined)
  }

  useEffect(() => {
    let alive = true
    fetchAssistantStatus()
      .then((value) => {
        if (alive) setStatus(value)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])

  // 新内容进来就滚到底（对话面板的默认预期）
  useEffect(() => {
    const node = listRef.current
    if (node) node.scrollTop = node.scrollHeight
  }, [items, busy])

  const send = async (question: string) => {
    const text = question.trim()
    if (!text || busy) return
    setBusy(true)
    setError(null)
    setItems((prev) => [...prev, { kind: 'user', text }])
    setInput('')
    try {
      await askAssistant(text, sid, ({ event, data }) => {
        if (event === 'meta') {
          setStatus((prev) =>
            prev
              ? {
                  ...prev,
                  configured: Boolean(data.configured),
                  provider_label: String(data.provider_label ?? prev.provider_label),
                  provider: String(data.provider ?? prev.provider),
                }
              : prev,
          )
        } else if (event === 'tool') {
          setItems((prev) => [
            ...prev,
            { kind: 'tool', name: String(data.name ?? ''), effect: String(data.effect ?? '') },
          ])
        } else if (event === 'done') {
          setItems((prev) => [
            ...prev,
            {
              kind: 'assistant',
              text: String(data.text ?? ''),
              scope: String(data.scope ?? ''),
              tools: Array.isArray(data.tools) ? (data.tools as string[]) : [],
            },
          ])
        } else if (event === 'error') {
          setItems((prev) => [...prev, { kind: 'notice', text: String(data.message ?? '未知错误') }])
        }
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
      refresh() // 记忆占用可能变了
    }
  }

  const clearSession = () => {
    assistantReset('session', sid)
      .then(() => {
        setItems([])
        refresh()
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
  }

  // ---- 模型设置：打开时回填 / 保存 / 试连 ----
  const openSettings = () => {
    void fetchAssistantConfig()
      .then((value) => {
        setConfig(value)
        const known = ['openai', 'ollama', 'mock']
        setForm({
          provider: (
            known.includes(value.provider) ? value.provider : 'openai'
          ) as AssistantConfigIn['provider'],
          base_url: value.base_url,
          api_key: '',
          model: value.model,
        })
      })
      .catch(() => undefined)
  }

  const saveConfig = async () => {
    setCfgBusy('save')
    setCfgNotice(null)
    setCfgOk(null)
    try {
      const res = await saveAssistantConfig(form)
      setCfgNotice(`已保存并生效：${res.provider_label}`)
      setCfgOk(true)
      refresh()
      openSettings()
    } catch (err) {
      setCfgNotice(err instanceof Error ? err.message : String(err))
      setCfgOk(false)
    } finally {
      setCfgBusy(null)
    }
  }

  const testConfig = async () => {
    setCfgBusy('test')
    setCfgNotice('正在测试连通性（真实调用一次模型）…')
    setCfgOk(null)
    try {
      const res = await testAssistantConfig(form)
      setCfgNotice(res.detail)
      setCfgOk(res.ok)
    } catch (err) {
      setCfgNotice(err instanceof Error ? err.message : String(err))
      setCfgOk(false)
    } finally {
      setCfgBusy(null)
    }
  }

  const blocks = status?.memory.blocks ?? []

  return (
    <section className="panel panel--assistant">
      <div className="panel__head">
        <h2 className="panel__title">流量助手</h2>
        <span className="panel__hint">{status ? status.provider_label : '读取中…'}</span>
        <button
          type="button"
          className="assistant__clear"
          onClick={() => {
            const next = !showSettings
            setShowSettings(next)
            setCfgNotice(null)
            if (next) openSettings()
          }}
        >
          {showSettings ? '收起设置' : '模型设置'}
        </button>
        <button type="button" className="assistant__clear" onClick={clearSession} disabled={busy}>
          清空对话
        </button>
      </div>

      {showSettings ? (
        <div className="assistant__settings">
          <label className="assistant__field">
            <span className="assistant__fieldLabel">接口类型</span>
            <select
              className="assistant__select"
              value={form.provider}
              onChange={(event) =>
                setForm((prev) => ({
                  ...prev,
                  provider: event.target.value as AssistantConfigIn['provider'],
                }))
              }
              aria-label="接口类型"
            >
              <option value="openai">OpenAI 兼容（OpenAI / DashScope / DeepSeek / 各类中转）</option>
              <option value="ollama">本地 Ollama（数据零外发）</option>
              <option value="mock">mock（不联网，仅演示链路）</option>
            </select>
          </label>

          {form.provider !== 'mock' ? (
            <>
              <label className="assistant__field">
                <span className="assistant__fieldLabel">Base URL</span>
                <input
                  className="assistant__input"
                  value={form.base_url}
                  onChange={(event) => setForm((prev) => ({ ...prev, base_url: event.target.value }))}
                  placeholder={
                    form.provider === 'ollama'
                      ? 'http://127.0.0.1:11434/v1'
                      : 'https://dashscope.aliyuncs.com/compatible-mode/v1'
                  }
                />
              </label>
              {form.provider === 'openai' ? (
                <label className="assistant__field">
                  <span className="assistant__fieldLabel">API Key</span>
                  <input
                    className="assistant__input"
                    type="password"
                    value={form.api_key}
                    onChange={(event) => setForm((prev) => ({ ...prev, api_key: event.target.value }))}
                    placeholder={
                      config?.api_key_masked
                        ? `已保存 ${config.api_key_masked}（留空 = 不修改）`
                        : 'sk-...'
                    }
                    autoComplete="off"
                  />
                </label>
              ) : null}
              <label className="assistant__field">
                <span className="assistant__fieldLabel">模型</span>
                <input
                  className="assistant__input"
                  value={form.model}
                  onChange={(event) => setForm((prev) => ({ ...prev, model: event.target.value }))}
                  placeholder={form.provider === 'ollama' ? 'qwen2.5:7b' : 'qwen-plus'}
                />
              </label>
            </>
          ) : null}

          <div className="assistant__settingsActions">
            <button
              type="button"
              className="assistant__send"
              onClick={() => void saveConfig()}
              disabled={cfgBusy !== null}
            >
              {cfgBusy === 'save' ? '保存中…' : '保存并生效'}
            </button>
            <button
              type="button"
              className="assistant__clear"
              onClick={() => void testConfig()}
              disabled={cfgBusy !== null}
            >
              {cfgBusy === 'test' ? '测试中…' : '测试连接'}
            </button>
          </div>
          {cfgNotice ? (
            <p className={cfgOk === false ? 'msg msg--notice' : 'panel__hint'}>{cfgNotice}</p>
          ) : null}
          <p className="panel__hint">
            配置保存在本机 <code>{config?.config_path ?? 'assistant_config.json'}</code>
            （已加入 .gitignore，不会提交）。环境变量 / .env 仍可用，页面里的设置优先。
          </p>
        </div>
      ) : null}

      {blocks.length > 0 ? (
        <p
          className="assistant__memory mono"
          title="长期记忆块（跨会话保留）：标签 已用/上限 字符"
        >
          记忆 {blocks.map((block) => `${block.label} ${block.chars_current}/${block.limit}`).join(' · ')}
          {status && status.memory.compacted > 0 ? ` · 已压缩 ${status.memory.compacted} 条` : ''}
        </p>
      ) : null}

      <div className="assistant__list" ref={listRef}>
        {items.length === 0 ? (
          <div className="assistant__empty">
            <p className="panel__hint">
              问它本机的流量：谁在占带宽、某个进程为什么异常、某个域名连了多少 ——
              回答只基于 flowwatch 自己采到的数据，不编造。
            </p>
            <div className="assistant__chips">
              {SUGGESTIONS.map((text) => (
                <button key={text} type="button" onClick={() => void send(text)} disabled={busy}>
                  {text}
                </button>
              ))}
            </div>
          </div>
        ) : (
          items.map((item, index) => <Row key={`${index}-${item.kind}`} item={item} />)
        )}
        {busy ? <p className="msg msg--tool mono dim">查询中…</p> : null}
      </div>

      {status && !status.configured ? (
        <p className="panel__note">
          助手还没配模型：点右上角「模型设置」，填一个 OpenAI 兼容接口或本地 Ollama 即可用 ——
          保存后立即生效，无需重启。用 ollama 或 mock 则零外发。
        </p>
      ) : null}

      <form
        className="assistant__form"
        onSubmit={(event) => {
          event.preventDefault()
          void send(input)
        }}
      >
        <input
          className="assistant__input"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="问点什么…"
          aria-label="向流量助手提问"
          disabled={busy}
        />
        <button className="assistant__send" type="submit" disabled={busy || input.trim().length === 0}>
          发送
        </button>
      </form>

      {error ? <p className="msg msg--notice">{error}</p> : null}
    </section>
  )
}
