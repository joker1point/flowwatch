import { useCallback, useEffect, useState } from 'react'
import {
  checkAlertRules,
  deleteAlertRule,
  fetchAlertRules,
  fetchTopProcesses,
  saveAlertRule,
  testAlertRule,
} from '../api'
import type { AlertRuleIn } from '../api'
import type { AlertCondition, AlertRule, ProcessTop } from '../types'
import { bytes } from '../format'

/**
 * 告警面板（「告警」页）：
 * 进程流量告警规则的 Web 配置——任意进程 × 双条件（窗口累计 / 持续时长）。
 * 每张卡实时展示条件的「当前值 / 阈值 / 是否命中」，评估由服务端守护每 5 分钟跑一轮。
 *
 * 降低门槛的三件套（2026-10-16）：① 一键模板（没头绪也能起）；② 进程点选（不用会写通配符）；
 * ③ 文案去术语（示例不再出现具体软件名）。
 */

const DIRECTION_LABEL: Record<string, string> = { out: '上行', in: '下行', total: '总流量' }

function condLabel(c: AlertCondition): string {
  if (c.type === 'window_bytes') {
    return `近 ${c.window_minutes} 分钟${DIRECTION_LABEL[c.direction ?? 'total']} ≥ ${bytes(c.bytes ?? 0)}`
  }
  return `持续传输 ≥ ${c.minutes} 分钟`
}

function ConditionRow({ c, s }: { c: AlertCondition; s: AlertRule['status'] }) {
  // status.conditions 与 rule.conditions 同序（后端按序评估）
  const st = s.conditions.find((x) => x.type === c.type && sameParams(x, c))
  const hit = Boolean(st?.hit)
  return (
    <li className={`ar__cond${hit ? ' ar__cond--hit' : ''}`}>
      <span className="ar__cond-mark">{hit ? '🔔' : '·'}</span>
      <span className="ar__cond-label">{condLabel(c)}</span>
      <span className="ar__cond-current">
        {st?.error
          ? st.error
          : c.type === 'window_bytes'
            ? `当前 ${bytes(st?.current ?? 0)}`
            : `当前连续 ${st?.current ?? 0} 分钟${st?.active === false ? '（此刻没在传）' : ''}`}
      </span>
    </li>
  )
}

function sameParams(x: { window_minutes?: number; minutes?: number; direction?: string }, c: AlertCondition): boolean {
  if (c.type === 'window_bytes') {
    return x.window_minutes === c.window_minutes && x.direction === (c.direction ?? 'total')
  }
  return x.minutes === c.minutes
}

function fmtTs(ts: number | null | undefined): string {
  if (!ts) return '从未'
  return new Date(ts * 1000).toLocaleString()
}

const EMPTY_DRAFT: AlertRuleIn = {
  name: '',
  processes: [],
  enabled: true,
  match: 'any',
  conditions: [{ type: 'window_bytes', window_minutes: 60, bytes: 1024 ** 3, direction: 'total' }],
  cooldown_minutes: 30,
}

/** 一键模板：预填名称与条件，进程留空引导去点选 */
const TEMPLATES: { label: string; hint: string; draft: AlertRuleIn }[] = [
  {
    label: '大流量上传',
    hint: '任意进程 1 小时内上传 ≥ 1 GB',
    draft: {
      name: '大流量上传',
      processes: [],
      enabled: true,
      match: 'any',
      conditions: [{ type: 'window_bytes', window_minutes: 60, bytes: 1024 ** 3, direction: 'out' }],
      cooldown_minutes: 30,
    },
  },
  {
    label: '大流量下载',
    hint: '任意进程 1 小时内下载 ≥ 1 GB',
    draft: {
      name: '大流量下载',
      processes: [],
      enabled: true,
      match: 'any',
      conditions: [{ type: 'window_bytes', window_minutes: 60, bytes: 1024 ** 3, direction: 'in' }],
      cooldown_minutes: 30,
    },
  },
  {
    label: '持续传输',
    hint: '任意进程连续传输 ≥ 1 小时',
    draft: {
      name: '持续传输',
      processes: [],
      enabled: true,
      match: 'any',
      conditions: [{ type: 'sustained_minutes', minutes: 60 }],
      cooldown_minutes: 30,
    },
  },
]

export function AlertRulesPanel() {
  const [rules, setRules] = useState<AlertRule[]>([])
  const [intervalSec, setIntervalSec] = useState(300)
  const [path, setPath] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)

  const [editingId, setEditingId] = useState<string | null>(null)   // null=不在编辑；'new'=新建
  const [draft, setDraft] = useState<AlertRuleIn>(EMPTY_DRAFT)
  const [processText, setProcessText] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [procOptions, setProcOptions] = useState<ProcessTop[]>([])

  const load = useCallback(() => {
    fetchAlertRules()
      .then((v) => {
        setRules(v.items)
        setIntervalSec(v.interval_sec)
        setPath(v.path)
        setLoadError(null)
      })
      .catch((e) => setLoadError(String(e)))
  }, [])

  useEffect(() => {
    load()
    // 15s 轮询：条件当前值是慢变量（分钟级桶），跟事件流同节奏足够
    const id = window.setInterval(load, 15000)
    return () => window.clearInterval(id)
  }, [load])

  // 进入编辑/新建时拉一次「近 24 小时有流量的进程」，给点选列表用（失败静默，不阻塞表单）
  useEffect(() => {
    if (!editingId) return
    fetchTopProcesses(24 * 60, 24)
      .then((v) => setProcOptions(v.items ?? []))
      .catch(() => setProcOptions([]))
  }, [editingId])

  /** 把点选的进程名追加进匹配串（去重，不区分大小写） */
  const appendProcess = (name: string) => {
    setProcessText((prev) => {
      const parts = prev.split(/[,，]/).map((s) => s.trim()).filter(Boolean)
      if (parts.some((p) => p.toLowerCase() === name.toLowerCase())) return prev
      return [...parts, name].join(', ')
    })
  }

  const startCreate = () => {
    setEditingId('new')
    setDraft(EMPTY_DRAFT)
    setProcessText('')
    setFormError(null)
  }

  const startTemplate = (t: (typeof TEMPLATES)[number]) => {
    setEditingId('new')
    setDraft({ ...t.draft, conditions: t.draft.conditions.map((c) => ({ ...c })) })
    setProcessText('')
    setFormError(null)
  }

  const startEdit = (rule: AlertRule) => {
    setEditingId(rule.id)
    setDraft({
      name: rule.name,
      processes: rule.processes,
      enabled: rule.enabled,
      match: rule.match,
      conditions: rule.conditions.map((c) => ({ ...c })),
      cooldown_minutes: rule.cooldown_minutes,
    })
    setProcessText(rule.processes.join(', '))
    setFormError(null)
  }

  const cancelEdit = () => {
    setEditingId(null)
    setFormError(null)
  }

  const handleSave = async () => {
    const processes = processText
      .split(/[,，]/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (!draft.name.trim()) {
      setFormError('规则名称不能为空')
      return
    }
    if (processes.length === 0) {
      setFormError('至少填一个进程名——可从下面列表点选，或手工填（% 表示任意字符，如 %update%）')
      return
    }
    if (draft.conditions.length === 0) {
      setFormError('至少添加一个条件')
      return
    }
    setSaving(true)
    setFormError(null)
    try {
      await saveAlertRule({ ...draft, name: draft.name.trim(), processes },
        editingId === 'new' ? undefined : editingId ?? undefined)
      cancelEdit()
      load()
    } catch (e) {
      setFormError(String(e))
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (rule: AlertRule) => {
    if (!window.confirm(`删除规则「${rule.name}」？`)) return
    try {
      await deleteAlertRule(rule.id)
      load()
    } catch (e) {
      setFormError(String(e))
    }
  }

  const handleToggle = async (rule: AlertRule, enabled: boolean) => {
    try {
      await saveAlertRule(
        {
          name: rule.name,
          processes: rule.processes,
          enabled,
          match: rule.match,
          conditions: rule.conditions,
          cooldown_minutes: rule.cooldown_minutes,
        },
        rule.id,
      )
      load()
    } catch (e) {
      setFormError(String(e))
    }
  }

  const handleTest = async (rule: AlertRule) => {
    try {
      await testAlertRule(rule.id)
    } catch (e) {
      setFormError(String(e))
    }
  }

  const handleCheck = async () => {
    try {
      const r = await checkAlertRules()
      load()
      if (r.alerted > 0) window.alert(`本轮 ${r.alerted} 条规则命中，已按通道告警`)
    } catch (e) {
      setFormError(String(e))
    }
  }

  const setCond = (i: number, patch: Partial<AlertCondition>) => {
    setDraft((d) => {
      const conds = d.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c))
      return { ...d, conditions: conds }
    })
  }

  const addCond = (type: AlertCondition['type']) => {
    setDraft((d) => ({
      ...d,
      conditions: [
        ...d.conditions,
        type === 'window_bytes'
          ? { type: 'window_bytes', window_minutes: 60, bytes: 1024 ** 3, direction: 'total' }
          : { type: 'sustained_minutes', minutes: 60 },
      ],
    }))
  }

  const removeCond = (i: number) => {
    setDraft((d) => ({ ...d, conditions: d.conditions.filter((_, j) => j !== i) }))
  }

  // 点选列表按名字去重（同进程多 pid 只留一条），最多显示 20 个
  const seen = new Set<string>()
  const procNames = procOptions
    .filter((p) => {
      const k = p.process.toLowerCase()
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
    .slice(0, 20)

  return (
    <div className="ar">
      <div className="ar__bar">
        <div className="ar__intro">
          <b>进程流量告警规则</b>
          <span className="ar__meta">
            服务端每 {Math.round(intervalSec / 60)} 分钟评估一轮，命中且过冷却即弹窗（Catrace
            小窗 / 置顶弹窗 / 桌面文件三通道）
          </span>
        </div>
        <div className="ar__actions">
          <button type="button" className="ar__btn" onClick={handleCheck}>
            立即检查一轮
          </button>
          <button type="button" className="ar__btn ar__btn--primary" onClick={startCreate}>
            + 新建规则
          </button>
        </div>
      </div>

      {!editingId ? (
        <div className="ar__templates">
          <span className="ar__templates-label">没头绪？一键起个模板：</span>
          {TEMPLATES.map((t) => (
            <button
              key={t.label}
              type="button"
              className="ar__btn ar__btn--sm"
              title={t.hint}
              onClick={() => startTemplate(t)}
            >
              {t.label}
            </button>
          ))}
        </div>
      ) : null}

      {loadError ? <div className="banner">加载失败：{loadError}</div> : null}
      {formError && !editingId ? <div className="banner">{formError}</div> : null}

      {editingId ? (
        <section className="ar__form">
          <h3>{editingId === 'new' ? '新建规则' : '编辑规则'}</h3>
          <label className="ar__field">
            规则名称
            <input
              type="text"
              value={draft.name}
              maxLength={60}
              placeholder="如：下载器持续传输超 1 小时"
              onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
            />
          </label>
          <label className="ar__field">
            进程名（可多个，逗号分隔；大小写不敏感，% 代表任意字符）
            <input
              type="text"
              value={processText}
              placeholder="如：某下载器.exe, %update%"
              onChange={(e) => setProcessText(e.target.value)}
            />
          </label>
          {procNames.length > 0 ? (
            <div className="ar__proc-pick">
              <span className="ar__proc-pick-label">或从最近有流量的进程里点选（近 24 小时）：</span>
              <span className="ar__proc-pick-list">
                {procNames.map((p) => (
                  <button
                    key={`${p.process}-${p.pid}`}
                    type="button"
                    className="ar__btn ar__btn--sm"
                    title={`近 24 小时 ${bytes(p.total_bytes)}`}
                    onClick={() => appendProcess(p.process)}
                  >
                    {p.process}
                  </button>
                ))}
              </span>
            </div>
          ) : null}
          <div className="ar__field-row">
            <label className="ar__field">
              命中方式
              <select
                value={draft.match}
                onChange={(e) => setDraft((d) => ({ ...d, match: e.target.value as 'any' | 'all' }))}
              >
                <option value="any">任一条件命中即告警</option>
                <option value="all">全部条件命中才告警</option>
              </select>
            </label>
            <label className="ar__field ar__field--num">
              冷却（分钟）
              <input
                type="number"
                min={0}
                max={1440}
                value={draft.cooldown_minutes}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, cooldown_minutes: Math.max(0, Number(e.target.value) || 0) }))
                }
              />
            </label>
            <label className="ar__field ar__field--check">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
              />
              启用
            </label>
          </div>

          <div className="ar__conds">
            <div className="ar__conds-head">
              <span>条件（可叠加）</span>
              <span className="ar__conds-add">
                <button type="button" className="ar__btn ar__btn--sm" onClick={() => addCond('window_bytes')}>
                  + 窗口流量
                </button>
                <button type="button" className="ar__btn ar__btn--sm" onClick={() => addCond('sustained_minutes')}>
                  + 持续时长
                </button>
              </span>
            </div>
            {draft.conditions.map((c, i) => (
              <div className="ar__cond-edit" key={i}>
                <select
                  value={c.type}
                  onChange={(e) => {
                    const t = e.target.value as AlertCondition['type']
                    setCond(i, t === 'window_bytes'
                      ? { type: t, window_minutes: 60, bytes: 1024 ** 3, direction: 'total', minutes: undefined }
                      : { type: t, minutes: 60, window_minutes: undefined, bytes: undefined, direction: undefined })
                  }}
                >
                  <option value="window_bytes">窗口累计流量</option>
                  <option value="sustained_minutes">持续传输时长</option>
                </select>
                {c.type === 'window_bytes' ? (
                  <>
                    <span>近</span>
                    <input
                      type="number" min={1} max={1440} className="ar__num"
                      value={c.window_minutes ?? 60}
                      onChange={(e) => setCond(i, { window_minutes: Math.max(1, Number(e.target.value) || 1) })}
                    />
                    <span>分钟</span>
                    <select
                      value={c.direction ?? 'total'}
                      onChange={(e) => setCond(i, { direction: e.target.value as AlertCondition['direction'] })}
                    >
                      <option value="out">上行</option>
                      <option value="in">下行</option>
                      <option value="total">总流量</option>
                    </select>
                    <span>≥</span>
                    <select
                      className="ar__num"
                      value={String(c.bytes ?? 1024 ** 3)}
                      onChange={(e) => setCond(i, { bytes: Number(e.target.value) })}
                    >
                      <option value={String(100 * 1024 * 1024)}>100 MB</option>
                      <option value={String(500 * 1024 * 1024)}>500 MB</option>
                      <option value={String(1024 ** 3)}>1 GB</option>
                      <option value={String(5 * 1024 ** 3)}>5 GB</option>
                      <option value={String(10 * 1024 ** 3)}>10 GB</option>
                    </select>
                  </>
                ) : (
                  <>
                    <span>连续传输 ≥</span>
                    <input
                      type="number" min={1} max={1440} className="ar__num"
                      value={c.minutes ?? 60}
                      onChange={(e) => setCond(i, { minutes: Math.max(1, Number(e.target.value) || 1) })}
                    />
                    <span>分钟（分钟桶缺列算断裂）</span>
                  </>
                )}
                <button
                  type="button" className="ar__btn ar__btn--sm ar__btn--danger"
                  onClick={() => removeCond(i)}
                  disabled={draft.conditions.length <= 1}
                >
                  移除
                </button>
              </div>
            ))}
          </div>

          {formError ? <div className="banner">{formError}</div> : null}
          <div className="ar__form-actions">
            <button type="button" className="ar__btn ar__btn--primary" onClick={handleSave} disabled={saving}>
              {saving ? '保存中…' : '保存'}
            </button>
            <button type="button" className="ar__btn" onClick={cancelEdit}>
              取消
            </button>
          </div>
        </section>
      ) : null}

      <section className="ar__list">
        {rules.length === 0 && !loadError ? (
          <div className="ar__empty">还没有规则——点「+ 新建规则」添加（默认规则应在首次启动时自动种入）</div>
        ) : null}
        {rules.map((rule) => {
          const st = rule.status
          return (
            <article key={rule.id} className={`ar__card${rule.enabled ? '' : ' ar__card--off'}`}>
              <header className="ar__card-head">
                <label className="ar__switch">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={(e) => handleToggle(rule, e.target.checked)}
                  />
                </label>
                <b className="ar__card-name">{rule.name}</b>
                <span className={`ar__badge ar__badge--${rule.match}`}>
                  {rule.match === 'any' ? '任一命中' : '全部命中'}
                </span>
                {st.error ? <span className="ar__badge ar__badge--err">{st.error}</span> : null}
                <span className="ar__card-actions">
                  <button type="button" className="ar__btn ar__btn--sm" onClick={() => handleTest(rule)}>
                    测试告警
                  </button>
                  <button type="button" className="ar__btn ar__btn--sm" onClick={() => startEdit(rule)}>
                    编辑
                  </button>
                  <button
                    type="button"
                    className="ar__btn ar__btn--sm ar__btn--danger"
                    onClick={() => handleDelete(rule)}
                  >
                    删除
                  </button>
                </span>
              </header>
              <div className="ar__procs">
                {(rule.processes ?? []).map((p) => (
                  <code className="ar__proc" key={p}>{p}</code>
                ))}
              </div>
              <ul className="ar__cond-list">
                {(rule.conditions ?? []).map((c, i) => (
                  <ConditionRow key={i} c={c} s={st} />
                ))}
              </ul>
              <footer className="ar__card-foot">
                <span>
                  冷却 {rule.cooldown_minutes} 分钟
                  {st.cooling ? `（还剩 ${st.cooldown_left_min} 分钟）` : ''}
                </span>
                <span>上次告警：{fmtTs(st.last_alert_ts)}</span>
                {rule.note ? <span className="ar__note">{rule.note}</span> : null}
              </footer>
            </article>
          )
        })}
      </section>

      <footer className="ar__foot">
        规则文件：<code>{path}</code>
        {' · '}
        持续时长按分钟桶判定——采集断过的分钟算断裂，不会把断线时段并成「一直在传」
      </footer>
    </div>
  )
}
