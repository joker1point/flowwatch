import { useEffect, useState } from 'react'
import {
  deleteAiNote,
  deletePersona,
  fetchAiNotes,
  fetchPersonas,
  fetchUserNotes,
  generateAiNote,
  savePersona,
  saveUserNotes,
} from '../api'
import type { AiNote, Persona } from '../api'

/**
 * 笔记区（「笔记」页）：
 * - 用户笔记：本机代理 / 流量专属指南，自由编辑，点「保存到磁盘」写入 notes/user_notes.md
 * - AI 笔记：读取真实流量统计生成每日笔记；人设内置 3 个、可编辑可自建
 */
export function NotesPanel() {
  // ---- 用户笔记 ----
  const [content, setContent] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<string | null>(null)
  const [noteError, setNoteError] = useState<string | null>(null)

  // ---- AI 笔记 ----
  const [personas, setPersonas] = useState<Persona[]>([])
  const [personaId, setPersonaId] = useState('analyst')
  const [notes, setNotes] = useState<AiNote[]>([])
  const [generating, setGenerating] = useState(false)
  const [genError, setGenError] = useState<string | null>(null)

  // ---- 人设编辑 ----
  const [editing, setEditing] = useState(false)
  const [editingIsNew, setEditingIsNew] = useState(false)
  const [editName, setEditName] = useState('')
  const [editPrompt, setEditPrompt] = useState('')

  useEffect(() => {
    let alive = true
    fetchUserNotes()
      .then((v) => {
        if (alive) {
          setContent(v.content)
          setLoaded(true)
        }
      })
      .catch(() => setLoaded(true))
    fetchPersonas()
      .then((v) => {
        if (alive && v.items.length > 0) {
          setPersonas(v.items)
          setPersonaId(v.items[0].id)
        }
      })
      .catch(() => undefined)
    fetchAiNotes()
      .then((v) => {
        if (alive) setNotes(v.items)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])

  const currentPersona = personas.find((p) => p.id === personaId)

  const handleSaveNotes = async () => {
    setSaving(true)
    setNoteError(null)
    try {
      await saveUserNotes(content)
      setSavedAt(new Date().toLocaleTimeString())
    } catch (e) {
      setNoteError(String(e))
    } finally {
      setSaving(false)
    }
  }

  const handleGenerate = async () => {
    setGenerating(true)
    setGenError(null)
    try {
      await generateAiNote(personaId)
      const v = await fetchAiNotes()
      setNotes(v.items)
    } catch (e) {
      setGenError(String(e))
    } finally {
      setGenerating(false)
    }
  }

  const openEditCurrent = () => {
    if (!currentPersona) return
    setEditingIsNew(false)
    setEditName(currentPersona.name)
    setEditPrompt(currentPersona.prompt)
    setEditing(true)
  }

  const openCreateNew = () => {
    setEditingIsNew(true)
    setEditName('')
    setEditPrompt('')
    setEditing(true)
  }

  const handlePersonaSave = async () => {
    try {
      const payload =
        editingIsNew || !currentPersona
          ? { name: editName, prompt: editPrompt }
          : { id: currentPersona.id, name: editName, prompt: editPrompt }
      const item = await savePersona(payload)
      const v = await fetchPersonas()
      setPersonas(v.items)
      setPersonaId(item.id)
      setEditing(false)
    } catch (e) {
      setGenError(String(e))
    }
  }

  const handleDeletePersona = async () => {
    if (!currentPersona || currentPersona.builtin) return
    try {
      await deletePersona(currentPersona.id)
      const v = await fetchPersonas()
      setPersonas(v.items)
      if (v.items.length > 0) setPersonaId(v.items[0].id)
    } catch (e) {
      setGenError(String(e))
    }
  }

  const handleDeleteNote = async (day: string) => {
    try {
      await deleteAiNote(day)
      const v = await fetchAiNotes()
      setNotes(v.items)
    } catch (e) {
      setGenError(String(e))
    }
  }

  return (
    <div className="notes">
      <section className="panel">
        <div className="panel__head">
          <h2 className="notes__title">本机代理 / 流量专属指南（用户笔记）</h2>
          <span className="panel__hint">
            {savedAt ? `已保存 ${savedAt}` : '编辑后点「保存到磁盘」写入 notes/user_notes.md'}
          </span>
        </div>
        <textarea
          className="notes__editor"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={14}
          spellCheck={false}
          placeholder="记录你的代理端口约定、故障处理步骤、常见坑…（例如：终端代理用 proxyon，别用 setx）"
        />
        <div className="notes__actions">
          <button type="button" className="notes__btn" onClick={handleSaveNotes} disabled={saving || !loaded}>
            {saving ? '保存中…' : '保存到磁盘'}
          </button>
          {noteError ? <span className="notes__error">{noteError}</span> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel__head">
          <h2 className="notes__title">AI 每日流量笔记</h2>
          <span className="panel__hint">AI 读取真实流量统计生成；人设可编辑、可自建</span>
        </div>

        <div className="notes__toolbar">
          <select
            className="notes__select"
            value={personaId}
            onChange={(e) => setPersonaId(e.target.value)}
            aria-label="选择人设"
          >
            {personas.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.builtin ? '（内置）' : ''}
              </option>
            ))}
          </select>
          <button type="button" className="notes__btn" onClick={handleGenerate} disabled={generating}>
            {generating ? '生成中…' : '生成今天的笔记'}
          </button>
          <button type="button" className="notes__btn notes__btn--ghost" onClick={openEditCurrent}>
            编辑人设
          </button>
          <button type="button" className="notes__btn notes__btn--ghost" onClick={openCreateNew}>
            新建人设
          </button>
          {currentPersona && !currentPersona.builtin ? (
            <button type="button" className="notes__btn notes__btn--ghost" onClick={handleDeletePersona}>
              删除人设
            </button>
          ) : null}
        </div>

        {editing ? (
          <div className="notes__editbox">
            <input
              className="notes__input"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              placeholder="人设名字（如：深夜福尔摩斯）"
              maxLength={40}
            />
            <textarea
              className="notes__editor notes__editor--sm"
              value={editPrompt}
              onChange={(e) => setEditPrompt(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder="人设提示词：定义它的语气、关注点、输出格式…"
            />
            <div className="notes__actions">
              <button
                type="button"
                className="notes__btn"
                onClick={handlePersonaSave}
                disabled={!editName.trim() || !editPrompt.trim()}
              >
                {editingIsNew ? '创建' : '保存修改'}
              </button>
              <button type="button" className="notes__btn notes__btn--ghost" onClick={() => setEditing(false)}>
                取消
              </button>
            </div>
          </div>
        ) : null}

        {genError ? <p className="notes__error">{genError}</p> : null}

        <div className="notes__list">
          {notes.length === 0 ? (
            <p className="dim">还没有 AI 笔记——选个人设，点「生成今天的笔记」试试。</p>
          ) : null}
          {notes.map((n) => (
            <article className="notes__card" key={n.date}>
              <header className="notes__cardhead">
                <span className="mono">{n.date}</span>
                <span className="notes__badge">{n.persona_name}</span>
                <button
                  type="button"
                  className="notes__del"
                  onClick={() => handleDeleteNote(n.date)}
                  aria-label={`删除 ${n.date} 的笔记`}
                >
                  ×
                </button>
              </header>
              <pre className="notes__body">{n.content}</pre>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}
