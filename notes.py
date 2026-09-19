#!/usr/bin/env python3
"""flowwatch 笔记区：用户笔记（手写落盘）+ AI 每日流量笔记（可配人设）。

设计对齐 assistant.py 的既有约定：
- LLM 配置复用 `assistant.load_config()`（FLOWWATCH_ASSISTANT_* 环境变量）
- 调用复用 `assistant.chat_completion()`；代理策略随其 `_opener()`（**默认直连**）
- mock provider / 未配置时也能生成（内容来自真实流量数据，明确标注）

存储（notes/ 目录，纯文本可备份）：
    notes/user_notes.md   用户"本机代理/流量专属指南"（点保存写盘）
    notes/personas.json   人设（3 个内置 + 自定义）
    notes/ai_notes.json   每日 AI 笔记（按日期键，同日重生成=覆盖）

数据口径：v1 的"当日" = 最近 24 小时（history 桶聚合，Top100 进程求和近似总量）。
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import date as _date
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import assistant

NOTES_DIR = Path(__file__).with_name("notes")
USER_NOTES = NOTES_DIR / "user_notes.md"
PERSONAS = NOTES_DIR / "personas.json"
AI_NOTES = NOTES_DIR / "ai_notes.json"

router = APIRouter()
_store: Any = None

BUILTIN_PERSONAS = [
    {
        "id": "analyst",
        "name": "严谨分析员",
        "prompt": (
            "你是本机流量的严谨分析员。基于给定的真实统计数据写今日流量笔记："
            "先给一句话总览（总上行/下行），再按「最活跃进程 Top3」「访问最多的域名 Top3」"
            "逐条分析，指出任何异常（异常高的上传、深夜流量、显著变化）。"
            "只引用给定数据，不编造。语气克制专业，用简洁短段落。"
        ),
        "builtin": True,
    },
    {
        "id": "roaster",
        "name": "毒舌吐槽役",
        "prompt": (
            "你是本机流量的毒舌吐槽役。基于真实统计数据写今日流量笔记："
            "用幽默犀利的口吻吐槽流量里的离谱之处（谁在偷偷跑量、哪个网站最费流量），"
            "但所有数字必须来自给定数据，不许瞎编。狂而不妄，槽点都落在数据上。"
        ),
        "builtin": True,
    },
    {
        "id": "butler",
        "name": "养生管家",
        "prompt": (
            "你是用户的作息与流量养生管家。基于真实统计数据写今日流量笔记："
            "语气温和关怀，先肯定今天用得不错的地方，再温和提醒需要注意的"
            "（深夜还在跑的进程、长时间大流量等），最后给一条具体可执行的小建议。"
            "只基于给定的真实数据。"
        ),
        "builtin": True,
    },
]


def configure(store: Any = None) -> None:
    """server.py 启动时注入只读历史库；并确保 notes/ 目录与初始文件存在。"""
    global _store
    if store is not None:
        _store = store
    NOTES_DIR.mkdir(exist_ok=True)
    if not USER_NOTES.exists():
        USER_NOTES.write_text(
            "# 本机代理 / 流量专属指南\n\n"
            "（在这里记录你的代理配置、端口约定、常见故障处理方式……"
            "点「保存到磁盘」写入文件）\n",
            encoding="utf-8",
        )
    if not PERSONAS.exists():
        _write_json(PERSONAS, BUILTIN_PERSONAS)
    if not AI_NOTES.exists():
        _write_json(AI_NOTES, {})


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- 用户笔记
@router.get("/api/notes/user")
def get_user_notes() -> dict[str, Any]:
    return {
        "content": USER_NOTES.read_text(encoding="utf-8") if USER_NOTES.exists() else "",
        "path": str(USER_NOTES),
    }


class UserNotesIn(BaseModel):
    content: str = Field(default="", max_length=200_000)


@router.post("/api/notes/user")
def save_user_notes(payload: UserNotesIn) -> dict[str, Any]:
    USER_NOTES.write_text(payload.content, encoding="utf-8")
    return {"ok": True, "bytes": len(payload.content.encode("utf-8")), "saved_at": time.time()}


# ---------------------------------------------------------------- 人设
class PersonaIn(BaseModel):
    id: Optional[str] = None
    name: str = Field(min_length=1, max_length=40)
    prompt: str = Field(min_length=1, max_length=4000)


@router.get("/api/notes/personas")
def list_personas() -> dict[str, Any]:
    return {"items": _read_json(PERSONAS, BUILTIN_PERSONAS)}


@router.post("/api/notes/personas")
def upsert_persona(payload: PersonaIn) -> dict[str, Any]:
    items = _read_json(PERSONAS, BUILTIN_PERSONAS)
    target = None
    if payload.id:
        target = next((p for p in items if p.get("id") == payload.id), None)
    if target is None:
        target = {"id": "c" + secrets.token_hex(4), "builtin": False}
        items.append(target)
    target["name"] = payload.name
    target["prompt"] = payload.prompt
    target.setdefault("builtin", False)
    _write_json(PERSONAS, items)
    return {"ok": True, "item": target}


@router.delete("/api/notes/personas/{persona_id}")
def delete_persona(persona_id: str) -> dict[str, Any]:
    items = _read_json(PERSONAS, BUILTIN_PERSONAS)
    target = next((p for p in items if p.get("id") == persona_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="人设不存在")
    if target.get("builtin"):
        raise HTTPException(status_code=400, detail="内置人设不可删除（可编辑）")
    _write_json(PERSONAS, [p for p in items if p.get("id") != persona_id])
    return {"ok": True}


# ---------------------------------------------------------------- AI 每日笔记
def _collect_day_data() -> dict[str, Any]:
    """聚合近 24h 数据（只读，纯聚合口径，不含对端 IP）。"""
    if _store is None:
        raise HTTPException(status_code=503, detail="历史库未就绪")
    procs = _store.top_processes(minutes=1440, limit=100)
    doms = _store.top_domains(minutes=1440, limit=10, named_only=False)
    events = _store.events(limit=50)
    total_out = sum(p.get("out_bytes", 0) for p in procs)
    total_in = sum(p.get("in_bytes", 0) for p in procs)
    return {"procs": procs, "doms": doms, "events": events,
            "total_out": total_out, "total_in": total_in}


def _summarize_for_prompt(data: dict[str, Any]) -> str:
    lines = [
        "【本机流量统计（近 24 小时，聚合口径；总量 = Top100 进程求和近似）】",
        f"总上行 {data['total_out'] / 1e9:.2f} GB / 总下行 {data['total_in'] / 1e9:.2f} GB",
        "— 进程 Top：",
    ]
    for p in data["procs"][:8]:
        lines.append(
            f"  · {p.get('process')}：上行 {p.get('out_bytes', 0) / 1e9:.2f} GB / "
            f"下行 {p.get('in_bytes', 0) / 1e9:.2f} GB"
        )
    lines.append("— 域名 Top：")
    for d in data["doms"][:8]:
        label = d.get("name") or "(未知)"
        kind = "" if d.get("kind") == "domain" else f"[{d.get('kind')}]"
        lines.append(
            f"  · {kind}{label}：上行 {d.get('out_bytes', 0) / 1e6:.1f} MB / "
            f"下行 {d.get('in_bytes', 0) / 1e6:.1f} MB / 连接 {d.get('conns', 0)}"
        )
    ev = data.get("events") or []
    if ev:
        lines.append(f"— 变化事件 {len(ev)} 条（最近 5 条）：")
        for e in ev[:5]:
            lines.append(f"  · [{e.get('kind')}] {e.get('process') or ''} {e.get('detail') or ''}")
    return "\n".join(lines)


def _llm_generate(config, persona_prompt: str, digest: str, day: str) -> str:
    messages = [
        {"role": "system", "content": persona_prompt},
        {"role": "user", "content": f"日期：{day}\n\n{digest}\n\n请写今日流量笔记（150-300 字）。"},
    ]
    result = assistant.chat_completion(config, messages, tools=[])
    return (result.get("content") or "").strip() or "（模型返回为空）"


class GenerateIn(BaseModel):
    date: Optional[str] = None
    persona_id: str = "analyst"


@router.post("/api/notes/ai/generate")
async def generate_ai_note(payload: GenerateIn) -> dict[str, Any]:
    day = payload.date or _date.today().isoformat()
    personas = _read_json(PERSONAS, BUILTIN_PERSONAS)
    persona = next((p for p in personas if p.get("id") == payload.persona_id), None)
    if persona is None:
        raise HTTPException(status_code=404, detail="人设不存在")

    data = await asyncio.to_thread(_collect_day_data)      # 同步 DB → 线程池
    digest = _summarize_for_prompt(data)

    config = assistant.load_config()
    if not config.configured or config.name == "mock":
        content = f"（mock：未配置真实模型，以下为真实数据直读）\n\n{digest}"
    else:
        content = await asyncio.to_thread(_llm_generate, config, persona["prompt"], digest, day)

    notes = _read_json(AI_NOTES, {})
    notes[day] = {
        "date": day,
        "persona_id": persona["id"],
        "persona_name": persona["name"],
        "content": content,
        "generated_at": time.time(),
    }
    _write_json(AI_NOTES, notes)
    return {"ok": True, **notes[day]}


@router.get("/api/notes/ai")
def list_ai_notes() -> dict[str, Any]:
    notes = _read_json(AI_NOTES, {})
    items = sorted(notes.values(), key=lambda x: str(x.get("date", "")), reverse=True)
    return {"items": items[:60]}


@router.delete("/api/notes/ai/{day}")
def delete_ai_note(day: str) -> dict[str, Any]:
    notes = _read_json(AI_NOTES, {})
    if day not in notes:
        raise HTTPException(status_code=404, detail="该日笔记不存在")
    del notes[day]
    _write_json(AI_NOTES, notes)
    return {"ok": True}
