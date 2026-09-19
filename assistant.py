#!/usr/bin/env python3
"""flowwatch 流量助手：带工具调用与分层记忆的**只读** Agent。

## 设计来源（这套结构不是自己拍的，每处都对齐一份成熟实现）

1. **记忆分层 ← Letta / MemGPT 的 Context Hierarchy**（`letta-ai/letta`，MemGPT 论文）
   - 三层职责不同：**热状态**（每轮注入的 block）、**会话证据日志**（原始消息，可检索，
     压缩时不做删除性销毁）、**长期事实**（Letta 用 archival 按需检索；这里用 `findings`
     block 代替 —— 流量助手要记的结论量小，block 足够，不为"分层而分层"）。
   - Prompt 拼装对齐它的 **Memory Block Prompt ABI**：`label / description / value /
     limit / read_only`，并把 `chars_current` 与 `chars_limit` 一起渲染给模型 ——
     让模型对"预算快满了"有感知，从而主动整理而不是盲目追加。
   - 变更原语沿用三种粒度：`memory_replace`（精确小改）/ `memory_insert`（追加）/
     `memory_rethink`（整块重写）。一个"写记忆"通吃会让模型分不清意图。
   - **对抗 Summary Drift**：消息压缩只做标记、不删原文，并留 `conversation_search`
     让模型能回到证据核对 —— 这是 Letta 把「策展记忆」与「会话证据」分开的原因。

2. **工具契约 ← Pydantic AI 的核心主张**：类型即契约 —— schema 从 Pydantic 模型生成、
   description 从 docstring 取、**校验失败作为观察结果回给模型**而不是抛异常。
   项目本来就有 pydantic（FastAPI 依赖），零新增依赖。

3. **会话与循环 ← OpenAI Agents SDK**：Session 抽象（消息持久化 + 自动拼装输入）、
   `max_turns` 上限、工具异常不中断回合、工具执行过程作为可观测步骤流。

## 为什么不直接引入框架
flowwatch 的依赖只有 psutil / fastapi / uvicorn —— 抓包层是用 ctypes 直调 wpcap 写的。
引入 LangGraph / pydantic-ai / letta 会拖进 httpx 等一整棵依赖树，对本机小工具不划算。
所以这里是**借鉴设计、不抄代码**：这符合 dev-lessons 的「复用不复制」原则。

## 隐私分级
C 档（aggregate，默认）**不注入**明细工具 —— 对端 IP 物理上进不了模型上下文，
而不是靠提示词叮嘱"别查 IP"。D 档（detail）由问题意图路由。

配置（环境变量，全部可选）：
    FLOWWATCH_ASSISTANT_PROVIDER   openai | ollama | mock（空 = 未配置）
    FLOWWATCH_ASSISTANT_BASE_URL   远端兼容 API 的 .../v1
    FLOWWATCH_ASSISTANT_API_KEY    远端 key
    FLOWWATCH_ASSISTANT_MODEL      模型名
    FLOWWATCH_ASSISTANT_OLLAMA_URL 默认 http://127.0.0.1:11434/v1
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ValidationError

SCHEMA = "flowwatch-assistant/v1"
MEMORY_PATH = Path(__file__).with_name("assistant_memory.db")

MAX_TURNS = 6                # 一轮提问最多几次模型往返（含工具轮）
RECENT_MESSAGES = 10         # 注入上下文的最近消息条数
COMPACT_THRESHOLD = 28       # 超过这么多条就把更早的标记为已压缩（**不删除**）
HTTP_TIMEOUT = 90.0

# ---------------------------------------------------------------- 数据分级

# 命中这些意图才升到 D 档（含对端 IP:端口）。刻意保守：宁可少给一次明细，
# 也不默认把 IP 往外发（"物理隔离"的判定侧）。
DETAIL_PATTERNS = (
    "对端", "连了谁", "连接到哪", "连哪", "哪个ip", "哪个 ip", "什么ip", "什么 ip",
    "明细", "端口", "remote", "ip:", "地址", "具体连", "连接列表",
)


def route_scope(question: str) -> str:
    """按问题意图选数据档位：aggregate（默认，只聚合）/ detail（含对端明细）。"""
    text = (question or "").lower()
    return "detail" if any(p in text for p in DETAIL_PATTERNS) else "aggregate"


# ---------------------------------------------------------------- 数据源注入

class _Source:
    """server.py 在启动时注入的只读数据入口（避免循环 import）。"""

    hub: Any = None
    store: Any = None
    capturer: Any = None
    session_id: str = "default"     # 由请求设置，供记忆类工具定位会话


def configure(hub: Any = None, store: Any = None, capturer: Any = None,
              memory_path: Path | None = None) -> None:
    if hub is not None:
        _Source.hub = hub
    if store is not None:
        _Source.store = store
    if capturer is not None:
        _Source.capturer = capturer
    if memory_path is not None:
        global MEMORY
        MEMORY = Memory(memory_path)


# ---------------------------------------------------------------- 记忆层
# 结构对齐 Letta 的 BaseBlock：label（寻址）/ description（写入路由策略）/ value /
# limit（Prompt 预算契约）/ read_only（能力边界）。策略留在代码里，内容落在库里。

@dataclass(frozen=True)
class BlockSpec:
    label: str
    description: str
    limit: int
    read_only: bool = False


DEFAULT_BLOCKS: tuple[BlockSpec, ...] = (
    BlockSpec("human", "这台机器的使用者：他关心什么、常问什么、偏好怎样的回答方式", 1200),
    BlockSpec("watchlist", "需要持续盯住的进程 / 域名，以及为什么要盯它", 1200),
    BlockSpec("findings", "已经核实过的结论（写清日期与依据），避免重复推导", 2000),
)

_BLOCK_BY_LABEL = {spec.label: spec for spec in DEFAULT_BLOCKS}


@dataclass
class MemoryState:
    blocks: list[dict[str, Any]] = field(default_factory=list)
    messages: int = 0
    compacted: int = 0


class Memory:
    """分层记忆：热状态 blocks + 会话证据 messages。

    - blocks 是 **agent 级**（不按 session 切）—— 长期状态要跨会话延续；
    - messages 是**会话级证据日志**：压缩只打标记、不删原文，
      并留 `conversation_search` 给模型回溯核对（对抗摘要漂移）。
    每次操作单独开连接（对话频率低，换线程安全与实现简单），WAL 与其它读不互斥。
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._ensure()

    # ---- 存储
    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """一次操作一个连接，用完**显式关闭**。

        踩过的坑：sqlite3 的 `with conn` 只管事务（commit/rollback），**不管关闭** ——
        直接 `with self._connect() as conn` 会把连接一直留着，Windows 上库文件被锁住
        （连临时目录都删不掉），长跑进程还会持续积累句柄。
        """
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS blocks (
                  label      TEXT PRIMARY KEY,
                  value      TEXT NOT NULL DEFAULT '',
                  updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                  id         TEXT PRIMARY KEY,
                  created_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL,
                  summary    TEXT NOT NULL DEFAULT '',
                  turns      INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS messages (
                  id         INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id TEXT NOT NULL,
                  role       TEXT NOT NULL,
                  content    TEXT NOT NULL,
                  scope      TEXT NOT NULL DEFAULT '',
                  tools      TEXT NOT NULL DEFAULT '',
                  ts         INTEGER NOT NULL,
                  compacted  INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_assistant_msg ON messages(session_id, id);
                """
            )
            # 幂等迁移：早期版本的 messages 没有 compacted 列（ALTER 失败即已存在）
            try:
                conn.execute("ALTER TABLE messages ADD COLUMN compacted INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass

    # ---- 热状态：blocks
    def blocks(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = dict(
                conn.execute("SELECT label, value FROM blocks").fetchall()
            )
        return [
            {
                "label": spec.label,
                "description": spec.description,
                "value": rows.get(spec.label, ""),
                "limit": spec.limit,
                "read_only": spec.read_only,
                "chars_current": len(rows.get(spec.label, "")),
            }
            for spec in DEFAULT_BLOCKS
        ]

    def block_value(self, label: str) -> str:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM blocks WHERE label=?", (label,)).fetchone()
        return row[0] if row else ""

    def block_write(self, label: str, value: str) -> dict[str, Any]:
        """整块写入。容量契约在这里执行：超限就拒绝并让模型自己精简。"""
        spec = _BLOCK_BY_LABEL.get(label)
        if spec is None:
            return {"error": f"没有这个块：{label}",
                    "available": [item.label for item in DEFAULT_BLOCKS]}
        if spec.read_only:
            return {"error": f"块 {label} 是只读的"}
        if len(value) > spec.limit:
            return {"error": f"超出容量：{len(value)}/{spec.limit} 字符。请先精简再写"
                             f"（宁可合并同类项，也别把原文堆进来）"}
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO blocks(label, value, updated_at) VALUES(?, ?, ?)
                   ON CONFLICT(label) DO UPDATE SET value=excluded.value,
                                                    updated_at=excluded.updated_at""",
                (label, value, int(time.time())),
            )
        return {"ok": True, "label": label, "chars_current": len(value), "chars_limit": spec.limit}

    def render_blocks(self) -> str:
        """Prompt ABI：把块编译成模型能稳定读写的结构（含容量元数据）。"""
        lines = ["<memory_blocks>"]
        for item in self.blocks():
            lines.append(f"<{item['label']}>")
            lines.append(f"<description>{item['description']}</description>")
            lines.append("<metadata>")
            lines.append(f"- chars_current={item['chars_current']}")
            lines.append(f"- chars_limit={item['limit']}")
            lines.append(f"- read_only={'true' if item['read_only'] else 'false'}")
            lines.append("</metadata>")
            lines.append(f"<value>{item['value'] or '(空)'}</value>")
            lines.append(f"</{item['label']}>")
        lines.append("</memory_blocks>")
        return "\n".join(lines)

    # ---- 会话证据：messages
    def history(self, session_id: str, limit: int = RECENT_MESSAGES) -> list[dict[str, str]]:
        """**活跃**上下文：只取未压缩的消息。已压缩的仍留在库里，走 conversation_search。"""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT role, content FROM messages
                   WHERE session_id=? AND compacted=0 ORDER BY id DESC LIMIT ?""",
                (session_id, limit),
            ).fetchall()
        return [{"role": role, "content": content} for role, content in reversed(rows)]

    def summary(self, session_id: str) -> str:
        with self._conn() as conn:
            row = conn.execute("SELECT summary FROM sessions WHERE id=?", (session_id,)).fetchone()
        return row[0] if row else ""

    def append(self, session_id: str, role: str, content: str, scope: str = "",
               tools: tuple[str, ...] = ()) -> None:
        now = int(time.time())
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO sessions(id, created_at, updated_at, summary, turns)
                   VALUES(?, ?, ?, '', 0)
                   ON CONFLICT(id) DO UPDATE SET
                     updated_at=excluded.updated_at,
                     turns=turns + CASE WHEN ?='user' THEN 1 ELSE 0 END""",
                (session_id, now, now, role),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, scope, tools, ts) VALUES(?,?,?,?,?,?)",
                (session_id, role, content, scope, json.dumps(list(tools), ensure_ascii=False), now),
            )

    def conversation_search(self, session_id: str, query: str, limit: int = 5) -> list[dict[str, Any]]:
        """按关键词回溯会话证据（零依赖的召回，语义检索留给将来）。"""
        keyword = f"%{(query or '').strip()[:40]}%"
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT role, content, ts, compacted FROM messages
                   WHERE session_id=? AND content LIKE ?
                   ORDER BY id DESC LIMIT ?""",
                (session_id, keyword, max(1, min(20, limit))),
            ).fetchall()
        return [
            {"role": role, "content": content[:600], "ts": ts, "compacted": bool(compacted)}
            for role, content, ts, compacted in rows
        ]

    def compact(self, session_id: str) -> bool:
        """压缩：把超出保留窗的消息**标记**为已压缩并生成摘要 —— 原文留着做证据。

        Letta 把「策展记忆」与「会话证据」分开，正是因为摘要漂移后要能回到原文核对；
        所以这里绝不 DELETE。
        """
        with self._conn() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE session_id=? AND compacted=0", (session_id,)
            ).fetchone()[0]
            if active <= COMPACT_THRESHOLD:
                return False
            rows = conn.execute(
                """SELECT id, role, content FROM messages
                   WHERE session_id=? AND compacted=0 ORDER BY id LIMIT ?""",
                (session_id, active - RECENT_MESSAGES),
            ).fetchall()
            if not rows:
                return False
            parts: list[str] = []
            for _, role, content in rows:
                text = " ".join((content or "").split())
                parts.append(("问:" if role == "user" else "答:") + text[:70])
            old = conn.execute("SELECT summary FROM sessions WHERE id=?", (session_id,)).fetchone()
            merged = ((old[0] + "；") if old and old[0] else "") + "；".join(parts)
            conn.execute("UPDATE sessions SET summary=? WHERE id=?", (merged[-2400:], session_id))
            conn.execute(
                "UPDATE messages SET compacted=1 WHERE id IN (%s)" % ",".join("?" * len(rows)),
                [row[0] for row in rows],
            )
        return True

    def reset(self, session_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
            conn.execute(
                "UPDATE sessions SET summary='', turns=0, updated_at=? WHERE id=?",
                (int(time.time()), session_id),
            )

    def forget_blocks(self) -> None:
        """清空长期记忆（blocks）—— 面板上的"忘掉我"按钮。"""
        with self._conn() as conn:
            conn.execute("DELETE FROM blocks")

    def state(self) -> dict[str, Any]:
        with self._conn() as conn:
            messages = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            compacted = conn.execute("SELECT COUNT(*) FROM messages WHERE compacted=1").fetchone()[0]
            sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        return {
            "path": str(self.path),
            "sessions": sessions,
            "messages": messages,
            "compacted": compacted,
            "blocks": self.blocks(),
        }


MEMORY = Memory(MEMORY_PATH)


# ---------------------------------------------------------------- 工具契约
# Pydantic 模型即契约：schema 由类型生成、description 取自 docstring、
# 校验失败作为观察结果回给模型（Pydantic AI 的做法）。

class GetHealthArgs(BaseModel):
    """采集层健康状态：设备、抓包错误、未归因比例、看门狗重开次数、历史库自述。"""


class GetLiveFrameArgs(BaseModel):
    """当前 1 秒窗口的实时快照：总速率、Top 进程、Top 域名、未归因明细。"""

    top: int = Field(8, ge=1, le=20, description="返回前多少个进程/域名")


class GetTopProcessesArgs(BaseModel):
    """区间内按累计字节排行的进程（只统计 pid > 0，不含哨兵桶）。"""

    minutes: int = Field(60, ge=1, le=60 * 24 * 30, description="回看多少分钟，默认 60")
    limit: int = Field(10, ge=1, le=20, description="返回条数")


class GetTopDomainsArgs(BaseModel):
    """区间内的域名排行（含 kind=ip 的未识别来源）。"""

    minutes: int = Field(60, ge=1, le=60 * 24 * 30)
    limit: int = Field(10, ge=1, le=20)
    named_only: bool = Field(False, description="只看有域名的")


class GetProcessHistoryArgs(BaseModel):
    """某个进程的历史曲线骨架（首末观测、峰值、区间累计、头尾若干桶）。"""

    pid: int = Field(..., ge=1, description="进程 PID")
    minutes: int = Field(60, ge=1, le=60 * 24 * 30)
    bucket: int = Field(1, ge=1, le=60, description="重采样桶宽（分钟）")


class GetEventsArgs(BaseModel):
    """变化事件流（出现 / 消失 / 尖峰），由落库观测值派生。"""

    limit: int = Field(20, ge=1, le=50)
    pid: int | None = Field(None, description="只看某个进程")


class GetLiveConnectionsArgs(BaseModel):
    """某进程当前窗口的连接明细（对端 IP:端口 + 域名）。仅在明细档可用。"""

    pid: int = Field(..., ge=1)
    limit: int = Field(10, ge=1, le=20)


class MemoryInsertArgs(BaseModel):
    """往长期记忆块追加一段内容（不要用它重写整块 —— 那是 memory_rethink）。"""

    label: str = Field(..., description="块名：human / watchlist / findings")
    text: str = Field(..., description="要追加的内容（自包含的一句话）")


class MemoryReplaceArgs(BaseModel):
    """精确修改块里的一小段：old_text 必须在块内逐字出现且唯一。"""

    label: str = Field(..., description="块名：human / watchlist / findings")
    old_text: str = Field(..., description="要替换掉的原文片段")
    new_text: str = Field("", description="替换成什么；留空表示删除该片段")


class MemoryRethinkArgs(BaseModel):
    """整块重写：用于合并重复、删除过期、大规模重组（小改用 memory_replace）。"""

    label: str = Field(..., description="块名：human / watchlist / findings")
    text: str = Field(..., description="重写后的完整块内容")


class ConversationSearchArgs(BaseModel):
    """回溯历史对话原文（证据核对：摘要可能压缩失真时用它）。"""

    query: str = Field(..., description="关键词")
    limit: int = Field(5, ge=1, le=20)


def _strip_titles(node: Any) -> Any:
    """Pydantic 生成的 schema 带 title，塞给模型是噪声 —— 递归清掉。"""
    if isinstance(node, dict):
        return {key: _strip_titles(value) for key, value in node.items() if key != "title"}
    if isinstance(node, list):
        return [_strip_titles(item) for item in node]
    return node


def _json_schema(model: type[BaseModel]) -> dict[str, Any]:
    schema = _strip_titles(model.model_json_schema())
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    return schema


@dataclass
class Tool:
    name: str
    scope: str                       # aggregate | detail | memory
    args: type[BaseModel]
    run: Callable[[Any, str], dict]  # (args, session_id) -> dict
    effect: str = ""                 # 给前端展示的一句人话

    @property
    def description(self) -> str:
        return (self.args.__doc__ or "").strip()

    def spec(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": _json_schema(self.args),
            },
        }


# ---------------------------------------------------------------- 数据工具实现

def _clamp(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _tool_health(args: GetHealthArgs, _session: str) -> dict[str, Any]:
    capturer = _Source.capturer
    if capturer is None:
        return {"error": "采集层未就绪"}
    stats = capturer.aggregator.stats()
    return {
        "device": capturer.device_name,
        "capture_error": capturer.error,
        "refresh_error": capturer.refresh_error,
        "packets_total": stats.get("packets"),
        "watchdog": capturer.watchdog_stats() if hasattr(capturer, "watchdog_stats") else None,
        "names": capturer.resolver.stats(),
        "history": _Source.store.stats() if _Source.store is not None else None,
    }


def _tool_live_frame(args: GetLiveFrameArgs, _session: str) -> dict[str, Any]:
    hub = _Source.hub
    if hub is None or not hub.latest:
        return {"error": "还没有实时帧（采集刚启动或没有流量）"}
    frame = hub.latest
    window = max(1e-3, frame.get("window", 1))
    return {
        "ts": frame.get("ts"),
        "window_seconds": frame.get("window"),
        "totals": frame.get("totals"),
        "top_processes": [
            {
                "pid": row["pid"],
                "process": row["process"],
                "out_bps": round(row["out_bps"]),
                "in_bps": round(row["in_bps"]),
            }
            for row in frame.get("by_pid", [])[: args.top]
        ],
        "top_domains": [
            {
                "name": entry.get("name"),
                "kind": entry.get("kind"),
                "out_bps": round(entry.get("out_bytes", 0) / window),
                "in_bps": round(entry.get("in_bytes", 0) / window),
            }
            for entry in frame.get("domains", [])[: args.top]
        ],
        "unknown_flows": frame.get("unknown_flows", [])[:5],
    }


def _tool_top_processes(args: GetTopProcessesArgs, _session: str) -> dict[str, Any]:
    if _Source.store is None:
        return {"error": "历史层未就绪"}
    items = _Source.store.top_processes(minutes=args.minutes, limit=args.limit)
    return {"minutes": args.minutes, "items": items}


def _tool_top_domains(args: GetTopDomainsArgs, _session: str) -> dict[str, Any]:
    if _Source.store is None:
        return {"error": "历史层未就绪"}
    items = _Source.store.top_domains(
        minutes=args.minutes, limit=args.limit, named_only=args.named_only
    )
    return {"minutes": args.minutes, "items": items}


def _tool_process_history(args: GetProcessHistoryArgs, _session: str) -> dict[str, Any]:
    if _Source.store is None:
        return {"error": "历史层未就绪"}
    data = _Source.store.process_series(args.pid, minutes=args.minutes, bucket_minutes=args.bucket)
    if not data:
        return {"error": "历史层未就绪"}
    series = data.get("series", [])
    return {
        "pid": data.get("pid"),
        "process": data.get("process"),
        "bucket_seconds": data.get("bucket_seconds"),
        "total_bytes": data.get("total_bytes"),
        "peak_bps": data.get("peak_bps"),
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
        "buckets": len(series),
        # 只给骨架：几百个桶塞进上下文既贵又没用
        "series_head": series[:6],
        "series_tail": series[-6:],
    }


def _tool_events(args: GetEventsArgs, _session: str) -> dict[str, Any]:
    if _Source.store is None:
        return {"error": "历史层未就绪"}
    return {"items": _Source.store.events(limit=args.limit, pid=args.pid)}


def _tool_live_connections(args: GetLiveConnectionsArgs, _session: str) -> dict[str, Any]:
    hub = _Source.hub
    if hub is None or not hub.latest:
        return {"error": "还没有实时帧"}
    row = next(
        (item for item in hub.latest.get("by_pid", []) if item["pid"] == args.pid), None
    )
    if row is None:
        return {"error": f"当前窗口里没有 pid {args.pid}（它可能这秒没流量）"}
    return {
        "pid": args.pid,
        "process": row["process"],
        "connections": [
            {
                "remote": conn["remote"],
                "name": conn.get("name"),
                "name_source": conn.get("name_source"),
                "out_bps": round(conn["out_bps"]),
                "in_bps": round(conn["in_bps"]),
            }
            for conn in row.get("conns", [])[: args.limit]
        ],
    }


# ---------------------------------------------------------------- 记忆工具实现

def _tool_memory_insert(args: MemoryInsertArgs, session: str) -> dict[str, Any]:
    current = MEMORY.block_value(args.label)
    joined = (current + "\n" + args.text).strip() if current else args.text.strip()
    result = MEMORY.block_write(args.label, joined)
    if result.get("ok"):
        result["hint"] = "已追加。块快满时用 memory_rethink 合并同类项，别硬塞。"
    return result


def _tool_memory_replace(args: MemoryReplaceArgs, session: str) -> dict[str, Any]:
    current = MEMORY.block_value(args.label)
    if args.label not in _BLOCK_BY_LABEL:
        return {"error": f"没有这个块：{args.label}",
                "available": [spec.label for spec in DEFAULT_BLOCKS]}
    hits = current.count(args.old_text)
    if hits == 0:
        return {"error": "old_text 在块里找不到（必须逐字匹配，包括标点）"}
    if hits > 1:
        return {"error": f"old_text 出现 {hits} 次，不唯一 —— 多带些上下文再改"}
    return MEMORY.block_write(args.label, current.replace(args.old_text, args.new_text))


def _tool_memory_rethink(args: MemoryRethinkArgs, session: str) -> dict[str, Any]:
    return MEMORY.block_write(args.label, args.text.strip())


def _tool_conversation_search(args: ConversationSearchArgs, session: str) -> dict[str, Any]:
    items = MEMORY.conversation_search(session, args.query, args.limit)
    return {"query": args.query, "items": items,
            "note": "这是原始对话证据；compacted=true 表示它已不在活跃上下文里"}


# ---------------------------------------------------------------- 工具注册表

TOOLS: tuple[Tool, ...] = (
    Tool("get_health", "aggregate", GetHealthArgs, _tool_health,
         effect="读取采集健康状态"),
    Tool("get_live_frame", "aggregate", GetLiveFrameArgs, _tool_live_frame,
         effect="读取当前实时窗口"),
    Tool("get_top_processes", "aggregate", GetTopProcessesArgs, _tool_top_processes,
         effect="查询区间进程排行"),
    Tool("get_top_domains", "aggregate", GetTopDomainsArgs, _tool_top_domains,
         effect="查询区间域名排行"),
    Tool("get_process_history", "aggregate", GetProcessHistoryArgs, _tool_process_history,
         effect="查询某进程历史曲线"),
    Tool("get_events", "aggregate", GetEventsArgs, _tool_events,
         effect="读取变化事件流"),
    Tool("get_live_connections", "detail", GetLiveConnectionsArgs, _tool_live_connections,
         effect="读取连接明细（含对端）"),
    Tool("memory_insert", "memory", MemoryInsertArgs, _tool_memory_insert,
         effect="追加长期记忆"),
    Tool("memory_replace", "memory", MemoryReplaceArgs, _tool_memory_replace,
         effect="精确修改长期记忆"),
    Tool("memory_rethink", "memory", MemoryRethinkArgs, _tool_memory_rethink,
         effect="重写长期记忆块"),
    Tool("conversation_search", "memory", ConversationSearchArgs, _tool_conversation_search,
         effect="回溯对话证据"),
)

_TOOL_BY_NAME = {tool.name: tool for tool in TOOLS}


def tools_for(scope: str) -> list[dict[str, Any]]:
    """按档位给出工具清单 —— "物理隔离"就落在这个函数里。

    记忆类工具始终可用（它不碰数据暴露面）；明细工具只在 D 档出现。
    """
    allowed = [tool for tool in TOOLS if tool.scope in ("aggregate", "memory")]
    if scope == "detail":
        allowed += [tool for tool in TOOLS if tool.scope == "detail"]
    return [tool.spec() for tool in allowed]


def run_tool(name: str, raw_args: Any, session_id: str = "default") -> dict[str, Any]:
    """执行工具。参数校验失败**不抛异常**，而是把校验结果作为观察回给模型。"""
    tool = _TOOL_BY_NAME.get(name)
    if tool is None:
        return {"error": f"没有这个工具：{name}", "available": sorted(_TOOL_BY_NAME)}
    try:
        args = tool.args.model_validate(raw_args if isinstance(raw_args, dict) else {})
    except ValidationError as exc:
        return {
            "error": "参数不合法",
            "details": exc.errors(include_url=False)[:3],
            "hint": "按 schema 修正后重试",
        }
    try:
        return tool.run(args, session_id)
    except Exception as exc:  # noqa: BLE001 - 工具失败要让模型知道，而不是把整轮打挂
        return {"error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------- provider

@dataclass
class ProviderConfig:
    name: str          # openai | ollama | mock | none
    label: str
    base_url: str
    api_key: str
    model: str

    @property
    def configured(self) -> bool:
        return self.name != "none"


UNCONFIGURED = ProviderConfig(name="none", label="未配置", base_url="", api_key="", model="")


def load_config() -> ProviderConfig:
    name = (os.environ.get("FLOWWATCH_ASSISTANT_PROVIDER") or "").strip().lower()
    model = (os.environ.get("FLOWWATCH_ASSISTANT_MODEL") or "").strip()
    if name == "mock":
        return ProviderConfig("mock", "本地 mock（不联网，仍真跑工具）", "", "", model or "mock")
    if name == "openai":
        base = (os.environ.get("FLOWWATCH_ASSISTANT_BASE_URL") or "").strip().rstrip("/")
        key = (os.environ.get("FLOWWATCH_ASSISTANT_API_KEY") or "").strip()
        if not (base and key and model):
            return UNCONFIGURED
        return ProviderConfig("openai", f"远端 · {model}", base, key, model)
    if name == "ollama":
        base = (os.environ.get("FLOWWATCH_ASSISTANT_OLLAMA_URL")
                or "http://127.0.0.1:11434/v1").strip().rstrip("/")
        return ProviderConfig("ollama", f"本地 Ollama · {model or '未指定模型'}", base, "ollama",
                              model or "qwen2.5:7b")
    return UNCONFIGURED


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str],
               timeout: float = HTTP_TIMEOUT) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    # 本机代理常常没开：对本机地址强制直连；远端则尊重环境里的代理设置
    host = urllib.parse.urlparse(url).hostname
    if host in ("127.0.0.1", "localhost", "::1"):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    else:
        opener = urllib.request.build_opener()
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def chat_completion(config: ProviderConfig, messages: list[dict[str, Any]],
                    tools: list[dict[str, Any]]) -> dict[str, Any]:
    """调一次 chat/completions，返回 assistant message（content + tool_calls）。"""
    payload: dict[str, Any] = {"model": config.model, "messages": messages, "temperature": 0.2}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
    data = _post_json(f"{config.base_url}/chat/completions", payload, headers)
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"provider 没有返回 choices：{json.dumps(data)[:200]}")
    message = choices[0].get("message") or {}
    return {
        "content": message.get("content") or "",
        "tool_calls": message.get("tool_calls") or [],
    }


# ---------------------------------------------------------------- mock provider

def mock_turn(question: str, scope: str, tool_trace: list[dict[str, Any]],
              session_id: str = "default") -> dict[str, Any]:
    """无模型时也能验证链路：真的跑工具，再把事实读成一段话。

    它不是"假装有 AI"—— 输出明确标注 mock，且内容全部来自真实工具结果。
    """
    text = (question or "").strip()
    lower = text.lower()
    picked: list[tuple[str, dict[str, Any]]] = []
    if any(word in lower for word in ("域名", "网站", "domain", "访问")):
        picked.append(("get_top_domains", {"minutes": 60, "limit": 8}))
    if any(word in lower for word in ("排行", "最多", "第一", "top", "谁在", "哪些进程")):
        picked.append(("get_top_processes", {"minutes": 60, "limit": 8}))
    if any(word in lower for word in ("健康", "状态", "未归因", "丢包", "采集")):
        picked.append(("get_health", {}))
    if any(word in lower for word in ("事件", "变化", "尖峰", "出现", "消失")):
        picked.append(("get_events", {"limit": 10}))
    if not picked:
        picked.append(("get_live_frame", {"top": 6}))

    lines = ["【mock 模式】未配置真实模型，以下结论由本地规则直接读取监控数据得出："]
    for name, args in picked:
        result = run_tool(name, args, session_id)
        tool_trace.append({"name": name, "args": args, "result": result})
        if name == "get_top_processes":
            for item in result.get("items", [])[:5]:
                lines.append(
                    f"· {item['process']}（#{item['pid']}）近 60 分钟 "
                    f"{item['total_bytes']/1048576:.1f} MiB（出 {item['out_bytes']/1048576:.1f} / "
                    f"入 {item['in_bytes']/1048576:.1f}）"
                )
        elif name == "get_top_domains":
            for item in result.get("items", [])[:5]:
                lines.append(f"· 域名 {item.get('name')}（{item.get('kind')}）"
                             f"{item.get('total_bytes', 0)/1048576:.1f} MiB，{item.get('conns')} 连接")
        elif name == "get_live_frame":
            totals = result.get("totals") or {}
            lines.append(f"· 当前出 {totals.get('out_bps', 0)/1024:.0f} KiB/s、"
                         f"入 {totals.get('in_bps', 0)/1024:.0f} KiB/s、"
                         f"未归因滚动 {(totals.get('unknown_ratio_rolling') or 0)*100:.1f}%")
            for row in result.get("top_processes", [])[:5]:
                lines.append(f"· {row['process']}（#{row['pid']}）"
                             f"出 {row['out_bps']/1024:.0f} / 入 {row['in_bps']/1024:.0f} KiB/s")
        elif name == "get_health":
            lines.append(f"· 设备 {result.get('device')}，抓包错误 {result.get('capture_error')}，"
                         f"看门狗 {result.get('watchdog')}")
        elif name == "get_events":
            for item in result.get("items", [])[:5]:
                lines.append(f"· {item.get('ts')} {item.get('kind')} {item.get('process')} "
                             f"{item.get('detail')}")
    lines.append("")
    lines.append("配置真实模型即可获得自然语言分析与追问能力："
                 "设 FLOWWATCH_ASSISTANT_PROVIDER=openai（或 ollama）并填 key/model。")
    return {"content": "\n".join(lines), "tool_calls": []}


# ---------------------------------------------------------------- Agent 主循环

SYSTEM_PROMPT = """你是 flowwatch 的流量分析助手。flowwatch 运行在这台 Windows 机器上，\
抓包统计**元数据**（进程 / 域名 / 对端 / 字节数），不保存包体。

工作方式：
- 答案必须来自工具返回的真实数据，**不要编造**数字；查不到就说查不到。
- 用户问"为什么/怎么回事"时，先查排行、历史、事件，再下结论。
- 字节用 MiB/GiB，速率用 KiB/s、MiB/s；时间用本地时间。
- 归因口径要说清：pid > 0 才是具体进程；"未归因"= 说不清是谁的，"属主受限"= 非提权
  拿不到 PID 的，两者都单独记账，不混进进程排行。
- 某进程流量异常大时，先考虑它是不是**中间人型代理**（本地加速器 / VPN / 代理会替别的
  程序转发，流量都挂在它名下）。
- 当前数据档位 {scope}：aggregate 只有聚合数据；detail 表示用户明确要明细，可用连接明细工具。

记忆（像人一样用它，不要每轮硬灌）：
- 三个记忆块是长期状态，会跨会话保留，**每轮都会注入**给你看：
  human（使用者偏好）/ watchlist（要盯住的对象）/ findings（已核实结论）。
- 值得长期留的才写：用户偏好、要持续盯的进程/域名、核实过的结论（写上日期）。
  一次性的查询结果不要写进记忆。
- 小改用 memory_replace，追加用 memory_insert，整块整理用 memory_rethink；
  块快满时先合并同类项再写，不要硬塞。
- 摘要可能失真时，用 conversation_search 回到对话原文核对。

回答用中文，简洁：先结论，再依据。"""


def _context_block(scope: str, blocks_rendered: str) -> str:
    """每轮注入的最小事实：省一次工具往返，同时把记忆块按 ABI 渲染进来。"""
    hub = _Source.hub
    store = _Source.store
    bits = [blocks_rendered, f"当前数据档位：{scope}"]
    if hub is not None and hub.latest:
        totals = hub.latest.get("totals", {})
        bits.append(
            f"实时帧 ts={hub.latest.get('ts')}，"
            f"出 {totals.get('out_bps', 0)/1024:.0f} KiB/s、"
            f"入 {totals.get('in_bps', 0)/1024:.0f} KiB/s、"
            f"未归因滚动 {(totals.get('unknown_ratio_rolling') or 0)*100:.1f}%"
        )
    if store is not None:
        stats = store.stats()
        bits.append(f"历史库保留 {stats.get('retention_days')} 天，最早数据 {stats.get('oldest')}")
    return "\n".join(bits)


def run_turn(question: str, session_id: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """跑一轮对话，产出 (event, payload)，由路由层封装成 SSE。"""
    config = load_config()
    scope = route_scope(question)
    tool_trace: list[dict[str, Any]] = []
    used_tools: list[str] = []
    _Source.session_id = session_id

    yield "meta", {
        "schema": SCHEMA,
        "provider": config.name,
        "provider_label": config.label,
        "model": config.model,
        "scope": scope,
        "scope_reason": "问题里出现了明细类字样" if scope == "detail" else "默认只发聚合摘要",
        "configured": config.configured,
    }

    if not config.configured:
        yield "error", {
            "message": "助手未配置模型。设置 FLOWWATCH_ASSISTANT_PROVIDER=openai 或 ollama"
                       "（以及 BASE_URL / API_KEY / MODEL）后重启即可；也可先用 mock 看链路。",
        }
        return

    MEMORY.append(session_id, "user", question)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT.format(scope=scope)}
    ]
    summary = MEMORY.summary(session_id)
    if summary:
        messages.append({"role": "system",
                         "content": f"更早对话的摘要（可用 conversation_search 回溯原文）：{summary}"})
    messages.append({"role": "system", "content": _context_block(scope, MEMORY.render_blocks())})
    messages += MEMORY.history(session_id)
    if not any(item["role"] == "user" and item["content"] == question for item in messages):
        messages.append({"role": "user", "content": question})

    tools = tools_for(scope)
    answer = ""

    try:
        if config.name == "mock":
            result = mock_turn(question, scope, tool_trace, session_id)
            for item in tool_trace:
                used_tools.append(item["name"])
                yield "tool", {"name": item["name"], "args": item["args"],
                               "effect": _effect_of(item["name"]),
                               "result": _truncate(item["result"])}
            answer = result["content"]
        else:
            for turn in range(MAX_TURNS):
                message = chat_completion(config, messages, tools)
                calls = message["tool_calls"]
                if not calls:
                    answer = message["content"] or ""
                    break
                messages.append({
                    "role": "assistant",
                    "content": message["content"] or "",
                    "tool_calls": calls,
                })
                for call in calls:
                    name = (call.get("function") or {}).get("name") or ""
                    raw = (call.get("function") or {}).get("arguments") or "{}"
                    try:
                        args = json.loads(raw) if isinstance(raw, str) else dict(raw)
                    except json.JSONDecodeError:
                        args = {}
                    result = run_tool(name, args, session_id)
                    used_tools.append(name)
                    yield "tool", {"name": name, "args": args,
                                   "effect": _effect_of(name),
                                   "result": _truncate(result)}
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id") or name,
                        "content": json.dumps(result, ensure_ascii=False),
                    })
                if turn == MAX_TURNS - 1:
                    answer = "（达到工具调用轮数上限，先把已查到的结果给你）"
    except Exception as exc:  # noqa: BLE001 - 网络/协议错误要如实告诉用户
        yield "error", {"message": f"{type(exc).__name__}: {exc}"}
        return

    MEMORY.append(session_id, "assistant", answer, scope=scope, tools=tuple(used_tools))
    compacted = MEMORY.compact(session_id)
    state = MEMORY.state()

    yield "done", {
        "text": answer,
        "scope": scope,
        "tools": used_tools,
        "compacted": compacted,
        "memory": {"sessions": state["sessions"], "messages": state["messages"],
                   "compacted": state["compacted"],
                   "blocks": [
                       {"label": item["label"], "chars_current": item["chars_current"],
                        "chars_limit": item["limit"]}
                       for item in state["blocks"]
                   ]},
    }


def _effect_of(name: str) -> str:
    tool = _TOOL_BY_NAME.get(name)
    return tool.effect if tool else name


def _truncate(result: Any, limit: int = 1400) -> Any:
    """工具结果回给前端展示时收一下，别把整页刷满。"""
    try:
        text = json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"raw": str(result)[:limit]}
    if len(text) <= limit:
        return result
    return {"truncated": True, "preview": text[:limit] + "…"}


# ---------------------------------------------------------------- HTTP 路由

router = APIRouter()


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    session_id: str = Field("default", max_length=120)


@router.get("/api/assistant/status")
async def assistant_status() -> dict[str, Any]:
    config = load_config()
    state = MEMORY.state()
    return {
        "schema": SCHEMA,
        "configured": config.configured,
        "provider": config.name,
        "provider_label": config.label,
        "model": config.model,
        "routing": {"default_scope": "aggregate", "detail_triggers": list(DETAIL_PATTERNS)},
        "tools": [{"name": tool.name, "scope": tool.scope, "description": tool.description}
                  for tool in TOOLS],
        "memory": {
            "sessions": state["sessions"],
            "messages": state["messages"],
            "compacted": state["compacted"],
            "blocks": state["blocks"],
        },
        "privacy": "只发送聚合元数据（进程名/域名/字节数）；对端 IP 明细仅在问题明确要求时"
                   "进入模型上下文。用 ollama 或 mock 则零外发。",
    }


@router.post("/api/assistant/chat")
async def assistant_chat(payload: ChatRequest) -> StreamingResponse:
    session_id = payload.session_id or "default"

    def stream() -> Iterator[str]:
        try:
            for event, data in run_turn(payload.question, session_id):
                yield f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001 - 兜底，保证 SSE 一定收尾
            body = json.dumps({"message": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False)
            yield f"event: error\ndata: {body}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.delete("/api/assistant/session/{session_id}")
async def assistant_reset(session_id: str) -> dict[str, Any]:
    MEMORY.reset(session_id)
    return {"ok": True, "memory": MEMORY.state()}


@router.delete("/api/assistant/memory")
async def assistant_forget() -> dict[str, Any]:
    """清空长期记忆块（保留会话记录）。"""
    MEMORY.forget_blocks()
    return {"ok": True, "memory": MEMORY.state()}
