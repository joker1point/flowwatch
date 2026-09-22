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

import asyncio
import ctypes
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Literal

import psutil
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ValidationError

import datadir

SCHEMA = "flowwatch-assistant/v1"
# 运行期数据落盘位置：源码运行 = 项目目录；打包成 exe = exe 所在目录（见 datadir.py）
MEMORY_PATH = datadir.data_path("assistant_memory.db")
# UI「模型设置」的落盘位置（含 API key，必须在 .gitignore 内）；
# 文件不存在时 load_config 静默回退环境变量 / 项目 .env。
CONFIG_PATH = datadir.data_path("assistant_config.json")

MAX_TURNS = 6                # 一轮提问最多几次模型往返（含工具轮）
RECENT_MESSAGES = 10         # 注入上下文的最近消息条数
COMPACT_THRESHOLD = 28       # 超过这么多条就把更早的标记为已压缩（**不删除**）
HTTP_TIMEOUT = 90.0
# 首轮"零工具调用"兜底。背景（2026-09-20 实测事故）：用户问"doubao 收发的是心跳包吗"，
# 模型一次工具都没调，直接编出"我查了实时帧 / 排行榜 / 事件流，都没有"整段结论，
# 而服务端当时无条件采信了它（while 循环里 `if not calls: answer = content; break`）。
# 命中 DATA_INTENT_PATTERNS 说明这问题要的是**本机实际数据**，必须先拿证据再说话。
DATA_INTENT_PATTERNS = (
    "进程", "程序", "应用", "域名", "网站", "流量", "带宽", "网速", "速率", "排行", "排名",
    "占用", "谁在", "哪个", "哪些", "连接", "事件", "心跳", "端口", "上传", "下载",
    "发送", "接收", "丢包", "延迟", "未归因", "字节", "dns", ".exe", ".com", "ip",
)
GROUNDING_NUDGE = (
    "（内部提示，用户看不到）你刚才没有调用任何工具就作答，涉及本机数据的结论没有依据，"
    "那份草稿已经作废、不会展示给用户，也不要提起它或检讨它。"
    "请直接重新作答：先调用需要的工具（用户点名了进程或域名就用 match 参数在全量数据里检索），"
    "拿不到数据就明确说没查到，不要编造查询过程。"
    "如果这其实是纯概念问题、不涉及本机数据，请说明这一点后再作答。"
)
UNVERIFIED_NOTE = "⚠️ 本轮未调用任何工具核实，以下内容没有本机数据支撑：\n\n"
# 只有取数据的工具（get_*）算"证据"。记忆类工具（memory_* / conversation_search）不产生任何
# 本机数据 —— 实测：模型只调 memory_insert 就顺带编出"Tabbit 占出向带宽 62%"，当时 grounded 还是 True。
DATA_TOOL_PREFIX = "get_"

# 纯记忆操作类请求（"记一下 / 帮我盯着 / 忘掉"）：这类问题的答案是"收据"，不是数据结论 ——
# 不该被打"未核实"前缀。但**只要答案里出现带单位的数字**（= 在给数据结论），前缀照样加：
# 这条红线来自 09-20 那次"只写记忆却编出占出向带宽 62%"。两处口径都由评估集发现（2026-09-22 修）。
MEMORY_INTENT_PATTERNS = (
    "记一下", "记录一下", "记下", "帮我记", "写进记忆", "记到", "存一下", "记个",
    "帮我盯", "盯着", "关注一下", "忘掉", "删除记忆", "删掉这条", "更新记忆", "改一下记忆",
)

_DATA_CLAIM_RE = re.compile(
    r"\d+(?:\.\d+)?\s*(?:%|KiB|MiB|GiB|TiB|KB|MB|GB|TB|bps|kbps|Mbps|Gbps|B/s)",
    re.IGNORECASE,
)


def is_memory_request(question: str) -> bool:
    """问题是不是"要求做一次记忆操作"（而不是问数据）。"""
    text = (question or "").lower()
    return any(pattern in text for pattern in MEMORY_INTENT_PATTERNS)


def _answer_has_data_claims(text: str) -> bool:
    """答案里有没有带单位的数字（= 它在给数据结论）。"""
    return bool(_DATA_CLAIM_RE.search(text or ""))


def _previous_user_question(session_id: str, current: str) -> str:
    """同一会话里上一句用户提问（用来把"数据意图"继承给追问）。"""
    for item in reversed(MEMORY.history(session_id, 8)):
        if item.get("role") == "user" and item.get("content") != current:
            return str(item.get("content") or "")
    return ""


def _is_evidence_result(result: Any) -> bool:
    """这次取数调用是否**真的拿到了数据**。

    踩过的坑：`grounded` 只看"调没调 get_*"时，参数校验失败（Pydantic 拦下、返回
    {"error": "参数不合法"}）也会被算成证据 —— 于是一个没拿到任何数据的一轮，在面板上
    显示成"已核实"。证据 = 取数工具 **且** 结果里没有 error。
    """
    return isinstance(result, dict) and "error" not in result


def needs_evidence(question: str) -> bool:
    """问题是否在要"本机实际数据"：决定零工具调用时要不要强制纠正一轮。

    明细档的问题**也是要数据** —— 两个词表必须一致。实测漏网（2026-09-22 联调）：
    问"Steam++ 连了谁？给我对端明细"时 `route_scope` 已经升到 detail（系统知道这是明细问题），
    但 `needs_evidence` 因为词表里没有"连了谁/对端/明细"而返回 False → 模型一次工具没调、
    答案里还引了"当前系统中…"，**却连"未核实"标都没有**。所以这里直接复用分档判据。
    """
    text = (question or "").lower()
    if any(pattern in text for pattern in DATA_INTENT_PATTERNS):
        return True
    return route_scope(question) == "detail"

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


# ---------------------------------------------------------------- 只读门面

class ReadOnlyStore:
    """历史库的**只读门面**：助手只拿得到查询方法，写方法在类型上不存在。

    为什么要有这一层：只读承诺不能停在"当前没有工具去写它"（那是**约定**）。`HistoryStore`
    上有 `append` / `submit` / `start_writer` / `stop_writer` / `close` / `set_name_resolver`，
    过去是随整个对象一起注入给助手的 —— 一次重构、一个新工具就能顺手用上，而且没人会注意到。
    这里与"明细工具在聚合档压根不注入"用同一套路：**物理隔离，不是提示词承诺**。

    刻意**不实现 `__getattr__`**：那会把写方法一起透传回来，等于没做门面。
    """

    #：真 `HistoryStore` 上的写面（评估集/单测据此断言"门面确实挡住了它们"）
    FORBIDDEN = ("open", "append", "submit", "start_writer", "stop_writer", "close",
                 "set_name_resolver")

    __slots__ = ("_store",)

    def __init__(self, store: Any) -> None:
        self._store = store

    def stats(self) -> dict[str, Any]:
        return self._store.stats()

    def top_processes(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return self._store.top_processes(*args, **kwargs)

    def top_domains(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return self._store.top_domains(*args, **kwargs)

    def timeline(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._store.timeline(*args, **kwargs)

    def events(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return self._store.events(*args, **kwargs)

    def process_series(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._store.process_series(*args, **kwargs)

    def __repr__(self) -> str:
        return "<ReadOnlyStore>"


# ---------------------------------------------------------------- 数据源注入

class _Source:
    """server.py 在启动时注入的只读数据入口（避免循环 import）。"""

    hub: Any = None
    store: Any = None
    capturer: Any = None
    session_id: str = "default"     # 由请求设置，供记忆类工具定位会话
    scope: str = "aggregate"        # 当前数据档位：决定哪些字段可以出到模型上下文


def configure(hub: Any = None, store: Any = None, capturer: Any = None,
              memory_path: Path | None = None) -> None:
    if hub is not None:
        _Source.hub = hub
    if store is not None:
        # 只挂只读门面（见 ReadOnlyStore）：助手没有"写历史库"的能力，不是"我们不写"
        _Source.store = ReadOnlyStore(store)
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

    def times_asked(self, session_id: str, question: str) -> int:
        """这句问题在本会话里问过几次（含刚写入的这一次）。

        用途：重复提问 = 上次的回答没被接受。实测过模型会复读自己上一轮的工具选择与结论
        （同一句"现在谁在占带宽"问两遍，它第二遍仍只查记忆里记着的那两个对象），
        所以这里给一个**确定性的信号**，而不是指望提示词把它劝住。
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE session_id=? AND role='user' AND content=?",
                (session_id, question),
            ).fetchone()
        return int(row[0]) if row else 0

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
    """区间内按累计字节排行的进程（只统计 pid > 0，不含哨兵桶）。用户点名某个进程时必须用 match 检索全量数据，不要只在排行榜里扫一眼。"""

    minutes: int = Field(60, ge=1, le=60 * 24 * 30, description="回看多少分钟，默认 60")
    limit: int = Field(10, ge=1, le=20, description="返回条数")
    match: str | None = Field(
        None,
        description="按进程名检索（不区分大小写的子串：小写 doubao 能命中 Doubao.exe）。"
                    "给了它就在全量数据里找、并按进程名合并，不受 limit 截断；"
                    "返回 matched=false 表示这段时间它没有流量记录 —— 不等于进程不存在。"
                    "**注意：它只按名字过滤**，问'谁占带宽最多'这种全局问题别传 match，"
                    "那会把答案缩成只看这一个对象",
    )
    group: bool = Field(
        True,
        description="按进程名合并同名多进程（默认开）。Electron 类应用常跑十几个同名进程，"
                    "按 pid 会被拆成十几行，单个 pid 甚至挤不进榜",
    )


class GetTopDomainsArgs(BaseModel):
    """区间内的域名排行（含 kind=ip 的未识别来源）。用户点名某个域名或服务时用 match 检索。"""

    minutes: int = Field(60, ge=1, le=60 * 24 * 30)
    limit: int = Field(10, ge=1, le=20)
    named_only: bool = Field(False, description="只看有域名的")
    match: str | None = Field(
        None,
        description="按**域名名**检索（不区分大小写的子串：小写 doubao 能命中 logifier.doubao.com）。"
                    "过滤发生在排行榜截断之前，命中的条目一定会返回。"
                    "注意它不等于'某个进程访问过的域名'—— 历史层不保存进程与域名的关联，"
                    "这条只有明细档的实时窗口（get_live_connections）能看到",
    )


class GetProcessHistoryArgs(BaseModel):
    """某个进程的历史曲线骨架（首末观测、峰值、区间累计、头尾若干桶）。"""

    pid: int = Field(..., ge=1, description="进程 PID")
    minutes: int = Field(60, ge=1, le=60 * 24 * 30)
    bucket: int = Field(1, ge=1, le=60, description="重采样桶宽（分钟）")


class GetEventsArgs(BaseModel):
    """变化事件流（出现 / 消失 / 尖峰），由落库观测值派生。问"某个应用最近有没有异常"用 match，别用 pid。"""

    limit: int = Field(20, ge=1, le=50)
    pid: int | None = Field(None, description="只看某个进程实例（pid 会变，一般用 match 更稳）")
    match: str | None = Field(
        None,
        description="按进程名过滤（不区分大小写子串：doubao 能命中 Doubao.exe）。"
                    "事件是稀疏数据，明确窗口才看得出'没有异常'",
    )
    minutes: int | None = Field(
        None, ge=1, le=60 * 24 * 30,
        description="只看最近多少分钟；不传就是全库最近 limit 条（可能全是别人的事件）",
    )


class GetLiveConnectionsArgs(BaseModel):
    """某进程当前窗口的连接明细（对端 IP:端口 + 域名）。仅在明细档可用。"""

    pid: int = Field(..., ge=1)
    limit: int = Field(10, ge=1, le=20)


class GetProcessIdentityArgs(BaseModel):
    """某个进程到底是哪个软件：exe 的厂商 / 产品名 / 描述 / 版本（完整路径只在明细档给出）。回答"这个进程是什么/谁装的/是不是系统组件"就用它，别靠名字猜。"""

    pid: int | None = Field(None, ge=1, description="进程 PID（从排行或实时帧里拿）")
    match: str | None = Field(
        None,
        description="只知道名字时给名字片段（如 GameViewer）：工具会先按它查到 pid 再读身份信息",
    )
    minutes: int = Field(60, ge=1, le=60 * 24 * 30,
                         description="用 match 找 pid 时的回看窗口，默认 60 分钟")


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
    items = _Source.store.top_processes(minutes=args.minutes, limit=args.limit,
                                        match=args.match, group=args.group)
    payload: dict[str, Any] = {"minutes": args.minutes, "match": args.match, "items": items}
    if args.match:
        payload["matched"] = bool(items)
        payload["note"] = "match 已生效：这是按名字在**全量**数据里检索的结果，不是排行榜前 N 条"
        if not items:
            payload["hint"] = (
                f"近 {args.minutes} 分钟内没有进程名含「{args.match}」的流量记录。"
                "这只说明「没有流量」，不等于进程没在跑 —— 进程在跑但没有网络活动是两回事，"
                "不要据此说进程不存在；可以说'归因数据里没有它的流量'。"
            )
    return payload


def _tool_top_domains(args: GetTopDomainsArgs, _session: str) -> dict[str, Any]:
    if _Source.store is None:
        return {"error": "历史层未就绪"}
    items = _Source.store.top_domains(
        minutes=args.minutes, limit=args.limit, named_only=args.named_only, match=args.match
    )
    payload: dict[str, Any] = {"minutes": args.minutes, "match": args.match, "items": items}
    if args.match:
        payload["matched"] = bool(items)
        payload["note"] = "match 已生效：过滤发生在排行截断之前，命中的一定会返回"
    return payload


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
    items = _Source.store.events(limit=args.limit, pid=args.pid,
                                 match=args.match, minutes=args.minutes)
    payload: dict[str, Any] = {"minutes": args.minutes, "match": args.match,
                               "count": len(items), "items": items}
    if len(items) >= args.limit:
        payload["truncated"] = True
        payload["truncated_note"] = (f"只返回了最近 {len(items)} 条（命中 limit），"
                                     "不是全量 —— 说明情况时要讲清这是样本")
    if args.match and not items:
        payload["note"] = (
            "这段窗口里没有该名字的事件。事件只在「出现 / 消失 / 尖峰」时产生，"
            "**没有事件 ≠ 没有流量** —— 要说它有流量还是没流量，得另查排行。"
        )
    elif not args.minutes:
        payload["note"] = "没限定时间窗，这只是全库最近的若干条；判断'有没有异常'请带上 minutes 重查。"
    return payload


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


def _version_strings(path: str) -> dict[str, str]:
    """读 exe 的版本资源：CompanyName / ProductName / FileDescription / FileVersion。

    为什么值得写这段 ctypes：光看进程名判断不了"这是哪个软件"—— `GameViewerServer.exe`
    实际是「网易UU远程」。版本资源里写着厂商与产品名，是最便宜的身份答案。
    pywin32 不在依赖里，所以直接调 version.dll；非 Windows 或读不到都返回空字典（fail-closed）。
    """
    if sys.platform != "win32":
        return {}
    try:
        from ctypes import wintypes

        version = ctypes.WinDLL("version.dll")
        version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                wintypes.DWORD, ctypes.c_void_p]
        version.GetFileVersionInfoW.restype = wintypes.BOOL
        version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_uint)]
        version.VerQueryValueW.restype = wintypes.BOOL

        ignored = wintypes.DWORD()
        size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
        if not size:
            return {}
        block = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, block):
            return {}

        def probe(sub: str) -> tuple[int, int] | None:
            pointer = ctypes.c_void_p()
            length = ctypes.c_uint()
            if not version.VerQueryValueW(block, sub, ctypes.byref(pointer), ctypes.byref(length)):
                return None
            if not pointer.value or not length.value:
                return None
            return int(pointer.value), int(length.value)

        # 踩过的坑：VerQueryValueW 返回的长度单位不统一 —— **二进制块按字节，字符串按字符**。
        # 一开始全按字节读（string_at(ptr, len)）→ "NetEase" 只读到 "NetE"，产品名只读到
        # "网易UU"（真值「网易UU远程」）。字符串值本身以 NUL 结尾，直接 wstring_at 最稳。
        hit = probe(r"\VarFileInfo\Translation")
        translation = ctypes.string_at(hit[0], hit[1]) if hit else b""
        pairs = [
            (int.from_bytes(translation[i:i + 2], "little"),
             int.from_bytes(translation[i + 2:i + 4], "little"))
            for i in range(0, len(translation) - 3, 4)
        ] or [(0x0409, 0x04B0)]            # 没有翻译表就用 en-US + Unicode
        for lang, codepage in pairs:
            prefix = rf"\StringFileInfo\{lang:04x}{codepage:04x}"
            got: dict[str, str] = {}
            for field in ("CompanyName", "ProductName", "FileDescription", "FileVersion"):
                hit = probe(f"{prefix}\\{field}")
                got[field] = ctypes.wstring_at(hit[0]).strip() if hit else ""
            if any(got.values()):
                return got
        return {}
    except Exception:      # 任何异常都只是"读不到身份"，不该打断一轮对话
        return {}


def _tool_process_identity(args: GetProcessIdentityArgs, _session: str) -> dict[str, Any]:
    pid = args.pid
    name = ""
    if pid is None:
        if not (args.match or "").strip():
            return {"error": "pid 与 match 至少给一个"}
        if _Source.store is None:
            return {"error": "历史层未就绪"}
        found = _Source.store.top_processes(minutes=args.minutes, limit=1, match=args.match)
        if not found:
            return {"pid": None, "match": args.match, "found": False,
                    "hint": f"近 {args.minutes} 分钟没有进程名含「{args.match}」的流量记录，"
                            "于是拿不到 pid —— 没有流量不等于进程没在运行"}
        pid = int(found[0]["pid"])
        name = str(found[0].get("process") or "")
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        if not name:
            name = proc.name()
    except Exception as exc:  # 进程已退出 / 权限不足（服务或提权进程）
        return {"pid": pid, "process": name, "error": f"{type(exc).__name__}: {exc}",
                "hint": "拿不到可执行路径：它可能已退出，或跑在更高权限下（服务/提权进程）"}
    info = _version_strings(exe)
    payload: dict[str, Any] = {
        "pid": pid,
        "process": name,
        "company": info.get("CompanyName", ""),
        "product": info.get("ProductName", ""),
        "description": info.get("FileDescription", ""),
        "version": info.get("FileVersion", ""),
    }
    if _Source.scope == "detail":
        payload["path"] = exe
    else:
        payload["path_note"] = ("完整路径按隐私分级只在明细档给（用户问对端/端口/明细时会升档）；"
                                "厂商/产品/版本当前档位即可用")
    if not any(payload[key] for key in ("company", "product", "description")):
        payload["note"] = "该 exe 没有版本资源（自编译 / 绿色软件常见），只能按名字判断"
    return payload


# ---------------------------------------------------------------- 记忆工具实现

def _tool_memory_insert(args: MemoryInsertArgs, session: str) -> dict[str, Any]:
    text = args.text.strip()
    if not text:
        return {"error": "text 是空的 —— 追加内容要是自包含的一句话"}
    current = MEMORY.block_value(args.label)
    # 去重：块每轮都注入给模型看，重复写入只会在预算里灌水（实测过：一句话被写两遍）
    if text.casefold() in current.casefold():
        return {"ok": False, "reason": "块里已经有同样内容，未重复写入", "current": current}
    joined = (current + "\n" + text).strip() if current else text
    result = MEMORY.block_write(args.label, joined)
    if result.get("ok"):
        result["current"] = MEMORY.block_value(args.label)   # 回读：模型能直接核对自己写进去的东西
        result["hint"] = ("已追加。同一事实只写一次；块快满时用 memory_rethink 合并同类项，"
                          "别把重复内容硬塞进去。")
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
    Tool("get_process_identity", "aggregate", GetProcessIdentityArgs, _tool_process_identity,
         effect="读取进程身份（厂商/产品/版本）"),
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


def memory_write_enabled() -> bool:
    """是否给助手"写自己记忆库"的权限（默认给）。

    记忆是 **agent 自己的状态**，不是观测数据 —— 所以默认 auto。`off` 时**结构上关掉**：
    `tools_for()` 不再注入 `memory_*` 写工具，`run_tool()` 也会拒绝（防模型凭空点名叫它）。
    写法与隐私分档一致：不是叮嘱它别写，而是它写不了。
    """
    return (os.environ.get("FLOWWATCH_ASSISTANT_MEMORY_WRITE") or "auto").strip().lower() != "off"


def tools_for(scope: str) -> list[dict[str, Any]]:
    """按档位给出工具清单 —— "物理隔离"就落在这个函数里。

    记忆类工具始终可用（它不碰数据暴露面，且读记忆的 conversation_search 不需要写权限）；
    明细工具只在 D 档出现；`FLOWWATCH_ASSISTANT_MEMORY_WRITE=off` 时写记忆的三个也摘掉。
    """
    allowed = [tool for tool in TOOLS if tool.scope in ("aggregate", "memory")]
    if scope == "detail":
        allowed += [tool for tool in TOOLS if tool.scope == "detail"]
    if not memory_write_enabled():
        allowed = [tool for tool in allowed if not tool.name.startswith("memory_")]
    return [tool.spec() for tool in allowed]


def run_tool(name: str, raw_args: Any, session_id: str = "default") -> dict[str, Any]:
    """执行工具。参数校验失败**不抛异常**，而是把校验结果作为观察回给模型。

    执行前有两道**硬闸**（纵深防御，不是给模型看的提示词）：
      · 档位闸：明细工具在非明细档直接拒绝 —— 模型被诱导、或幻觉点名叫它都没用
        （"不在工具列表里"只是第一道；模型完全可以凭记忆拼出工具名）；
      · 记忆写闸：`FLOWWATCH_ASSISTANT_MEMORY_WRITE=off` 时拒绝写记忆（读的照常）。
    """
    tool = _TOOL_BY_NAME.get(name)
    if tool is None:
        return {"error": f"没有这个工具：{name}", "available": sorted(_TOOL_BY_NAME)}
    if tool.scope == "detail" and _Source.scope != "detail":
        return {"error": f"{name} 在当前数据档位不可用（明细档才对模型开放）",
                "scope": _Source.scope}
    if tool.name.startswith("memory_") and not memory_write_enabled():
        return {"error": "记忆写入已关闭（FLOWWATCH_ASSISTANT_MEMORY_WRITE=off）"}
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


_ENV_FILE_LOADED = False


def _read_config_file() -> dict[str, str]:
    """读 UI 保存的配置；不存在/损坏都返回空字典（静默回退 env，不打断服务）。"""
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v.strip() for k, v in data.items() if isinstance(v, str) and v.strip()}


def _mask_key(key: str) -> str:
    """API key 只回显前 6 位（前端据此实现"留空 = 不修改"）。"""
    if not key:
        return ""
    return f"{key[:6]}***" if len(key) > 6 else "***"


def _load_env_file_once() -> None:
    """可选：从项目内 .env 加载 FLOWWATCH_ASSISTANT_*（零依赖；不覆盖已有环境变量）。

    便于把 provider/key 配置留在项目里，而不污染用户级环境变量。
    注意：.env 含 API key，必须在 .gitignore 内。
    """
    global _ENV_FILE_LOADED
    if _ENV_FILE_LOADED:
        return
    _ENV_FILE_LOADED = True
    path = datadir.data_path(".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


def load_config() -> ProviderConfig:
    """配置优先级：UI 保存文件（assistant_config.json）> 环境变量 / 项目 .env。

    开源用户第一次打开页面时没有任何配置 —— 用页面里的「模型设置」写文件即可生效，
    不必再折腾环境变量；部署方仍可用环境变量做无人值守配置（逐字段回退）。
    """
    _load_env_file_once()
    saved = _read_config_file()

    def pick(field: str, env_name: str, default: str = "") -> str:
        return saved.get(field) or (os.environ.get(env_name) or "").strip() or default

    name = pick("provider", "FLOWWATCH_ASSISTANT_PROVIDER").lower()
    model = pick("model", "FLOWWATCH_ASSISTANT_MODEL")
    if name == "mock":
        return ProviderConfig("mock", "本地 mock（不联网，仍真跑工具）", "", "", model or "mock")
    if name == "openai":
        base = pick("base_url", "FLOWWATCH_ASSISTANT_BASE_URL").rstrip("/")
        key = pick("api_key", "FLOWWATCH_ASSISTANT_API_KEY")
        if not (base and key and model):
            return UNCONFIGURED
        return ProviderConfig("openai", f"远端 · {model}", base, key, model)
    if name == "ollama":
        base = pick("base_url", "FLOWWATCH_ASSISTANT_OLLAMA_URL",
                    "http://127.0.0.1:11434/v1").rstrip("/")
        return ProviderConfig("ollama", f"本地 Ollama · {model or '未指定模型'}", base, "ollama",
                              model or "qwen2.5:7b")
    return UNCONFIGURED


def _opener() -> urllib.request.OpenerDirector:
    """代理策略：**默认直连**。

    踩过的坑：本机全局设了 http_proxy / https_proxy = 127.0.0.1:7890（Clash 之类），
    代理没开时 urllib 会照着环境变量去连它 —— 连国内 API（如 dashscope）也会被挡下，
    报出来的还是 127.0.0.1 连接失败，很容易误判成"服务挂了"。
    需要走代理访问 OpenAI 的场景，显式配置：
        FLOWWATCH_ASSISTANT_PROXY=env          # 尊重环境变量里的代理
        FLOWWATCH_ASSISTANT_PROXY=http://127.0.0.1:7890
    """
    setting = (os.environ.get("FLOWWATCH_ASSISTANT_PROXY") or "").strip()
    if not setting:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    if setting.lower() == "env":
        return urllib.request.build_opener()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": setting, "https": setting})
    )


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str],
               timeout: float = HTTP_TIMEOUT) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with _opener().open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def chat_completion(config: ProviderConfig, messages: list[dict[str, Any]],
                    tools: list[dict[str, Any]],
                    tool_choice: str | None = None) -> dict[str, Any]:
    """调一次 chat/completions，返回 assistant message（content + tool_calls）。

    `tool_choice` 默认 "auto"；传 "required" = **协议层**要求必须调用某个工具。
    支持面因 provider 而异（2026-09-22 实测：DashScope 兼容模式对 auto / required /
    点名函数三种都接受），所以调用方一律走 `_completion()` —— 它会在 provider 不认这个
    字段时退回 auto，不让一轮对话因为"强制失败"直接报错。
    """
    payload: dict[str, Any] = {"model": config.model, "messages": messages, "temperature": 0.2}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = tool_choice or "auto"
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


def _completion(config: ProviderConfig, messages: list[dict[str, Any]],
                tools: list[dict[str, Any]], required: bool = False) -> dict[str, Any]:
    """带"必须调用工具"的兼容包装：provider 不认 `tool_choice` 就如实退回 auto。

    为什么要有这一层：纠正轮的意图是"这次必须先去查"，协议层强制比提示词叮嘱可靠
    （提示词拦不住的情况实测过）。但本地 Ollama / 各家兼容 API 对这个字段的支持面不一样，
    不支持时通常报 400/404/422 —— 那就退回 auto，如实降级而不是让整轮问答报错。
    """
    if not (required and tools):
        return chat_completion(config, messages, tools)
    try:
        return chat_completion(config, messages, tools, tool_choice="required")
    except urllib.error.HTTPError as exc:
        if exc.code not in (400, 404, 422):
            raise
        return chat_completion(config, messages, tools)


# ------------------------------------------------- 系统侧补查（零工具调用的兜底）
# 触发条件（见 run_turn）：问题要本机数据，而模型**纠正之后仍然**一个工具都没调。
# 这一层刻意不依赖模型合作 —— 服务端按问题类型跑确定性取数，把结果作为"系统补查"
# 注回上下文，让模型基于真实数据重答。与其它手段的分工：
#   · 提示词 / tool_choice：请模型自己查（首选，它选得比规则准）；
#   · 系统补查：它两次都没查时，别让用户拿到的答案从"作废"开始；
#   · 未核实标注：连补查也取不到数据时，如实标（红线不动）。
# 规则表与 mock_turn 的演示规则同族，这里多了实体抽取（match）与明细档的两步链路。

_FALLBACK_STOPWORDS = {"top", "ip", "dns", "exe", "app", "and", "the", "for", "this", "that"}

_FALLBACK_RULES: tuple[tuple[tuple[str, ...], str, dict[str, Any]], ...] = (
    (("域名", "网站", "domain", "访问"), "get_top_domains", {"minutes": 60, "limit": 8}),
    (("事件", "变化", "尖峰", "出现", "消失", "异常"), "get_events", {"limit": 10}),
    (("健康", "状态", "未归因", "丢包", "采集", "延迟"), "get_health", {}),
    (("实时", "当前", "此刻", "这会儿"), "get_live_frame", {"top": 6}),
    (("进程", "程序", "应用", "带宽", "流量", "占用", "排行", "排名", "最多", "第一",
      "谁在", "哪些", "连接", "连了谁", "对端", "明细", "心跳", "上传", "下载", "发送", "接收"),
     "get_top_processes", {"minutes": 60, "limit": 8}),
)
_FALLBACK_MAX_PICKS = 2


def _fallback_entity(question: str) -> str | None:
    """从问题里抽"点名对象"（英数名片段）当 match 用；抽不到返回 None。

    全局性问题（"谁占带宽最多 / 一共多少"）**不抽** —— 传 match 会把答案缩成单对象，
    这条在 get_top_processes 的 schema 里也写明了。
    """
    text = question or ""
    if any(word in text for word in ("排行", "最多", "第一", "谁在", "哪些", "哪几个",
                                     "一共", "总共", "总体", "整体")):
        return None
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_.+-]{1,}", text):
        name = token.strip("._+-").lower()
        if len(name) >= 3 and name not in _FALLBACK_STOPWORDS:
            return name
    return None


def _fallback_picks(question: str, scope: str) -> list[tuple[str, dict[str, Any]]]:
    """按问题类型给出确定性取数清单：只用**当前档位可见**的工具（隐私分档不在这里破），最多两个。"""
    lower = (question or "").lower()
    allowed = {item["function"]["name"] for item in tools_for(scope)}
    match = _fallback_entity(question)
    picks: list[tuple[str, dict[str, Any]]] = []
    for words, name, args in _FALLBACK_RULES:
        if len(picks) >= _FALLBACK_MAX_PICKS:
            break
        if name in allowed and all(name != item[0] for item in picks) \
                and any(word in lower for word in words):
            picks.append((name, dict(args)))
    if not picks:
        # 认不出类型：**点名了对象**就按名字检索（比窗口快照贴题），否则给最便宜的实时快照
        if match and "get_top_processes" in allowed:
            picks.append(("get_top_processes", {"minutes": 60, "limit": 8}))
        else:
            picks.append(("get_live_frame", {"top": 6}) if "get_live_frame" in allowed
                         else ("get_health", {}))
    if match:          # 点名对象 → 排行类工具带 match（明细档还要靠它定位 pid）
        picks = [(name, {**args, "match": match})
                 if name in ("get_top_processes", "get_top_domains") else (name, args)
                 for name, args in picks]
    return picks


def _fallback_evidence(result: Any) -> bool:
    """补查结果算不算证据：**必须有内容**。空排行 = 这段时间没记录，不是证据。"""
    if not _is_evidence_result(result):
        return False
    if isinstance(result, dict):
        items = result.get("items")
        if isinstance(items, list) and not items:
            return False
    return True


def _fallback_fetch(question: str, scope: str, session_id: str) -> list[dict[str, Any]]:
    """执行确定性补查（工具报错照实带回去，不吞）。明细档再补一步"连线明细"。"""
    fetched: list[dict[str, Any]] = []
    for name, args in _fallback_picks(question, scope):
        fetched.append({"name": name, "args": args, "result": run_tool(name, args, session_id)})
    # 明细档的关联只有实时窗口能给（历史层不保存"进程 ↔ 域名"），所以用刚查到的 pid 再补一条。
    if scope == "detail" and not any(item["name"] == "get_live_connections" for item in fetched):
        pid = next((int(item["pid"]) for entry in fetched
                    if entry["name"] == "get_top_processes" and isinstance(entry["result"], dict)
                    for item in (entry["result"].get("items") or [])
                    if isinstance(item, dict) and item.get("pid")), None)
        if pid:
            args = {"pid": pid, "limit": 10}
            fetched.append({"name": "get_live_connections", "args": args,
                            "result": run_tool("get_live_connections", args, session_id)})
    return fetched


def _fallback_note(fetched: list[dict[str, Any]]) -> str:
    """把补查结果作为**内部信息**注回上下文（这条消息用户看不到，但工具行会出现在面板上）。"""
    lines = ["（系统补查 · 用户看不到这段）你连续两次没有调用任何工具，涉及本机数据的结论没有依据。",
             "服务端已按问题类型代你执行下列取数，请直接基于这些结果作答：",
             "· 不要把它复述成'我调用了工具'；空结果就如实说这段时间没有记录。"]
    for item in fetched:
        lines.append(f"\n[{item['name']} {json.dumps(item['args'], ensure_ascii=False)}]\n"
                     f"{json.dumps(item['result'], ensure_ascii=False)}")
    return "\n".join(lines)


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
- **点名就先检索**：用户提到具体进程或域名（如 doubao）时，用 get_top_processes /
  get_top_domains 的 match 参数在全量数据里查，不要只在排行榜前 N 条里"扫一眼" ——
  同一个应用常跑十几个进程、还会分散在多个域名上，扫榜必漏。
  match 返回 matched=false 时只能说"这段时间没有它的流量记录"，**不能说"这个进程不存在"**
  （进程在跑但没有网络活动是两回事）。
- **不许描述没做过的动作**：工具调用过程用户能看到。别写"我用不区分大小写匹配查过"这类
  你没真的执行过的步骤，也不要把上文的背景数字当作查证结果。
- **记忆是背景，不是问题的范围**：用户问全局（"谁占带宽最多""一共多少流量"）时，必须查
  **不带 match** 的完整排行；记忆里记着的对象只是额外关注点，别把答案悄悄缩成"这两个对象的情况"。
- **每轮独立选工具；重复提问是红灯**：会话历史里出现过的查询方式只是记录，不是模板。
  如果用户把同一个问题又问了一遍，说明上次的回答他没接受 —— 必须重新核实，并换用更贴合
  问题的工具（问全局排行就用不带 match 的完整排行），不要复读上次的做法与结论。
- **内部过程留在内部**：不要写"我差点没调工具/违反了准则/现按规则重答"，也不要提"此前的回答
  有误 / 已确认编造"这类自我检讨 —— 用户看不到草稿，只看得到你这一条结论。答不了就直接说
  答不了和原因（例如历史层没有这个维度）。
- **match 只按名字过滤**。问"某个进程连了哪些域名"历史层答不了（进程与域名的关联没落库，
  只有 detail 档的实时窗口 get_live_connections 能看到）—— 要如实说查不到，别拿域名名过滤冒充。
- 某 pid 的"消失"事件只代表那一个进程实例结束了，**不等于整个应用没流量**；
  说一个对象有/没有流量，必须来自一次明确的排行查询。
- **别靠进程名猜软件**：要判断某个进程"是哪个软件/哪个厂商装的"，用 `get_process_identity`
  （给 pid，或直接给名字片段让它自己找 pid）。它读的是 exe 版本资源（厂商/产品/描述/版本），
  比按文件名猜可靠；进程已退出或跑在更高权限下时它会给不出路径，如实说"取不到"即可。
- 说进程"是干什么的"前先调 get_process_identity，别按名猜（曾把 GameViewerServer 猜成"腾讯游戏助手"）。
- 判断类结论必须贴定量证据（连接数、单连接平均字节、出/入比），别只给"能/不能判断"。
- 数据被 limit 截断时必须说明"这是最近 N 条样本，非全量"。
- 用户问"为什么/怎么回事"时，先查排行、历史、事件，再下结论。
- **代词先把指代查清楚**：用户说"它/他/这个"时，先用上一轮点名对象的 match 检索拿到数据，
  不要因为"指代不明"就放弃查数据、直接给一段泛泛的话（实测踩过：多轮里"它是哪个软件？"
  模型一个字都没查就作答，被打了"未核实"标）。
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
- **写之前先看本轮已注入的块内容**：同一事实只写一次，已在块里的直接跳过（重复写入会被拒）；
  写"对象 + 为什么要盯 + 日期"，不要写同义改写，也别给自己的描述加戏。
- 纯记忆类请求（"记一下""忘掉"）就回执这件事本身，**不要顺带给出没查过的流量数字**。
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


def _strip_repeated_answers(history: list[dict[str, str]], question: str) -> list[dict[str, str]]:
    """重复提问时，把历史里"同一句提问 + 紧随其后的回答"整对丢掉。

    实测背景（2026-09-20）：同一句"现在谁在占带宽"问第 4 遍，历史里那 3 对问答成了
    few-shot 模板，"每轮独立选工具"的提示词与新加的 system 提醒都拦不住复读 ——
    把模板本身移出上下文才有效。当前这一轮的提问由调用方在末尾补回。
    """
    kept: list[dict[str, str]] = []
    skip_answer = False
    for item in history:
        if skip_answer and item.get("role") == "assistant":
            skip_answer = False
            continue
        skip_answer = False
        if item.get("role") == "user" and item.get("content") == question:
            skip_answer = True          # 这一对不要了：回答紧跟在后面
            continue
        kept.append(item)
    return kept


def run_turn(question: str, session_id: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """跑一轮对话，产出 (event, payload)，由路由层封装成 SSE。"""
    config = load_config()
    scope = route_scope(question)
    tool_trace: list[dict[str, Any]] = []
    used_tools: list[str] = []
    evidence_tools: list[str] = []      # 只收"成功返回数据"的取数工具（见 _is_evidence_result）
    _Source.session_id = session_id
    _Source.scope = scope          # 工具的字段级隐私分级（如完整路径只在 detail 档出）

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

    # 追问继承上一轮的数据意图（实测漏网 2026-09-22 联调）："那 doubao 呢？"这类短追问不含任何
    # 数据关键词 —— 纯词表判定会漏，于是模型在正文里写了一次**没真发生**的工具调用也没人管。
    # 规则：本轮不含数据词时，看同一会话里上一句是不是数据问题；是则本轮也按数据问题对待。
    needs_data = bool(needs_evidence(question)
                      or needs_evidence(_previous_user_question(session_id, question)))

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT.format(scope=scope)}
    ]
    summary = MEMORY.summary(session_id)
    if summary:
        messages.append({"role": "system",
                         "content": f"更早对话的摘要（可用 conversation_search 回溯原文）：{summary}"})
    messages.append({"role": "system", "content": _context_block(scope, MEMORY.render_blocks())})
    # 重复提问 = 上次没答好。只要光提醒不够：实测同一句问 4 遍，模型会把自己上一轮的
    # 问答当成 few-shot 模板照抄（连加了 system 提醒都照抄）。要断复读，就得把那个模板
    # 从上下文里**拿掉**，再把"这是重复提问"讲清楚。
    asked_before = MEMORY.times_asked(session_id, question)
    history = MEMORY.history(session_id)
    if asked_before > 1:
        history = _strip_repeated_answers(history, question)
    messages += history
    if not any(item["role"] == "user" and item["content"] == question for item in messages):
        messages.append({"role": "user", "content": question})
    if asked_before > 1:
        messages.append({
            "role": "system",
            "content": f"注意：用户此前已问过同样的问题（含本轮共 {asked_before} 次），"
                       "说明上次的回答没有被接受，相关的旧回答已从上下文里移除。请重新核实，"
                       "并换用更贴合问题的工具（问全局排行就用**不带 match** 的完整排行）。",
        })

    tools = tools_for(scope)
    answer = ""
    forced_grounding = False        # 是否因"首轮零工具调用"强制纠正过一轮
    force_next = False              # 纠正轮的下一跳：协议层声明"必须调用工具"（见 _completion）
    fallback_tools: list[str] = []  # 系统补查代跑的工具（模型两次零工具时的兜底）

    try:
        if config.name == "mock":
            result = mock_turn(question, scope, tool_trace, session_id)
            for item in tool_trace:
                used_tools.append(item["name"])
                if item["name"].startswith(DATA_TOOL_PREFIX) and _is_evidence_result(item["result"]):
                    evidence_tools.append(item["name"])
                yield "tool", {"name": item["name"], "args": item["args"],
                               "effect": _effect_of(item["name"]),
                               "result": _truncate(item["result"])}
            answer = result["content"]
        else:
            for turn in range(MAX_TURNS):
                message = _completion(config, messages, tools, required=force_next)
                force_next = False
                calls = message["tool_calls"]
                if not calls:
                    draft = (message["content"] or "").strip()
                    # 首轮零工具调用，而问题要的是本机数据 → 不采信这份草稿，纠正一轮再来。
                    # 把草稿一起带回去，模型才知道"刚才那份不算数"。
                    # 刻意**不把草稿放回上下文**：放回去它就会在终稿里写"此前回答系编造、
                    # 已确认错误"这类自我检讨 —— 而用户从没见过那份草稿（实测踩过）。
                    if turn == 0 and not forced_grounding and tools and needs_data:
                        forced_grounding = True
                        force_next = True       # 纠正轮同时上协议层强制（不认的 provider 自动退回 auto）
                        messages.append({"role": "user", "content": GROUNDING_NUDGE})
                        continue
                    # 第二次仍然零工具 → **系统侧补查**：服务端自己按问题类型跑确定性取数，
                    # 把结果注回上下文让它基于真实数据重答。这是唯一不依赖模型合作的一层 ——
                    # 补查也取不到数据时，才落到下面的"未核实"标注（红线不动）。
                    # 触发条件是**整轮一个工具都没调用过**（`used_tools` 为空），刻意比"这一步没调"
                    # 更窄：调过工具却没拿到数据（参数非法、只调了记忆工具）不在这里抢管 ——
                    # 那两种情况继续由"未核实"标注兜底（红线用例 args-invalid-01 / memory-only-03）。
                    if needs_data and not used_tools and not fallback_tools:
                        fetched = _fallback_fetch(question, scope, session_id)
                        if fetched:
                            for item in fetched:
                                fallback_tools.append(item["name"])
                                used_tools.append(item["name"])
                                if item["name"].startswith(DATA_TOOL_PREFIX) \
                                        and _fallback_evidence(item["result"]):
                                    evidence_tools.append(item["name"])
                                yield "tool", {"name": item["name"], "args": item["args"],
                                               "effect": _effect_of(item["name"]),
                                               "origin": "system",   # 面板可据此标注"系统补查"
                                               "result": _truncate(item["result"])}
                            messages.append({"role": "system", "content": _fallback_note(fetched)})
                            continue
                    answer = draft
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
                    if name.startswith(DATA_TOOL_PREFIX) and _is_evidence_result(result):
                        evidence_tools.append(name)
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

    # 数据类问题却一个取数工具都没**成功**跑过（含"只调了记忆工具"这种假证据）→ 显式标注未核实。
    # 两处细化（都由评估集发现，2026-09-22 修）：
    #   ① 证据 = **成功返回数据**的取数调用（参数校验失败的调用不算，见 _is_evidence_result）；
    #   ② 纯记忆操作请求（"记一下/帮我盯着"）在"只调了记忆工具 + 答案里没有带单位的数字"时豁免
    #      —— 收据不再被误标，而"只写记忆却答数据"那条红线仍然守得住。
    memory_only = bool(used_tools) and all(
        name.startswith("memory_") or name == "conversation_search" for name in used_tools)
    exempt = (is_memory_request(question) and memory_only
              and not _answer_has_data_claims(answer))
    unverified = bool(needs_data and not evidence_tools and not exempt)
    if unverified:
        answer = UNVERIFIED_NOTE + answer

    MEMORY.append(session_id, "assistant", answer, scope=scope, tools=tuple(used_tools))
    compacted = MEMORY.compact(session_id)
    state = MEMORY.state()

    yield "done", {
        "text": answer,
        "scope": scope,
        "tools": used_tools,
        "evidence_tools": evidence_tools,   # 只算**成功返回数据**的取数工具
        "grounded": bool(evidence_tools),   # 本轮结论有没有数据证据
        "retried": forced_grounding,        # 是否触发过"零工具调用"纠正
        "fallback": fallback_tools,         # 系统侧补查代跑的工具（模型两次零工具时的兜底）
        "unverified": unverified,           # 本轮是否被打上"未核实"标注（评估集直接断言这个）
        "memory_request": is_memory_request(question),   # 纯记忆操作请求（收据类）
        "needs_evidence": needs_data,       # 本轮是否按"要本机数据"对待（含追问继承）
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


class ConfigIn(BaseModel):
    """UI「模型设置」表单：api_key 留空或掩码（sk-abc***）= 保留已保存的 key。"""
    provider: Literal["openai", "ollama", "mock"]
    base_url: str = Field("", max_length=500)
    api_key: str = Field("", max_length=500)
    model: str = Field("", max_length=200)


def _resolve_key(raw: str) -> str:
    """表单空值/掩码视为"不修改"，沿用已保存或环境变量里的 key。"""
    if raw and not raw.endswith("***"):
        return raw
    return _read_config_file().get("api_key", "") or (os.environ.get("FLOWWATCH_ASSISTANT_API_KEY") or "").strip()


def _candidate(provider: str, base_url: str, api_key: str, model: str) -> ProviderConfig:
    """把表单值拼成候选配置（不落盘），供保存前的「测试连接」使用。"""
    provider = provider.strip().lower()
    if provider == "mock":
        return ProviderConfig("mock", "本地 mock（不联网，仍真跑工具）", "", "", model or "mock")
    if provider == "ollama":
        return ProviderConfig("ollama", f"本地 Ollama · {model or '未指定模型'}",
                              (base_url or "http://127.0.0.1:11434/v1").rstrip("/"), "ollama",
                              model or "qwen2.5:7b")
    return ProviderConfig("openai", f"远端 · {model}", base_url.rstrip("/"), api_key, model)


def _ping(config: ProviderConfig) -> dict[str, Any]:
    """发一句最小请求验证连通性；HTTP 错误把响应体读出来（如配额/权限提示）。"""
    if config.name == "mock":
        return {"ok": True, "detail": "mock 模式不联网，始终可用"}
    try:
        result = chat_completion(config, [{"role": "user", "content": "回复两个字：连通"}], [])
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            body = ""
        return {"ok": False, "detail": f"HTTP {exc.code}: {body or exc.reason}"}
    except Exception as exc:  # noqa: BLE001 - 失败原因如实回给设置面板
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    text = (result.get("content") or "").strip()[:80]
    return {"ok": True, "detail": f"连通成功：{text or '(空响应)'}"}


@router.get("/api/assistant/config")
async def assistant_config_get() -> dict[str, Any]:
    """当前生效配置（key 只给掩码）。"""
    config = load_config()
    saved = _read_config_file()
    env_set = bool((os.environ.get("FLOWWATCH_ASSISTANT_PROVIDER") or "").strip())
    return {
        "configured": config.configured,
        "provider": config.name if config.configured else "",
        "base_url": config.base_url,
        "model": config.model,
        "api_key_masked": "" if config.api_key in ("", "ollama") else _mask_key(config.api_key),
        "source": "file" if saved else ("env" if env_set else "none"),
        "config_path": str(CONFIG_PATH),
    }


@router.post("/api/assistant/config")
async def assistant_config_save(payload: ConfigIn) -> dict[str, Any]:
    """保存 UI 配置并立即生效（load_config 每次直读文件，无需重启服务）。"""
    provider = payload.provider
    api_key = _resolve_key(payload.api_key.strip())
    base_url = payload.base_url.strip().rstrip("/")
    model = payload.model.strip()
    if provider == "openai" and not (base_url and api_key and model):
        raise HTTPException(status_code=400,
                            detail="openai 模式需要填齐 Base URL / API Key / 模型名")
    if provider == "ollama":
        base_url = base_url or "http://127.0.0.1:11434/v1"
        model = model or "qwen2.5:7b"
    CONFIG_PATH.write_text(
        json.dumps({"provider": provider, "base_url": base_url,
                    "api_key": api_key, "model": model}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    config = load_config()
    return {"ok": True, "configured": config.configured, "provider_label": config.label}


@router.post("/api/assistant/config/test")
async def assistant_config_test(payload: ConfigIn) -> dict[str, Any]:
    """保存前试连：用表单里的候选配置发一句最小请求（不落盘）。"""
    config = _candidate(payload.provider, payload.base_url,
                        _resolve_key(payload.api_key.strip()), payload.model.strip())
    return await asyncio.to_thread(_ping, config)


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
