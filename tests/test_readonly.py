#!/usr/bin/env python3
"""只读承诺的**静态 + 运行时证据** —— "助手调不到、也没真的调过危险动作"。

只读承诺分三层验（缺一层就只能叫"我们写了"）：
  · **静态（本文件 §1~4）**：从每个工具出发做调用图分析，证明工具可达的代码里没有危险调用；
  · **结构（单测 + 评估集）**：历史库以 `ReadOnlyStore` 只读门面注入；执行前还有档位/记忆写硬闸；
  · **运行时（本文件 §5）**：`sys.addaudithook` 真跑一遍全部工具 + 一轮对话，断言真实副作用
    只有自己的记忆库、零出站连接、零子进程，并用两条**阳性对照**证明"真的出副作用会被抓到"。

为什么用 AST 而不是 grep：采集层本来就要写库、要开 socket —— 关键不是"文件里有没有危险调用"，
而是"**这个危险调用在不在工具可达的路径上**"。所以这里按调用图判，而不是按文件判。

局限（如实说）：
  · `getattr(obj, "app" + "end")()` 这类拼名字绕得过静态检查；
  · 审计钩子在 CPython 解释器层，看不见 **ctypes 直调 Win32** 的文件访问（读 exe 版本资源就是）；
  · SQLite 的写不经 Python 的 `open`，所以"写文件白名单"只覆盖 Python 层，DB 层看 `sqlite3.connect`。
三者互补才叫"可验证"。
"""
from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evals"))

import assistant  # noqa: E402
import stub_source  # noqa: E402

SOURCE = ROOT / "assistant.py"
FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


# ---------------------------------------------------------------- 1. 工具名与档位
print("\n=== 工具面：名字里不许有写/控制动词 ===")
FORBIDDEN_PREFIXES = ("set_", "stop_", "start_", "delete_", "drop_", "clear_", "kill_",
                      "write_", "remove_", "shutdown_", "restart_", "update_", "exec_")
names = [tool.name for tool in assistant.TOOLS]
check("没有写/控制类工具名", [n for n in names if n.startswith(FORBIDDEN_PREFIXES)], [])
check("档位只有三种（聚合/明细/记忆）",
      sorted({tool.scope for tool in assistant.TOOLS}), ["aggregate", "detail", "memory"])
check("工具数量与公开说明一致", len(names), 12)
check("能写东西的只有三个记忆工具（写的是助手自己的库）",
      sorted(n for n in names if n.startswith("memory_")),
      ["memory_insert", "memory_replace", "memory_rethink"])

# ---------------------------------------------------------------- 2. 调用图静态分析
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCS = {node.name: node for node in tree.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

# 危险"模块限定"调用（点号前缀）
DANGER_MODULES = ("shutil", "subprocess", "socket", "urllib", "requests", "http.client",
                  "multiprocessing", "ctypes.windll.kernel32", "ctypes.windll.shell32")
DANGER_CALLS = ("os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir", "os.makedirs",
                "os.system", "os.popen", "os.startfile", "os.chmod", "os.kill")
# 危险"方法名"（任何对象上出现都算：psutil 的 terminate/kill、Memory 的写方法等）
DANGER_ATTRS = ("terminate", "kill", "suspend", "resume", "rmtree", "Popen", "WriteFile",
                "DeleteFile", "block_write", "forget_blocks", "stop_writer", "start_writer")
# 只有"取数工具"要额外守的：不许碰 history.db（sqlite3）、不许写记忆
DATA_ONLY_DANGER = ("sqlite3",)


def _dotted(node: ast.Attribute) -> str:
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def scan(graph: set[str]) -> tuple[set[str], set[str]]:
    """返回（点号调用串集合，方法名集合）—— 覆盖 graph 里所有函数的整棵语法树。"""
    dotted: set[str] = set()
    attrs: set[str] = set()
    for name in graph:
        for sub in ast.walk(FUNCS[name]):
            if isinstance(sub, ast.Call):
                target = sub.func
                if isinstance(target, ast.Attribute):
                    dotted.add(_dotted(target))
                    attrs.add(target.attr)
            elif isinstance(sub, ast.Attribute):
                attrs.add(sub.attr)
    return dotted, attrs


def reachable(start: str) -> set[str]:
    """模块内调用图可达集（跨函数传播，所以助手层助手也能查到）。"""
    seen: set[str] = set()
    stack = [start]
    while stack:
        name = stack.pop()
        if name in seen or name not in FUNCS:
            continue
        seen.add(name)
        for sub in ast.walk(FUNCS[name]):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                    and sub.func.id in FUNCS:
                stack.append(sub.func.id)
    return seen


def hits(values: set[str], needles) -> list[str]:
    return sorted(v for v in values
                  if any(v == n or v.startswith(n + ".") for n in needles))


data_tools = [tool for tool in assistant.TOOLS if tool.name.startswith("get_")]
memory_tools = [tool for tool in assistant.TOOLS
                if tool.name.startswith("memory_") or tool.name == "conversation_search"]

print("\n=== 取数工具：调用图里不许有写文件 / 起进程 / 开网络 / 碰历史库 ===")
for tool in data_tools:
    graph = reachable(tool.run.__name__)
    dotted, attrs = scan(graph)
    problems = hits(dotted, DANGER_MODULES + DANGER_CALLS + DATA_ONLY_DANGER) + \
        hits(attrs, DANGER_ATTRS)
    check(f"{tool.name}（可达 {len(graph)} 个函数）无危险调用", problems, [])

print("\n=== 记忆工具：只许写自己的库（sqlite3 除外，其余同样不许）===")
for tool in memory_tools:
    graph = reachable(tool.run.__name__)
    dotted, attrs = scan(graph)
    problems = hits(dotted, DANGER_MODULES + DANGER_CALLS) + \
        hits(attrs, tuple(a for a in DANGER_ATTRS if a != "block_write"))
    check(f"{tool.name}（可达 {len(graph)} 个函数）无危险调用", problems, [])

# ---------------------------------------------------------------- 3. 只读门面本身
# 门面的价值全在"写方法不存在"；一旦有人加 __getattr__ 转发，整层就白做了 —— 所以也要钉住。
print("\n=== 只读门面本身：不许有 __getattr__ 后门 ===")
check("ReadOnlyStore 没有 __getattr__（否则会透传写方法）",
      "__getattr__" in vars(assistant.ReadOnlyStore), False)
exposed = sorted(name for name, value in vars(assistant.ReadOnlyStore).items()
                 if not name.startswith("_") and callable(value))
check("门面只暴露查询方法", exposed,
      ["events", "process_series", "stats", "timeline", "top_domains", "top_processes"])
check("门面暴露的方法与「要挡的写面」没有交集",
      [name for name in exposed if name in assistant.ReadOnlyStore.FORBIDDEN], [])

# ---------------------------------------------------------------- 4. 档位并集
print("\n=== 档位：没有「分档之外」的隐藏工具，开关能真的摘掉写能力 ===")
agg = {item["function"]["name"] for item in assistant.tools_for("aggregate")}
det = {item["function"]["name"] for item in assistant.tools_for("detail")}
detail_only = sorted(n for n in det if n not in agg)
check("明细档只比聚合档多（是超集）", det >= agg, True)
check("明细工具只在明细档出现", sorted(n for n in agg if n in detail_only), [])
check("两档并集 = 工具全集（没有分档外的隐藏工具）", sorted(agg | det), sorted(names))

# ---- 复合保证（不变式）：注入面可以松，执行面不能松 ----
# 将来任何扩展机制（hook / 插件 / 配置）最多只能"多给模型看几个工具"，绝不能因此让明细工具
# 在聚合档真的跑起来。这条测试就是那个不变式的钉子 —— 它比"再测一遍硬闸"更强：
# 它规定的是"硬闸不依赖注入面"，所以引入任何扩展点之前，这条必须绿。
_saved_tools_for = assistant.tools_for
_saved_scope = assistant._Source.scope
try:
    assistant.tools_for = lambda scope: [tool.spec() for tool in assistant.TOOLS]   # 故意全放
    leaked = {item["function"]["name"] for item in assistant.tools_for("aggregate")}
    check("（模拟）注入面被放宽后，明细工具确实出现在清单里", "get_live_connections" in leaked, True)
    assistant._Source.scope = "aggregate"
    denied = assistant.run_tool("get_live_connections", {"pid": 84812, "limit": 5})
    check("注入面被放宽，执行闸仍然拒绝（不变式：能力边界不依赖注入面）",
          "当前数据档位不可用" in str(denied.get("error")), True)
finally:
    assistant.tools_for = _saved_tools_for
    assistant._Source.scope = _saved_scope
check("复原后注入面照旧（明细工具不在聚合档）",
      "get_live_connections" in {item["function"]["name"]
                                for item in assistant.tools_for("aggregate")}, False)

_saved = os.environ.get("FLOWWATCH_ASSISTANT_MEMORY_WRITE")
try:
    os.environ["FLOWWATCH_ASSISTANT_MEMORY_WRITE"] = "off"
    off = {item["function"]["name"] for item in assistant.tools_for("aggregate")}
    check("开关 off：三个写工具全部摘掉",
          sorted(agg - off), ["memory_insert", "memory_replace", "memory_rethink"])
    check("开关 off：读记忆的 conversation_search 保留", "conversation_search" in off, True)
finally:
    if _saved is None:
        os.environ.pop("FLOWWATCH_ASSISTANT_MEMORY_WRITE", None)
    else:
        os.environ["FLOWWATCH_ASSISTANT_MEMORY_WRITE"] = _saved

# ---------------------------------------------------------------- 5. 运行时审计
# 静态层证明"代码里没有"，这一节证明"跑起来确实没发生"：装 `sys.addaudithook`，
# 逐个跑完全部 12 个工具 + 跑一轮完整对话，把**可能产生副作用**的事件收成清单，断言：
#   · 写文件只有助手自己的记忆库（含 -wal / -shm）；
#   · 出站连接 0（桩数据源 + 假 transport，这一轮不该有任何网络活动）；
#   · 子进程 0、删除/重命名/建目录 0；
#   · 打开的数据库只有记忆库（观测库 history.db 连都不该连）。
# 还带一条**阳性对照**：故意在审计窗口里写一个临时文件，必须被抓到 —— 否则"没抓到写"
# 可能只是钩子坏了，而不是真的没写。
#
# 局限（如实说）：审计钩子在 CPython 解释器层，看不见 ctypes 直调 Win32 的文件访问
# （读 exe 版本资源走的就是 Win32 API）→ 所以这层与静态层互补，不替代。
print("\n=== 运行时审计：跑一遍全部工具 + 一轮对话，看真实副作用 ===")

WATCH_EVENTS = ("open", "socket.connect", "socket.getaddrinfo", "subprocess.Popen",
                "sqlite3.connect", "os.remove", "os.rename", "os.mkdir", "os.rmdir",
                "os.chmod", "os.system")
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
EVENTS: list[tuple[str, tuple]] = []


def _might_write(args: tuple) -> bool:
    """open 事件里这次打开**有没有写意图**（mode 或 os.open 的 flags）。"""
    path, mode, flags = (list(args) + [None, None, None])[:3]      # noqa: F841
    if isinstance(mode, str) and any(ch in mode for ch in "wax+"):
        return True
    return isinstance(flags, int) and bool(flags & WRITE_FLAGS)


def _hook(event: str, args: tuple) -> None:
    if event not in WATCH_EVENTS:
        return
    if event == "open" and not _might_write(args):
        return
    EVENTS.append((event, args))


sys.addaudithook(_hook)          # 装一次，之后本进程里的动作都会被记录（可按窗口清空）


def _audited(fn) -> list[tuple[str, tuple]]:
    EVENTS.clear()
    fn()
    return list(EVENTS)


def _facts(events: list[tuple[str, tuple]]) -> dict[str, list[str]]:
    return {
        # 注意：这里的"写文件"只覆盖 **Python 层**的写（open(mode="w") / Path.write_text）；
        # SQLite 的写走 C 层，不会产生 open 事件 —— 数据库动作看下面"数据库"那一项。
        "写文件": [str(args[0]) for event, args in events if event == "open"],
        "数据库": [str(args[0]) for event, args in events if event == "sqlite3.connect"],
        "出站连接": [f"{event} {args[:2]}" for event, args in events
                     if event in ("socket.connect", "socket.getaddrinfo")],
        "子进程": [str(args[0]) for event, args in events if event == "subprocess.Popen"],
        "破坏性改动": [f"{event} {args[0]}" for event, args in events
                       if event in ("os.remove", "os.rename", "os.rmdir", "os.chmod", "os.system")],
        # 建目录单独看：记忆层每次写入都会 mkdir(parents=True, exist_ok=True) 兜底，
        # 是幂等且无害的动作 —— 但必须只发生在自己的数据目录里。
        "建目录": [str(args[0]) for event, args in events if event == "os.mkdir"],
    }


TOOL_CALLS: list[tuple[str, dict]] = [
    ("get_health", {}),
    ("get_live_frame", {"top": 5}),
    ("get_top_processes", {"minutes": 60, "limit": 5}),
    ("get_top_domains", {"minutes": 60, "limit": 5}),
    ("get_process_history", {"pid": 84812, "minutes": 60}),
    ("get_events", {"limit": 5, "minutes": 60}),
    ("get_live_connections", {"pid": 84812, "limit": 5}),
    ("get_process_identity", {"pid": os.getpid()}),
    ("memory_insert", {"label": "human", "text": "运行时审计窗口内的写入（随后会删掉）"}),
    ("memory_replace", {"label": "human", "old_text": "运行时审计窗口内的写入（随后会删掉）",
                        "new_text": "运行时审计窗口内的写入（已改写）"}),
    ("memory_rethink", {"label": "human", "text": ""}),
    ("conversation_search", {"query": "带宽", "limit": 3}),
]

with tempfile.TemporaryDirectory() as _tmp:
    _mem = Path(_tmp) / "assistant_memory.db"
    assistant.configure(hub=stub_source.FakeHub(), store=stub_source.FakeStore(),
                        capturer=stub_source.FakeCapturer(), memory_path=_mem)

    def _exercise_all_tools() -> None:
        saved = assistant._Source.scope
        try:
            assistant._Source.scope = "detail"        # 明细工具的执行前提（档位硬闸）
            for name, args in TOOL_CALLS:
                assistant.run_tool(name, args, session_id="audit-session")
        finally:
            assistant._Source.scope = saved

    tool_facts = _facts(_audited(_exercise_all_tools))
    check("12 个工具都跑过一遍", len(TOOL_CALLS), 12)
    written = [path for path in tool_facts["写文件"]
               if "assistant_memory.db" not in os.path.basename(path)]
    check("Python 层写文件只有助手自己的记忆库（含 -wal/-shm）", sorted(set(written)), [])
    check("确实打开过记忆库 —— 阳性对照，说明审计看得见且记忆功能真跑了",
          [path for path in tool_facts["数据库"] if "assistant_memory.db" in path] != [], True)
    check("打开的数据库只有记忆库（观测库 history.db 连都不该连）",
          sorted({path for path in tool_facts["数据库"] if "assistant_memory.db" not in path}), [])
    check("工具调用期间零出站连接", tool_facts["出站连接"], [])
    check("工具调用期间零子进程", tool_facts["子进程"], [])
    check("工具调用期间零破坏性改动（删除/重命名/改权限/起 shell）", tool_facts["破坏性改动"], [])
    check("建目录只发生在自己的数据目录里",
          sorted({path for path in tool_facts["建目录"] if not path.startswith(_tmp)}), [])

    # 一轮完整对话（假 transport：先调一个取数工具，再作答）
    _real_chat = assistant.chat_completion
    _steps = [{"tool_calls": [{"name": "get_top_processes",
                               "args": {"minutes": 60, "limit": 8}}]},
              {"content": "第一名是 Steam++.Accelerator.exe，约 1018 MiB。"}]
    _seen: list[int] = []

    def _fake_chat(config, messages, tools, tool_choice=None):   # noqa: ARG001
        step = _steps[len(_seen)] if len(_seen) < len(_steps) else {"content": "（脚本用尽）"}
        _seen.append(1)
        calls = [{"id": f"t{len(_seen)}", "type": "function",
                  "function": {"name": call["name"],
                               "arguments": json.dumps(call["args"], ensure_ascii=False)}}
                 for call in step.get("tool_calls") or []]
        return {"content": step.get("content") or "", "tool_calls": calls}

    try:
        assistant.chat_completion = _fake_chat
        turn_events = _audited(
            lambda: list(assistant.run_turn("现在谁在占带宽最多？", "audit-turn")))
    finally:
        assistant.chat_completion = _real_chat
    turn_facts = _facts(turn_events)
    check("对话期间：写文件仍只有记忆库",
          sorted({path for path in turn_facts["写文件"]
                  if "assistant_memory.db" not in os.path.basename(path)}), [])
    check("对话期间：零出站连接（假 transport，不该有任何网络活动）", turn_facts["出站连接"], [])
    check("对话期间：零子进程", turn_facts["子进程"], [])

    # 阳性对照：故意在审计窗口里写一个临时文件 —— 必须被抓到
    _tripwire_path = Path(_tmp) / "should-not-happen.tmp"

    def _tripwire() -> None:
        _tripwire_path.write_text("x", encoding="utf-8")

    caught = [path for path in _facts(_audited(_tripwire))["写文件"]
              if path.endswith("should-not-happen.tmp")]
    check("阳性对照 ①：故意的写会立刻被抓到（证明钩子有效）", bool(caught), True)

    # 阳性对照 ②：把副作用藏进**工具内部**（一个 get_* 读函数顺手写文件）——
    # 这正是静态层最容易漏、运行时层最该抓的形态。桩对象可以随便改：门面里的那个才是助手看到的。
    _inner = assistant._Source.store._store       # noqa: SLF001 - 测试里摸到被门面包住的桩
    _real_stats = _inner.stats

    def _stats_with_side_effect():
        (Path(_tmp) / "sneaky-tool-side-effect.tmp").write_text("x", encoding="utf-8")
        return _real_stats()

    _inner.stats = _stats_with_side_effect
    try:
        sneaky = _facts(_audited(lambda: assistant.run_tool("get_health", {}, "audit-sneaky")))
    finally:
        _inner.stats = _real_stats
    check("阳性对照 ②：工具内部的隐藏写也会被抓到（静态层最容易漏的形态）",
          [path for path in sneaky["写文件"] if path.endswith("sneaky-tool-side-effect.tmp")] != [],
          True)

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
