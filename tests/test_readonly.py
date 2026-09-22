#!/usr/bin/env python3
"""只读承诺的**静态审计** —— "助手调不到危险动作"这件事的代码级证据。

只读承诺分三层验（缺一层就只能叫"我们写了"）：
  · **静态（本文件）**：从每个工具出发做调用图分析，证明工具可达的代码里没有危险调用；
  · **结构（单测 + 评估集）**：历史库以 `ReadOnlyStore` 只读门面注入；执行前还有档位/记忆写硬闸；
  · **运行时（评估集）**：注入与越权用例、`done.fallback`/`origin=system` 这类可观测证据。

为什么用 AST 而不是 grep：采集层本来就要写库、要开 socket —— 关键不是"文件里有没有危险调用"，
而是"**这个危险调用在不在工具可达的路径上**"。所以这里按调用图判，而不是按文件判。

局限（如实说）：`getattr(obj, "app" + "end")()` 这类拼名字绕得过静态检查 → 所以运行时那层必须留着。
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import assistant  # noqa: E402

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

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
