"""assistant.py 单元测试：工具分级、难度路由、分层记忆、mock 链路、provider 配置。

不需要网络、不需要真实模型、不碰真库 —— 数据源全部 stub 注入，记忆写到临时文件。
要钉死的三件事：
  1. **聚合档下明细工具不可见**（隐私靠物理隔离，不靠提示词）；
  2. **记忆块按 Letta 的 Prompt ABI 渲染**（label/description/value + 容量元数据）；
  3. **压缩只标记不删除** —— 摘要漂移后还能用 conversation_search 回到原文。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import assistant  # noqa: E402

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


# ---------------------------------------------------------------- stub 数据源

def _proc_row(pid: int, process: str, total: int) -> dict:
    return {
        "pid": pid, "process": process, "total_bytes": total,
        "out_bytes": total * 9 // 10, "in_bytes": total // 10,
        "first_seen": "2026-09-19T08:45:00", "last_seen": "2026-09-19T11:30:00",
    }


class FakeStore:
    """假历史层。Doubao.exe 故意给两个 pid —— 模拟 Electron 那种"一个应用十几个进程"，
    09-20 事故正是"小写 doubao 没命中 Doubao.exe"，这里用来钉死 match 的语义。"""

    def stats(self) -> dict:
        return {"retention_days": 30, "oldest": "2026-09-17T08:00:00", "buckets": 11, "events": 3}

    def top_processes(self, minutes: int = 60, limit: int = 10,
                      match: str | None = None, group: bool = False) -> list[dict]:
        rows = [_proc_row(84812, "Steam++.Accelerator.exe", 1067797993),
                _proc_row(50164, "Doubao.exe", 14093555),
                _proc_row(50304, "Doubao.exe", 6318897)]
        if match:
            rows = [row for row in rows if match.lower() in row["process"].lower()]
        elif not group:
            return rows[:limit]
        merged: dict[str, dict] = {}
        for row in rows:
            key = row["process"].lower()
            if key in merged:
                merged[key]["total_bytes"] += row["total_bytes"]
                merged[key]["pid_count"] += 1
            else:
                merged[key] = {**row, "pid_count": 1}
        ordered = sorted(merged.values(), key=lambda item: item["total_bytes"], reverse=True)
        return ordered[:limit]

    def top_domains(self, minutes: int = 60, limit: int = 10, named_only: bool = False,
                    match: str | None = None) -> list[dict]:
        rows = [{"name": "10.44.99.5", "kind": "ip", "total_bytes": 976000000, "conns": 79275},
                {"name": "logifier.doubao.com", "kind": "sni", "total_bytes": 23051911, "conns": 42}]
        if match:
            rows = [row for row in rows if match.lower() in row["name"].lower()]
        return rows[:limit]

    def process_series(self, pid: int, minutes: int = 60, bucket_minutes: int = 1) -> dict:
        if pid != 84812:
            return {}
        return {
            "pid": pid, "process": "Steam++.Accelerator.exe",
            "bucket_seconds": bucket_minutes * 60, "total_bytes": 1067797993, "peak_bps": 303453,
            "first_seen": "2026-09-19T08:45:00", "last_seen": "2026-09-19T11:30:00",
            "series": [
                {"ts": f"2026-09-19T{8 + i // 4:02d}:{(i % 4) * 15:02d}:00",
                 "out_bps": 1000.0 * i, "in_bps": 100.0, "bytes": 0, "packets": 0}
                for i in range(12)
            ],
        }

    def events(self, limit: int = 20, pid: int | None = None,
               match: str | None = None, minutes: int | None = None) -> list[dict]:
        items = [{"ts": "2026-09-20T09:53:00", "kind": "vanish", "pid": 50164,
                  "process": "Doubao.exe", "detail": "连续 3 分钟无流量"},
                 {"ts": "2026-09-19T11:12:00", "kind": "vanish", "pid": 84812,
                  "process": "Steam++.Accelerator.exe", "detail": "连续 3 分钟无流量"}]
        if pid is not None:
            items = [item for item in items if item["pid"] == pid]
        if match:
            items = [item for item in items if match.lower() in item["process"].lower()]
        return items[:limit]


class FakeHub:
    latest = {
        "ts": "2026-09-19T11:32:01", "window": 1.0,
        "totals": {"out_bps": 131518.0, "in_bps": 1702.0, "unknown_ratio_rolling": 0.01,
                   "unknown_ratio": 0.0, "masked_bytes": 0, "foreign_packets": 0,
                   "skipped_packets": 0, "packets": 10, "bytes": 1000, "packets_window": 10,
                   "unknown_bytes_window": 0, "masked_ratio_rolling": 0.0, "rolling_windows": 60},
        "domains": [{"name": "10.44.99.5", "kind": "ip", "out_bytes": 900, "in_bytes": 10, "conns": 3}],
        "unknown_flows": [],
        "by_pid": [
            {"pid": 84812, "process": "Steam++.Accelerator.exe", "out_bps": 900.0, "in_bps": 100.0,
             "packets": 10,
             "conns": [{"remote": "10.44.99.5:49716", "name": None, "name_source": None,
                        "out_bps": 800.0, "in_bps": 0.0}]}
        ],
    }


class FakeCapturer:
    device_name = "\\Device\\NPF_TEST"
    error = None
    refresh_error = None
    aggregator = type("Agg", (), {"stats": staticmethod(lambda: {"packets": 12345678})})()
    resolver = type("Res", (), {"stats": staticmethod(
        lambda: {"dns_records": 100, "sni_records": 50, "hit_ratio": 0.38})})()


assistant.configure(hub=FakeHub(), store=FakeStore(), capturer=FakeCapturer())

# ---------------------------------------------------------------- 1. 难度路由
print("\n=== 题目难度 → 数据档位 ===")
check("排行问题走聚合档", assistant.route_scope("现在谁占带宽最多"), "aggregate")
check("域名问题走聚合档", assistant.route_scope("近一小时访问了哪些域名"), "aggregate")
check("问对端升明细档", assistant.route_scope("Steam++ 连了谁"), "detail")
check("问具体 IP 升明细档", assistant.route_scope("它在和哪个 IP 通信"), "detail")
check("问端口升明细档", assistant.route_scope("看下它的端口明细"), "detail")

# ---------------------------------------------------------------- 2. 工具分级
print("\n=== 工具分级：物理隔离 + 记忆工具常驻 ===")
agg = {item["function"]["name"] for item in assistant.tools_for("aggregate")}
det = {item["function"]["name"] for item in assistant.tools_for("detail")}
check("聚合档不含明细工具", "get_live_connections" in agg, False)
check("明细档才给明细工具", "get_live_connections" in det, True)
check("记忆工具两档都在", {"memory_insert", "memory_replace", "memory_rethink",
                            "conversation_search"} <= agg, True)
check("明细档 = 聚合档 + 1", len(det), len(agg) + 1)
schema = next(item for item in assistant.tools_for("aggregate")
              if item["function"]["name"] == "get_top_processes")["function"]["parameters"]
check("schema 由 Pydantic 生成（无 title 噪声）", "title" in schema, False)
check("schema 带上参数约束", schema["properties"]["limit"]["maximum"], 20)
check("description 取自 docstring", "区间内按累计字节排行" in
      next(item for item in assistant.tools_for("aggregate")
           if item["function"]["name"] == "get_top_processes")["function"]["description"], True)

# ---------------------------------------------------------------- 3. 工具执行
print("\n=== 工具执行：参数校验失败回给模型，而不是抛异常 ===")
check("正常调用", assistant.run_tool("get_live_frame", {"top": 3})["top_processes"][0]["pid"], 84812)
bad = assistant.run_tool("get_top_processes", {"minutes": 999999})
check("越界参数被 Pydantic 拦住", bad["error"], "参数不合法")
check("错误里带可读细节", len(bad["details"]) >= 1, True)
check("类型错误同样被拦", assistant.run_tool("get_events", {"limit": "abc"})["error"], "参数不合法")
check("未知工具不炸", "error" in assistant.run_tool("nope", {}), True)

found = assistant.run_tool("get_top_processes", {"match": "doubao"})       # 用户就是敲的小写
check("match 不区分大小写：小写 doubao 命中 Doubao.exe", found["matched"], True)
check("match 结果按进程名合并", found["items"][0]["process"], "Doubao.exe")
check("match 给出被合并的 pid 数", found["items"][0]["pid_count"], 2)
check("match 生效时标注这是全量检索", "全量" in found["note"], True)
missing = assistant.run_tool("get_top_processes", {"match": "no-such-app"})
check("match 未命中给 matched=false", missing["matched"], False)
check("未命中时挡住'进程不存在'的结论", "不等于进程没在跑" in missing["hint"], True)
dom = assistant.run_tool("get_top_domains", {"match": "DOUBAO"})
check("域名 match 同样不区分大小写", dom["items"][0]["name"], "logifier.doubao.com")

events = assistant.run_tool("get_events", {"match": "doubao", "minutes": 60})
check("事件可按进程名检索（问'某应用有没有异常'的正路）",
      [item["process"] for item in events["items"]], ["Doubao.exe"])
no_event = assistant.run_tool("get_events", {"match": "no-such-app", "minutes": 60})
check("查不到事件时提醒'没有事件 ≠ 没有流量'", "没有事件 ≠ 没有流量" in no_event["note"], True)
check("事件条数与截断标记", assistant.run_tool("get_events", {"limit": 1})["truncated"], True)
no_window = assistant.run_tool("get_events", {"limit": 5})
check("没给时间窗时提示要带上 minutes", "minutes" in no_window["note"], True)
check("明细工具能取对端",
      assistant.run_tool("get_live_connections", {"pid": 84812})["connections"][0]["remote"],
      "10.44.99.5:49716")

# 进程身份：读 exe 版本资源（厂商/产品），路径按档位隔离 —— 用测试进程自己当样本
check("身份工具在聚合档可见", "get_process_identity" in agg, True)
identity = assistant.run_tool("get_process_identity", {"pid": os.getpid()})
check("能读到测试进程的身份", identity["pid"], os.getpid())
check("聚合档不出完整路径（字段级隔离）", "path" in identity, False)
check("聚合档说明路径的分级规则", "path_note" in identity, True)
check("身份字段齐全（值可为空，键必须在）",
      all(key in identity for key in ("company", "product", "description", "version")), True)
assistant._Source.scope = "detail"
detailed = assistant.run_tool("get_process_identity", {"pid": os.getpid()})
check("明细档才给完整路径且路径真实存在", os.path.exists(str(detailed.get("path"))), True)
assistant._Source.scope = "aggregate"
unknown = assistant.run_tool("get_process_identity", {"match": "no-such-app"})
check("只知道名字时先按名找 pid", unknown["found"], False)
check("按名找不到时别断言进程不存在", "不等于进程没在运行" in unknown["hint"], True)
check("pid 与 match 都不给就报错",
      "error" in assistant.run_tool("get_process_identity", {}), True)

# ---------------------------------------------------------------- 4. 分层记忆
print("\n=== 分层记忆：Prompt ABI / 容量契约 / 压缩保留证据 ===")
with tempfile.TemporaryDirectory() as tmp:
    memory = assistant.Memory(Path(tmp) / "mem.db")
    rendered = memory.render_blocks()
    check("渲染成 memory_blocks 结构", rendered.startswith("<memory_blocks>"), True)
    check("块带头部描述", "<description>" in rendered, True)
    check("渲染容量元数据（Letta 的预算契约）",
          ("chars_current=0" in rendered and "chars_limit=1200" in rendered), True)
    check("三个默认块都在", all(f"<{label}>" in rendered for label in ("human", "watchlist", "findings")),
          True)

    check("写入块", memory.block_write("human", "用户关注本机流量异常")["ok"], True)
    check("追加后可读回", "用户关注" in memory.block_value("human"), True)
    check("未知名块被拒", "error" in memory.block_write("nope", "x"), True)
    check("超容量被拒（契约执行侧）", "error" in memory.block_write("human", "长" * 1300), True)

    # 会话消息 + 压缩
    session = "s1"
    for i in range(40):
        memory.append(session, "user", f"问题 {i}")
        memory.append(session, "assistant", f"回答 {i}", scope="aggregate")
    before = memory.state()
    check("压缩前消息数", before["messages"], 80)
    check("超过阈值触发压缩", memory.compact(session), True)
    after = memory.state()
    check("压缩不改消息总数（只标记，不销毁证据）", after["messages"], before["messages"])
    check("被标记为已压缩", after["compacted"] > 0, True)
    check("活跃上下文只剩最近 10 条", len(memory.history(session, 100)), 10)
    check("摘要记下了早先提问", "问:问题 0" in memory.summary(session), True)
    hits = memory.conversation_search(session, "问题 2")
    check("能检索到已压缩的原文（对抗摘要漂移）", len(hits) > 0, True)
    check("检索结果标出 compacted", any(item["compacted"] for item in hits), True)
    check("摘要长度有上限", len(memory.summary(session)) <= 2400, True)

    memory.forget_blocks()
    check("忘掉长期记忆后块清空", memory.block_value("human"), "")

# ---------------------------------------------------------------- 5. 记忆工具
print("\n=== 记忆工具：insert / replace / rethink ===")
with tempfile.TemporaryDirectory() as tmp:
    assistant.configure(memory_path=Path(tmp) / "tools.db")
    sid = "mt"
    assistant.run_tool("memory_insert", {"label": "watchlist", "text": "盯 Steam++.Accelerator.exe"}, sid)
    check("insert 写入成功", "Steam++" in assistant.MEMORY.block_value("watchlist"), True)
    assistant.run_tool("memory_insert", {"label": "watchlist", "text": "盯 10.44.99.5"}, sid)
    replaced = assistant.run_tool(
        "memory_replace",
        {"label": "watchlist", "old_text": "盯 10.44.99.5", "new_text": "已解释：10.44.99.5 是本机 IP"},
        sid,
    )
    check("replace 精确替换成功", replaced.get("ok"), True)
    check("替换结果可读", "已解释" in assistant.MEMORY.block_value("watchlist"), True)
    check("replace 找不到原文时拒绝",
          "error" in assistant.run_tool("memory_replace",
                                        {"label": "watchlist", "old_text": "不存在的片段"}, sid), True)
    assistant.MEMORY.block_write("watchlist", "重复片段 重复片段")
    check("replace 不唯一时拒绝（乐观语义选择器）",
          "error" in assistant.run_tool("memory_replace",
                                        {"label": "watchlist", "old_text": "重复片段"}, sid), True)
    check("rethink 整块重写",
          assistant.run_tool("memory_rethink", {"label": "watchlist", "text": "只剩一条"}, sid)["ok"], True)
    check("重写后内容干净", assistant.MEMORY.block_value("watchlist"), "只剩一条")
    dup = assistant.run_tool("memory_insert", {"label": "watchlist", "text": "只剩一条"}, sid)
    check("重复内容被拒（块每轮都注入，重复只会灌水）", dup["ok"], False)
    check("拒绝时回当前块内容供自查", dup["current"], "只剩一条")
    fresh = assistant.run_tool(
        "memory_insert", {"label": "findings", "text": "2026-09-20 doubao 上行以日志上报为主"}, sid)
    check("写入成功后回读整块", fresh["current"].endswith("日志上报为主"), True)
    check("空 text 被拒",
          "error" in assistant.run_tool("memory_insert", {"label": "findings", "text": "   "}, sid),
          True)
    check("块参数缺失被拒", assistant.run_tool("memory_rethink", {"label": "watchlist"})["error"],
          "参数不合法")

# ---------------------------------------------------------------- 6. mock 链路
print("\n=== mock provider：真跑工具、真读数、明确标注 ===")
trace: list[dict] = []
answer = assistant.mock_turn("现在谁在占带宽？近一小时排行", "aggregate", trace)
check("mock 明确标注自己不是模型", "mock 模式" in answer["content"], True)
check("mock 真的调了工具", len(trace) > 0, True)
check("mock 输出带真实进程名", "Steam++.Accelerator.exe" in answer["content"], True)

# ---------------------------------------------------------------- 7. provider 配置
print("\n=== provider 配置读取 ===")
saved = {k: os.environ.get(k) for k in (
    "FLOWWATCH_ASSISTANT_PROVIDER", "FLOWWATCH_ASSISTANT_BASE_URL",
    "FLOWWATCH_ASSISTANT_API_KEY", "FLOWWATCH_ASSISTANT_MODEL")}
# 隔离两个外部配置源：load_config 的优先级是 文件 > 环境变量 > .env，
# 开发机上真实存在的配置会压过下面所有 setenv（CI 上没这些文件，所以这个坑只在本地暴露）：
#   ① assistant_config.json（UI 保存的模型配置）→ 指向一个不存在的路径；
#   ② 项目 .env（首启会注入缺失的环境变量）→ 标记为"已加载"阻断它。
# 恢复放在第 8 段之后：端到端那轮同样要隔离，否则会用真实 provider 真发请求。
_saved_config_path = assistant.CONFIG_PATH
_saved_env_loaded = assistant._ENV_FILE_LOADED
assistant.CONFIG_PATH = Path(tempfile.gettempdir()) / "flowwatch-no-such-config.json"
assistant._ENV_FILE_LOADED = True
try:
    os.environ.pop("FLOWWATCH_ASSISTANT_PROVIDER", None)
    check("未配置时 provider=none", assistant.load_config().name, "none")
    os.environ["FLOWWATCH_ASSISTANT_PROVIDER"] = "mock"
    check("mock 模式可用", assistant.load_config().configured, True)
    os.environ["FLOWWATCH_ASSISTANT_PROVIDER"] = "openai"
    check("openai 缺 key 视为未配置", assistant.load_config().configured, False)
    os.environ.update({"FLOWWATCH_ASSISTANT_BASE_URL": "https://example.com/v1/",
                       "FLOWWATCH_ASSISTANT_API_KEY": "sk-test",
                       "FLOWWATCH_ASSISTANT_MODEL": "test-model"})
    cfg = assistant.load_config()
    check("openai 配齐后可用", (cfg.name, cfg.base_url, cfg.model),
          ("openai", "https://example.com/v1", "test-model"))
    os.environ["FLOWWATCH_ASSISTANT_PROVIDER"] = "ollama"
    os.environ.pop("FLOWWATCH_ASSISTANT_MODEL", None)
    check("ollama 默认本机 11434", assistant.load_config().base_url, "http://127.0.0.1:11434/v1")
finally:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

# ---------------------------------------------------------------- 8. 端到端一轮
print("\n=== run_turn 事件流（含记忆注入与写回）===")
with tempfile.TemporaryDirectory() as tmp:
    assistant.configure(memory_path=Path(tmp) / "turn.db")
    os.environ["FLOWWATCH_ASSISTANT_PROVIDER"] = "mock"
    try:
        events = list(assistant.run_turn("现在谁在占带宽？", "turn-session"))
    finally:
        os.environ.pop("FLOWWATCH_ASSISTANT_PROVIDER", None)
    names = [name for name, _ in events]
    check("首事件是 meta", names[0], "meta")
    check("末事件是 done", names[-1], "done")
    check("中间有工具事件", "tool" in names, True)
    tool_event = dict(events)["tool"]
    check("工具事件带人话描述", bool(tool_event.get("effect")), True)
    done = dict(events)["done"]
    check("done 带数据档位", done["scope"], "aggregate")
    check("done 报告记忆状态", "blocks" in done["memory"], True)
    check("问答都写进了记忆", len(assistant.MEMORY.history("turn-session", 5)), 2)

# ---------------------------------------------------------------- 9. 零工具调用兜底
# 09-20 线上事故：模型一次工具都没调，却编出"我查了实时帧/排行/事件都没有"整段结论，
# 服务端当时原样采信。现在：首轮零工具调用且问题要本机数据 → 强制纠正一轮；
# 纠正后仍无证据 → 给结论打上"未核实"标注，并在 done 里暴露 grounded/retried。
print("\n=== 零工具调用兜底：先纠正一轮，再决定是否采信 ===")
check("数据类问题要证据", assistant.needs_evidence("doubao发送和接收的是心跳包吗"), True)
check("光一个进程名也算数据类", assistant.needs_evidence("Doubao.exe"), True)
check("纯概念问题不强制", assistant.needs_evidence("什么是 TCP 三次握手"), False)

_real_chat = assistant.chat_completion
_ground_saved = {k: os.environ.get(k) for k in (
    "FLOWWATCH_ASSISTANT_PROVIDER", "FLOWWATCH_ASSISTANT_BASE_URL",
    "FLOWWATCH_ASSISTANT_API_KEY", "FLOWWATCH_ASSISTANT_MODEL")}
try:
    os.environ.update({"FLOWWATCH_ASSISTANT_PROVIDER": "openai",
                       "FLOWWATCH_ASSISTANT_BASE_URL": "https://example.com/v1/",
                       "FLOWWATCH_ASSISTANT_API_KEY": "sk-test",
                       "FLOWWATCH_ASSISTANT_MODEL": "test-model"})
    with tempfile.TemporaryDirectory() as tmp:
        assistant.configure(memory_path=Path(tmp) / "ground.db")

        tries = {"n": 0}
        lazy_prompts: list[str] = []
        lazy_draft = "查不到 doubao 进程，我扫了排行榜和事件流都没有。"

        def lazy_chat(config, messages, tools):
            tries["n"] += 1
            lazy_prompts.append("\n".join(str(item.get("content")) for item in messages))
            return {"content": lazy_draft, "tool_calls": []}

        assistant.chat_completion = lazy_chat
        events = list(assistant.run_turn("doubao发送和接收的是心跳包吗", "lazy-session"))
        done = dict(events)["done"]
        check("零工具调用会补一轮（共 2 次模型往返）", tries["n"], 2)
        check("纠正后仍无证据 → 标注未核实", done["text"].startswith("⚠️"), True)
        check("done 暴露证据标志", (done["grounded"], done["retried"]), (False, True))
        check("未核实的回答也照实写进记忆", "⚠️" in assistant.MEMORY.history("lazy-session", 5)[-1]["content"],
              True)
        check("作废的草稿不回灌上下文（否则终稿会自我检讨）",
              lazy_draft in lazy_prompts[1], False)

        tries2 = {"n": 0}

        def lazy_then_grounded(config, messages, tools):
            tries2["n"] += 1
            if tries2["n"] == 1:
                return {"content": "不清楚。", "tool_calls": []}
            if tries2["n"] == 2:
                return {"content": "", "tool_calls": [{
                    "id": "c1",
                    "function": {"name": "get_top_processes",
                                 "arguments": json.dumps({"match": "doubao"})}}]}
            return {"content": "Doubao.exe 近 60 分钟有流量：两个进程合计约 20.4 MiB。",
                    "tool_calls": []}

        assistant.chat_completion = lazy_then_grounded
        events2 = list(assistant.run_turn("doubao发送和接收的是心跳包吗", "grounded-session"))
        done2 = dict(events2)["done"]
        check("纠正后模型调了工具", "get_top_processes" in done2["tools"], True)
        check("纠正后不再标注未核实", done2["text"].startswith("⚠️"), False)
        check("证据标志为真", (done2["grounded"], done2["retried"]), (True, True))
        check("工具执行事件照常推给前端", "tool" in [name for name, _ in events2], True)
        check("追问也走了 match 检索", "Doubao.exe" in done2["text"], True)

        # ③ 只调记忆工具 = 假证据：它读不出任何本机数据，照样要标"未核实"
        tries3 = {"n": 0}

        def memory_only(config, messages, tools):
            tries3["n"] += 1
            if tries3["n"] == 1:
                return {"content": "", "tool_calls": [{
                    "id": "m1",
                    "function": {"name": "memory_insert",
                                 "arguments": json.dumps({"label": "findings",
                                                          "text": "doubao 的心跳占 62% 出向带宽"})}}]}
            return {"content": "doubao 的心跳占了大部分上行带宽。", "tool_calls": []}

        assistant.chat_completion = memory_only
        events3 = list(assistant.run_turn("doubao 的心跳占多少带宽？", "memory-only-session"))
        done3 = dict(events3)["done"]
        check("记忆工具不算数据证据", done3["evidence_tools"], [])
        check("只写记忆却答数据 → 标注未核实", done3["text"].startswith("⚠️"), True)
        check("grounded 按取数工具算", done3["grounded"], False)

        # ④ 重复提问 → 服务端注入确定性提醒（模型会复读自己上一轮的做法，实测过）
        print("\n=== 重复提问：别复读上一轮 ===")
        with tempfile.TemporaryDirectory() as tmp2:
            assistant.configure(memory_path=Path(tmp2) / "repeat.db")
            captured: list[list[dict]] = []

            def capture(config, messages, tools):
                captured.append([dict(item) for item in messages])
                if len(captured) % 2 == 1:      # 每次提问的第一轮：调一个取数工具
                    return {"content": "", "tool_calls": [{"id": "x", "function": {
                        "name": "get_live_frame", "arguments": "{}"}}]}
                return {"content": "上一轮答案-ABCD。", "tool_calls": []}

            assistant.chat_completion = capture
            repeated = "现在谁在占带宽？"
            list(assistant.run_turn(repeated, "repeat-session"))
            list(assistant.run_turn(repeated, "repeat-session"))
            first_prompt = "\n".join(str(item.get("content")) for item in captured[0])
            second_prompt = "\n".join(str(item.get("content")) for item in captured[2])
            check("首问不注入重复提醒", "已经问过" in first_prompt, False)
            check("再问同一句 → 提醒上次没被接受", "没有被接受" in second_prompt, True)
            check("提醒点明要用不带 match 的完整排行", "不带 match" in second_prompt, True)
            check("复读模板被剔除：上下文里只剩当前这一次提问",
                  second_prompt.count(repeated), 1)
            check("上一轮的回答不再出现在上下文里", "上一轮答案" in second_prompt, False)
            check("会话计数按问题累计", assistant.MEMORY.times_asked("repeat-session", repeated), 2)
            check("别的问题不计数", assistant.MEMORY.times_asked("repeat-session", "别的"), 0)
finally:
    assistant.chat_completion = _real_chat
    for key, value in _ground_saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

# 恢复第 7 段之前设的配置隔离（该段的 finally 只负责环境变量）
assistant.CONFIG_PATH = _saved_config_path
assistant._ENV_FILE_LOADED = _saved_env_loaded

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
