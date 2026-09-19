"""assistant.py 单元测试：工具分级、难度路由、分层记忆、mock 链路、provider 配置。

不需要网络、不需要真实模型、不碰真库 —— 数据源全部 stub 注入，记忆写到临时文件。
要钉死的三件事：
  1. **聚合档下明细工具不可见**（隐私靠物理隔离，不靠提示词）；
  2. **记忆块按 Letta 的 Prompt ABI 渲染**（label/description/value + 容量元数据）；
  3. **压缩只标记不删除** —— 摘要漂移后还能用 conversation_search 回到原文。
"""

from __future__ import annotations

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

class FakeStore:
    def stats(self) -> dict:
        return {"retention_days": 30, "oldest": "2026-09-17T08:00:00", "buckets": 11, "events": 3}

    def top_processes(self, minutes: int = 60, limit: int = 10) -> list[dict]:
        return [
            {
                "process": "Steam++.Accelerator.exe", "pid": 84812,
                "total_bytes": 1067797993, "out_bytes": 984000000, "in_bytes": 83797993,
                "first_seen": "2026-09-19T08:45:00", "last_seen": "2026-09-19T11:30:00",
            }
        ][:limit]

    def top_domains(self, minutes: int = 60, limit: int = 10, named_only: bool = False) -> list[dict]:
        return [{"name": "10.44.99.5", "kind": "ip", "total_bytes": 976000000, "conns": 79275}][:limit]

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

    def events(self, limit: int = 20, pid: int | None = None) -> list[dict]:
        items = [{"ts": "2026-09-19T11:12:00", "kind": "vanish", "pid": 84812,
                  "process": "Steam++.Accelerator.exe", "detail": "连续 3 分钟无流量"}]
        if pid is not None:
            items = [item for item in items if item["pid"] == pid]
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
check("明细工具能取对端",
      assistant.run_tool("get_live_connections", {"pid": 84812})["connections"][0]["remote"],
      "10.44.99.5:49716")

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

# 恢复第 7 段之前设的配置隔离（该段的 finally 只负责环境变量）
assistant.CONFIG_PATH = _saved_config_path
assistant._ENV_FILE_LOADED = _saved_env_loaded

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
