#!/usr/bin/env python3
"""flowwatch 流量助手 · **行为评估集**运行器。

与 `tests/test_assistant.py` 的分工：
  · 单测测**零件**（工具分级、路由、记忆原语）——已经覆盖，不重复；
  · 这里测**一轮对话的整体行为**：工具选得对不对、证据判定（grounded/retried）对不对、
    复制抑制有没有生效、分档边界有没有破、记忆往返对不对。

三档（互相独立，可只跑一档）：

    python evals/run_eval.py --mode scripted          # 默认：CI 用，零网络、确定性
    python evals/run_eval.py --mode live --base-url http://127.0.0.1:8788   # 真模型+真数据
    python evals/run_eval.py --mode live --record     # 顺带把原始转写落盘（含真实域名，勿提交）

**scripted 档在测什么、不测什么（口径）**：
  · 测：给定"模型说了什么"（脚本里的响应序列），**系统**有没有正确处置 ——
    零工具调用是否被纠正、只调记忆工具是否被判非证据、聚合档是否真的不把明细工具给模型、
    重复提问是否把旧问答对移出上下文、记忆写入是否去重/容量契约是否生效；
  · 不测：模型自己会不会选对工具 —— 那属于 live 档（脚本是我们写的，选工具是"给定"的）。
    想看"模型选择准确率"，跑 live 并按本文末的口径引用。

退出码：任一用例失败 → 1（CI 直接红）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

EVALS = Path(__file__).resolve().parent
ROOT = EVALS.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(EVALS))

import assistant  # noqa: E402
import stub_source  # noqa: E402

CASES = EVALS / "cases.jsonl"
RESULTS = EVALS / "results"
FIXTURES = EVALS / "fixtures"
REPORT = EVALS / "REPORT.md"

EVAL_ENV = {
    "FLOWWATCH_ASSISTANT_PROVIDER": "openai",       # 只为拿到"进主循环"的配置；真调用被替换
    "FLOWWATCH_ASSISTANT_BASE_URL": "https://eval.invalid/v1",
    "FLOWWATCH_ASSISTANT_API_KEY": "sk-eval",
    "FLOWWATCH_ASSISTANT_MODEL": "eval-scripted",
}


# ---------------------------------------------------------------- 断言

class Checks:
    """把断言收成一张表：每条都记 pass/fail + 实际值，失败原因直接可读。"""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, label: str, ok: bool, actual=None, wanted=None) -> None:
        self.rows.append({"label": label, "ok": bool(ok), "actual": actual, "wanted": wanted})

    def eq(self, label: str, actual, wanted) -> None:
        self.add(label, actual == wanted, actual, wanted)

    def contains(self, label: str, text: str, needle: str) -> None:
        self.add(label, needle in (text or ""), (text or "")[:160], f"包含 {needle!r}")

    def excludes(self, label: str, text: str, needle: str) -> None:
        self.add(label, needle not in (text or ""), (text or "")[:160], f"不含 {needle!r}")

    @property
    def failed(self) -> list[dict]:
        return [row for row in self.rows if not row["ok"]]

    def extend(self, other: "Checks") -> None:
        """并入另一组判据（live 档的"不变量候选"用它保留明细）。"""
        self.rows.extend(other.rows)


# ---------------------------------------------------------------- scripted 档

class ScriptedTransport:
    """脚本化"模型"：按用例给定的响应序列逐次返回，同时记录**它看到的东西**。

    记录 `offered`（每轮提供给模型的工具名）是关键 —— "聚合档下明细工具不可见"这条
    隐私承诺，只有在真实调用链里核对 offer 列表才算验过。
    """

    def __init__(self, script: list[dict]) -> None:
        self.script = list(script)
        self.calls: list[dict] = []
        self.prompts: list[str] = []
        self.offered: list[list[str]] = []
        self.tool_choices: list[str | None] = []   # 每跳向 provider 声明的 tool_choice（含 required）

    def __call__(self, config, messages, tools, tool_choice=None):   # noqa: ARG002 - 签名随 assistant
        index = len(self.calls)
        self.prompts.append("\n".join(str(item.get("content") or "") for item in messages))
        self.offered.append([(t.get("function") or {}).get("name") for t in (tools or [])])
        self.tool_choices.append(tool_choice)
        self.calls.append({"messages": messages, "tools": tools})
        step = self.script[index] if index < len(self.script) else {"content": "（评估脚本已用尽）"}
        return _to_response(step, index)


def _to_response(step: dict, index: int) -> dict:
    calls = []
    for i, call in enumerate(step.get("tool_calls") or []):
        calls.append({
            "id": f"eval-{index}-{i}",
            "type": "function",
            "function": {"name": call["name"],
                         "arguments": json.dumps(call.get("args") or {}, ensure_ascii=False)},
        })
    return {"content": step.get("content") or "", "tool_calls": calls}


def _install_source(tmp: Path) -> None:
    """每个用例一套干净的记忆库 + 固定世界（stub 数据源）。"""
    assistant.configure(hub=stub_source.FakeHub(), store=stub_source.FakeStore(),
                        capturer=stub_source.FakeCapturer(),
                        memory_path=tmp / "assistant_memory.db")
    # 别读开发机上的 assistant_config.json（否则本机配置会渗进评估）
    assistant.CONFIG_PATH = tmp / "assistant_config.json"
    assistant.load_config = lambda: assistant.ProviderConfig(
        "openai", "eval · scripted", "https://eval.invalid/v1", "sk-eval", "eval-scripted")


def _tool_args(tool_events: list[dict], name: str) -> list[dict]:
    return [item.get("args") or {} for item in tool_events if item.get("name") == name]


def _tool_results(tool_events: list[dict], name: str) -> list[dict]:
    return [item.get("result") for item in tool_events if item.get("name") == name]


def _assert_run(checks: Checks, expect: dict, run_result: dict) -> None:
    done = run_result["done"]
    tools = done.get("tools") or []
    tool_events = run_result["tool_events"]
    last_prompt = run_result["prompt"]
    offered = run_result["offered"]

    if "scope" in expect:
        checks.eq("scope", done.get("scope"), expect["scope"])
    if "grounded" in expect:
        checks.eq("grounded", bool(done.get("grounded")), expect["grounded"])
    if "retried" in expect:
        checks.eq("retried", bool(done.get("retried")), expect["retried"])
    if "unverified" in expect:
        checks.eq("unverified（被打未核实标）", bool(done.get("unverified")), expect["unverified"])
    if "tool_choice_required" in expect:
        # 协议层强制：纠正轮那一跳必须向 provider 声明 tool_choice="required"（不是只发提示词）
        seen = run_result.get("tool_choices") or []
        checks.eq("纠正轮声明 tool_choice=required", "required" in seen,
                  bool(expect["tool_choice_required"]))
    for name in expect.get("fallback_all_of", []):
        checks.add(f"系统补查代跑了 {name}", name in (done.get("fallback") or []),
                   done.get("fallback"))
    if "memory_request" in expect:
        checks.eq("memory_request", bool(done.get("memory_request")), expect["memory_request"])
    if "needs_evidence" in expect:
        checks.eq("needs_evidence（按数据问题对待）", bool(done.get("needs_evidence")),
                  expect["needs_evidence"])
    for name in expect.get("tools_all_of", []):
        checks.add(f"调用了 {name}", name in tools, tools)
    for name in expect.get("tools_none_of", []):
        checks.add(f"没调用 {name}", name not in tools, tools)
    for name in expect.get("offered_tools_all_of", []):
        checks.add(f"向模型提供了 {name}", any(name in row for row in offered), offered)
    for name in expect.get("offered_tools_none_of", []):
        checks.add(f"没向模型提供 {name}", all(name not in row for row in offered), offered)

    for name, wanted in (expect.get("tool_args") or {}).items():
        seen = _tool_args(tool_events, name)
        checks.add(f"{name} 被调用过", bool(seen), seen)
        for param, value in wanted.items():
            ok = any((args.get(param) is None if value is None else args.get(param) == value)
                     for args in seen)
            checks.add(f"{name}.{param} = {value!r}", ok, seen)

    for name, needle in (expect.get("tool_result_contains") or {}).items():
        blob = json.dumps(_tool_results(tool_events, name), ensure_ascii=False)
        checks.contains(f"{name} 结果包含 {needle!r}", blob, needle)

    for name, fields in (expect.get("tool_result_field") or {}).items():
        for key, value in fields.items():
            ok = any(isinstance(item, dict) and item.get(key) == value
                     for item in _tool_results(tool_events, name))
            checks.add(f"{name} 结果 {key}={value!r}", ok, _tool_results(tool_events, name))

    for name, needle in (expect.get("tool_description_contains") or {}).items():
        scope = done.get("scope") or "aggregate"
        spec = next((item for item in assistant.tools_for(scope)
                     if item["function"]["name"] == name), None)
        checks.contains(f"{name} 的 description 含 {needle!r}",
                        json.dumps(spec, ensure_ascii=False) if spec else "", needle)

    text = done.get("text") or ""
    if expect.get("answer_prefix"):
        checks.add(f"答案以 {expect['answer_prefix']!r} 开头", text.startswith(expect["answer_prefix"]), text[:80])
    if expect.get("answer_prefix_not"):
        checks.add(f"答案不以 {expect['answer_prefix_not']!r} 开头",
                   not text.startswith(expect["answer_prefix_not"]), text[:80])
    for needle in expect.get("answer_contains_all", []):
        checks.contains(f"答案包含 {needle!r}", text, needle)
    any_needles = expect.get("answer_contains_any") or []
    if any_needles:
        checks.add(f"答案包含 {' / '.join(repr(n) for n in any_needles)} 之一",
                   any(needle in text for needle in any_needles), text[:160])
    for needle in expect.get("answer_not_contains", []):
        checks.excludes(f"答案不含 {needle!r}", text, needle)

    for needle in expect.get("prompt_contains", []):
        checks.contains(f"本轮上下文包含 {needle!r}", last_prompt, needle)
    for needle in expect.get("prompt_not_contains", []):
        checks.excludes(f"本轮上下文不含 {needle!r}", last_prompt, needle)

    if "model_calls" in expect:
        checks.eq("模型往返次数", len(run_result["calls"]), expect["model_calls"])
    if "max_model_calls" in expect:
        checks.add("模型往返不超上限", len(run_result["calls"]) <= expect["max_model_calls"],
                   len(run_result["calls"]), expect["max_model_calls"])
    if "min_model_calls" in expect:
        checks.add("模型往返不少于下限", len(run_result["calls"]) >= expect["min_model_calls"],
                   len(run_result["calls"]), expect["min_model_calls"])

    for label, needle in (expect.get("memory_block") or {}).items():
        checks.contains(f"记忆块 {label} 含 {needle!r}", assistant.MEMORY.block_value(label), needle)
    for needle in expect.get("system_prompt_contains", []):
        checks.contains(f"SYSTEM_PROMPT 含 {needle!r}", assistant.SYSTEM_PROMPT, needle)


def run_case_scripted(case: dict) -> dict:
    session = f"eval-{case['id']}"
    runs: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _install_source(tmp_path)
        for label, value in (case.get("seed_memory") or {}).items():
            assistant.MEMORY.block_write(label, value)
        checks = Checks()
        for index, run in enumerate(case["runs"]):
            transport = ScriptedTransport(run.get("script") or [])
            assistant.chat_completion = transport
            events = list(assistant.run_turn(run["question"], session))
            events_dict = dict(events)
            if "done" not in events_dict:
                checks.add(f"第 {index + 1} 轮产出 done 事件", False, events_dict.get("error"))
                runs.append({"ok": False})
                continue
            result = {
                "done": events_dict["done"],
                "tool_events": [payload for name, payload in events if name == "tool"],
                "prompt": transport.prompts[-1] if transport.prompts else "",
                "offered": transport.offered,
                "calls": transport.calls,
                "tool_choices": transport.tool_choices,
            }
            before = len(checks.rows)
            _assert_run(checks, run.get("expect") or {}, result)
            runs.append({
                "ok": all(row["ok"] for row in checks.rows[before:]),
                "tools": result["done"].get("tools"),
                "grounded": result["done"].get("grounded"),
                "retried": result["done"].get("retried"),
                "scope": result["done"].get("scope"),
                "model_calls": len(transport.calls),
                "answer": result["done"].get("text"),
            })
    return {
        "id": case["id"], "category": case["category"], "mode": "scripted",
        "ok": not checks.failed, "runs": runs,
        "checks": checks.rows, "failures": checks.failed,
    }


# ---------------------------------------------------------------- live 档

def _post_sse(base_url: str, question: str, session: str, timeout: float = 180.0) -> dict:
    payload = json.dumps({"question": question, "session_id": session}).encode("utf-8")
    request = urllib.request.Request(f"{base_url.rstrip('/')}/api/assistant/chat", data=payload,
                                     method="POST", headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 本机服务：绕过代理
    events: list[tuple[str, dict]] = []
    with opener.open(request, timeout=timeout) as response:
        name = ""
        for raw in response:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("event: "):
                name = line[7:].strip()
            elif line.startswith("data: "):
                try:
                    events.append((name, json.loads(line[6:])))
                except json.JSONDecodeError:
                    pass
    return {"events": events, "dict": dict(events)}


def run_case_live(case: dict, base_url: str, record_dir: Path | None) -> dict:
    checks = Checks()
    runs: list[dict] = []
    transcript: list[dict] = []
    for index, run in enumerate(case["runs"]):
        session = f"eval-{case['id']}-{int(time.time())}"
        # 瞬时传输错误重试一次：实测遇到过 RemoteDisconnected（服务端日志全是 200，纯抖动）——
        # 把它算成"行为失败"会污染结论，所以重试一次；仍失败才如实记红。
        got: dict | None = None
        for attempt in range(2):
            try:
                got = _post_sse(base_url, run["question"], session)
                break
            except Exception as exc:                   # noqa: BLE001 - 如实报错，不算"跳过"
                if attempt == 1:
                    checks.add(f"第 {index + 1} 轮请求成功", False,
                               f"{type(exc).__name__}: {exc}（重试 1 次后仍失败）")
                else:
                    print(f"       · {case['id']}：传输抖动（{type(exc).__name__}: {exc}），重试一次")
                    time.sleep(2)
        if got is None:
            runs.append({"ok": False})
            continue
        done = got["dict"].get("done")
        if not done:
            checks.add(f"第 {index + 1} 轮产出 done", False, str(got["dict"].get("error"))[:200])
            runs.append({"ok": False})
            continue
        tool_events = [payload for name, payload in got["events"] if name == "tool"]
        # live 档只验"结构性"判据：上下文类（prompt_*）拿不到（请求走 HTTP），数字/文案也不比
        # （真数据一直在变）。两类期望二选一：
        #   · `live_expect_any`：一组"系统不变量"，命中任一条即通过 ——
        #     例如"要么有证据、要么明确标注未核实"，这才是系统真正保证的东西；
        #   · 否则退回 `expect` 里的结构性字段。
        run_result = {"done": done, "tool_events": tool_events,
                      "prompt": "", "offered": [], "calls": [], "tool_choices": []}
        variants = run.get("live_expect_any")
        if variants:
            probes = []
            for variant in variants:
                probe = Checks()
                _assert_run(probe, variant, run_result)
                probes.append(probe)
                if not probe.failed:
                    break
            hit = next((probe for probe in probes if not probe.failed), None)
            checks.add(f"命中任一 live 不变量（{len(variants)} 选 1）", hit is not None,
                       [row["label"] for row in (hit or probes[0]).failed], "至少一组通过")
            checks.extend(hit or probes[0])
            run_ok = hit is not None
        else:
            expect = run.get("live_expect") or run.get("expect") or {}
            structural = {key: expect[key] for key in
                          ("scope", "tools_all_of", "tools_none_of", "grounded", "retried",
                           "answer_prefix", "answer_prefix_not", "answer_not_contains",
                           "system_prompt_contains") if key in expect}
            skipped = sorted(set(expect) - set(structural) - {"live_expect"})
            if skipped:
                print(f"       · {case['id']}：live 档跳过非结构性判据 {skipped}")
            before = len(checks.rows)
            _assert_run(checks, structural, run_result)
            run_ok = all(row["ok"] for row in checks.rows[before:])
        transcript.append({"question": run["question"], "tools": done.get("tools"),
                           "scope": done.get("scope"), "grounded": done.get("grounded"),
                           "retried": done.get("retried"), "answer": done.get("text")})
        runs.append({"ok": run_ok,
                     "tools": done.get("tools"), "grounded": done.get("grounded"),
                     "retried": done.get("retried"), "scope": done.get("scope"),
                     "answer": done.get("text")})
    if record_dir is not None:
        record_dir.mkdir(parents=True, exist_ok=True)
        (record_dir / f"{case['id']}.json").write_text(
            json.dumps(transcript, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"id": case["id"], "category": case["category"], "mode": "live",
            "ok": not checks.failed, "runs": runs, "checks": checks.rows, "failures": checks.failed}


# ---------------------------------------------------------------- 报告

def load_cases() -> list[dict]:
    cases = []
    for line in CASES.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("//"):
            cases.append(json.loads(line))
    return cases


def write_report(all_results: list[dict], modes: list[str]) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M")
    lines = [f"# flowwatch Agent 评估报告（{stamp}）", ""]
    for mode in modes:
        subset = [row for row in all_results if row["mode"] == mode]
        if not subset:
            continue
        passed = sum(1 for row in subset if row["ok"])
        lines += [f"## {mode} 档：{passed}/{len(subset)} 通过", ""]
        if mode == "scripted":
            lines += [
                "- **口径**：脚本化模型（响应序列由用例给出）+ stub 数据源，零网络、确定性。",
                "- **测的是系统守卫**：工具分级是否真的不把明细工具给模型、证据判定（grounded/retried）、",
                "  记忆原语与容量契约、重复提问的复制抑制、轮数上限。**不测「模型自己会不会选对工具」**。",
                "",
            ]
        else:
            lines += [
                "- **口径**：真模型 + 真数据（本机运行中的 flowwatch），只断言结构性判据",
                "  （工具 / 档位 / 证据标志 / 前缀），不比对具体数字；模型与该次数据构成都会影响结果，",
                "  **引用请带上模型名、日期与样本量**。",
                "",
            ]
        lines += ["| 类别 | 用例 | 通过 |", "|---|---|---|"]
        by_cat: dict[str, list[dict]] = {}
        for row in subset:
            by_cat.setdefault(row["category"], []).append(row)
        for category, rows in by_cat.items():
            lines.append(f"| {category} | {len(rows)} | {sum(1 for r in rows if r['ok'])} |")
        lines += ["", "| id | 类别 | 结果 | 工具 | grounded | retried | 档位 | 模型往返 |",
                  "|---|---|---|---|---|---|---|---|"]
        for row in subset:
            first = (row["runs"] or [{}])[0]
            lines.append("| `{id}` | {cat} | {ok} | {tools} | {g} | {r} | {s} | {n} |".format(
                id=row["id"], cat=row["category"], ok="✅" if row["ok"] else "❌",
                tools=", ".join(first.get("tools") or []) or "-",
                g=first.get("grounded"), r=first.get("retried"), s=first.get("scope"),
                n=first.get("model_calls", "-")))
        failures = [row for row in subset if not row["ok"]]
        if failures:
            lines += ["", "### 失败明细", ""]
            for row in failures:
                lines.append(f"- `{row['id']}`")
                for check in row["failures"]:
                    if row["mode"] == "live":
                        # live 的 actual 可能是真模型答案（含真实域名/进程名）→ 报告里只留判据名，
                        # 具体值留在本地 results/（已 gitignore）。与截图脱敏同一条纪律。
                        lines.append(f"  - {check['label']}（实际值含真实数据，见本地 results/）")
                    else:
                        lines.append(f"  - {check['label']} → 实际 {check['actual']!r}"
                                     f"（期望 {check['wanted']!r}）")
        lines.append("")
    lines += [
        "## 口径与已知问题",
        "",
        "- **两个档不能混着引用**：scripted = 系统守卫（零网络、确定性）；live = 真模型行为",
        "  （受模型与数据构成影响，引用请带模型名 / 日期 / 样本量）。live 默认跳过会写记忆的用例。",
        "- **评估集本身要被证伪过**：`python _deploy/_qa/evals_mutation_check.py` 注入两个已知缺陷",
        "  （拆证据护栏 / 拆物理隔离），两个都能被抓住才算通过。",
        "- 已知口径问题 ①：参数校验失败的取数调用仍算证据（见 `args-invalid-01`）——",
        "  `grounded` 只看「调没调 `get_*`」，没看是否成功返回数据。",
        "- 已知口径问题 ②：纯记忆请求也会被打「未核实」前缀（见 `memory-write-01`）——",
        "  问题里点了 `.exe` 就命中数据意图，而记忆工具不算证据。",
        "",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="flowwatch 助手行为评估集")
    parser.add_argument("--mode", choices=("scripted", "live"), default="scripted")
    parser.add_argument("--base-url", default="http://127.0.0.1:8788")
    parser.add_argument("--only", default="", help="只跑这些 id（逗号分隔）")
    parser.add_argument("--record", action="store_true", help="live 档：原始转写落盘（含真实域名，勿提交）")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.only:
        wanted = {item.strip() for item in args.only.split(",") if item.strip()}
        cases = [case for case in cases if case["id"] in wanted]
    if not cases:
        print("[eval] 没有可跑的用例")
        return 1

    if args.mode == "scripted":
        os.environ.update(EVAL_ENV)
        results = []
        for case in cases:
            result = run_case_scripted(case)
            results.append(result)
            flag = "OK  " if result["ok"] else "FAIL"
            print(f"[{flag}] {case['id']:<26} {case['category']:<6} "
                  f"tools={','.join((result['runs'] or [{}])[0].get('tools') or []) or '-'}")
            for check in result["failures"]:
                print(f"       - {check['label']} → 实际 {check['actual']!r}（期望 {check['wanted']!r}）")
    else:
        record_dir = FIXTURES / f"live_{time.strftime('%Y%m%d-%H%M%S')}" if args.record else None
        results = []
        for case in cases:
            if case.get("live_skip"):
                print(f"[SKIP] {case['id']:<26} （live 档跳过：{case.get('live_skip')}）")
                continue
            result = run_case_live(case, args.base_url, record_dir)
            results.append(result)
            flag = "OK  " if result["ok"] else "FAIL"
            print(f"[{flag}] {case['id']:<26} {case['category']:<6} "
                  f"tools={','.join((result['runs'] or [{}])[0].get('tools') or []) or '-'}")
            for check in result["failures"]:
                print(f"       - {check['label']} → 实际 {check['actual']!r}（期望 {check['wanted']!r}）")

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"eval_{args.mode}_{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"mode": args.mode, "when": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "results": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    # 报告合并"每个档各自最新一次运行"，两个档互不覆盖（先后跑都能看到全貌）
    merged: list[dict] = []
    modes: list[str] = []
    for mode in ("scripted", "live"):
        files = sorted(RESULTS.glob(f"eval_{mode}_*.json"))
        if not files:
            continue
        latest = json.loads(files[-1].read_text(encoding="utf-8"))
        merged.extend(latest.get("results") or [])
        modes.append(mode)
    write_report(merged or results, modes or [args.mode])
    passed = sum(1 for row in results if row["ok"])
    print(f"\n[eval] {args.mode}: {passed}/{len(results)} 通过；结果 {out.relative_to(ROOT)}；报告 {REPORT.name}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
