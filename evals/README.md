# flowwatch 助手行为评估集

回答一个 `tests/` 回答不了的问题：**改了一轮提示词 / 工具 / 记忆逻辑之后，助手的行为有没有变差？**

`tests/test_assistant.py` 测的是**零件**（工具分级、难度路由、记忆原语、schema 生成）；
这里测的是**一轮对话的整体行为**：工具选得对不对、证据判定（grounded / retried）对不对、
复制抑制有没有生效、分档边界有没有破、记忆往返对不对。

## 两个档（口径完全不同，别混着引用）

| 档 | 命令 | 测什么 | 能不能进 CI |
|---|---|---|---|
| **scripted**（默认） | `python evals/run_eval.py --mode scripted` | **系统守卫**：给定"模型说了什么"（用例里写死的响应序列），系统有没有正确处置 —— 零工具调用是否被纠正、只调记忆工具是否被判非证据、聚合档是否真的不把明细工具给模型、重复提问是否把旧问答对移出上下文、轮数上限是否收口 | ✅ 零网络、确定性、约 1 秒 |
| **live** | `python evals/run_eval.py --mode live --base-url http://127.0.0.1:8788` | **真模型 + 真数据**：只断言结构性判据（工具 / 档位 / 证据标志 / 前缀），不比对具体数字 | ❌ 需要本机服务 + 配置好的模型 |

> **口径红线**：scripted 档**不测**"模型自己会不会选对工具"——脚本是我们写的，选工具是"给定"的。
> 想看模型选择准确率，跑 live 档，并**带上模型名、日期与样本量**一起引用（数据构成与模型都会影响结果）。
> live 档默认跳过所有会写记忆的用例（记忆块是 agent 级、跨会话可见，不该被评估污染）。

## 用例怎么组织

`cases.jsonl` 每行一条（`//` 开头与空行会被跳过）：

```json
{
  "id": "grounding-retry-01",
  "category": "证据纠正",
  "notes": "09-20 事故的回归：首轮零工具调用 → 强制纠正一轮；纠正后拿到证据则不打'未核实'",
  "seed_memory": {"watchlist": "盯 Doubao.exe"},
  "live_skip": "会写真实记忆库",
  "runs": [
    {
      "question": "doubao 收发的是心跳包吗？",
      "script": [{"content": "查不到…"}, {"tool_calls": [{"name": "get_top_processes", "args": {"match": "doubao"}}]}],
      "expect": {"retried": true, "grounded": true, "model_calls": 3, "answer_prefix_not": "⚠️"}
    }
  ]
}
```

`expect` 可用判据（全部确定性，来自 SSE 事件与模块状态，见 `run_eval.py` 的 `_assert_run`）：

- 事件级：`scope` / `grounded` / `retried` / `tools_all_of` / `tools_none_of` / `model_calls` / `max|min_model_calls`
- 工具级：`tool_args`（参数值；`null` = 必须缺省）、`tool_result_contains`、`tool_result_field`、`tool_description_contains`
- **发给模型的 offer 列表**：`offered_tools_all_of` / `offered_tools_none_of` —— 隐私隔离这类承诺只有在这层核对才算验过
- 答案级：`answer_prefix` / `answer_prefix_not` / `answer_contains_all` / `answer_contains_any` / `answer_not_contains`
- 上下文级：`prompt_contains` / `prompt_not_contains`（本轮模型输入；用来验"旧问答对被移出""记忆块已注入"）
- 记忆级：`memory_block`（块当前值包含某串）
- 提示词级：`system_prompt_contains`（提示词也是代码，回归要能被钉住）

## 它真的能变红吗：变异测试

永远全绿的评估集等于没测。所以有一道自检：

```bash
python ../_deploy/_qa/evals_mutation_check.py      # 在 frontend-works 下：python _deploy/_qa/evals_mutation_check.py
```

它注入两个已知缺陷 —— ①`needs_evidence` 恒 False（拆护栏）、②`tools_for` 无视档位（拆物理隔离）——
**两个都被抓到才算通过**。2026-09-21 实测：变异 A 让 3 条 grounding 用例全红、变异 B 让 `scope-aggregate-02` 变红。

## 产物

- `REPORT.md` —— **要提交的那一份**：分类汇总 + 逐用例明细 + 失败明细 + 口径说明。
  live 档的失败明细**只留判据名、不印实际值**（实际值可能是真模型答案，含真实域名）
- `results/eval_<mode>_<时间戳>.json` —— 每条用例的判据明细，可对比两次运行的差异；**本地留存（已 gitignore）**
- `fixtures/`（`--record` 时）—— live 档原始转写，**含真实进程名/域名，已 gitignore，不要提交**

## 首轮跑出来的两条真实观察（2026-09-21）

1. **live 档第一版有 1 条红了，红得有价值**：问"doubao 最近一小时有流量吗"，真模型（qwen-plus）
   走了 `get_top_domains(match=doubao)`（域名侧）而不是进程侧 —— 数据真实、`grounded=True`、答案也自洽。
   结论：这条用例原本只认一条正路，属于**期望过窄**；已把问题问明确（"doubao 这个进程…"），
   并把 live 期望改成"系统不变量"（进程侧或域名侧都算过）。这条记下来是因为它示范了
   **scripted 期望 ≠ live 期望**：前者钉机制，后者只能钉不变量。
2. **护栏在真模型上确实会触发**：`identity-miss-01` 在 live 档出现 `retried=True` ——
   模型首轮零工具调用直接作答，系统补了一轮纠正后它才去调 `get_process_identity`。
   这是"纠正轮"机制在真实模型上的第一次可观测命中（此前只在单测里以脚本化响应验证过）。
3. **多轮代词会让模型"弃疗"**：连续问过"现在谁在占带宽最多？"后问 `"它是哪个软件？"`，
   模型会因指代不明一个字都不查就作答（护栏接住了、打了标，但答案是废的）。
   已加提示词规则（"代词先把指代查清楚"）并用 `multiturn-pronoun-01` 钉住；
   修后实测：模型改为先用 `match` 检索上一轮点名的对象（`retried=True` → `grounded=True`）。
4. **联调 8 轮的真实计数**（2026-09-22，qwen-plus）：修前 2/8 出现"零工具调用"（1 条被护栏接住、
   1 条漏网）；修后同批问题 **0/8**（多轮组 3/3 全部先查再答）。**结论要这样读**：
   模型仍会偶发不调工具（比如 `"doubao发送和接收的是心跳包吗"` 有一次就是零工具 + 标未核实），
   但**不会再出现"没查却看起来像查过"** —— 这正是护栏存在的意义。

## 口径修复记录（评估集 + 联调实测，2026-09-22）

四处问题在发现当天修掉（改的是 `assistant.py`），修完由评估集验证：

| 问题 | 修法 | 钉子（用例） |
|---|---|---|
| 参数校验失败的取数调用也算证据 | `grounded` 只认**成功返回数据**的取数调用（结果里没有 `error`） | `args-invalid-01`（失败 → 照标未核实）、`args-invalid-02`（重试成功 → 不标） |
| 纯记忆请求被打"未核实"前缀 | 仅当"**记忆操作类请求** + 只调了记忆工具 + 答案里没有带单位的数字"时豁免；`grounded` 仍为 `false` | `memory-write-01`（收据不标）、`memory-write-02`（答案里带 `62%` → 照标）、`grounding-memory-only-03`（问带宽却只写记忆 → 照标，红线不破） |
| **明细档问题没被当成数据问题**：问"Steam++ 连了谁？给我对端明细"时系统已升 detail 档，但 `needs_evidence` 词表没覆盖 → 模型零工具作答、**连标的没有** | `needs_evidence` 也认 `route_scope(question) == "detail"`（两个词表对齐，单一判据） | `guard-detail-without-evidence-01` |
| **短追问整个绕过护栏**：`"那 doubao 呢？"` 不含任何数据关键词 → `needs_evidence=False`；实测模型甚至**在正文里写了一次没真发生的工具调用**（`执行 get_top_domains(...)`）却无人纠正 | **追问继承**：本轮不含数据词时，沿用同会话上一句的数据意图（`_previous_user_question`） | `followup-inherit-01` |

`done` 事件新增三个字段，评估集直接断言它们（比比对文案稳得多）：
`unverified`（本轮是否被打未核实标）、`memory_request`（是不是记忆操作类请求）、
`needs_evidence`（本轮是否按"要本机数据"对待，含追问继承）。

另外：live 档对**传输层瞬时错误**（实测遇到过 `RemoteDisconnected`，服务端日志全是 200）
会自动重试一次 —— 抖动不该被记成"行为失败"；重试后仍失败才算红。
