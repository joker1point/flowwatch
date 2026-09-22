# flowwatch Agent 评估报告（2026-09-22 18:05）

## scripted 档：23/23 通过

- **口径**：脚本化模型（响应序列由用例给出）+ stub 数据源，零网络、确定性。
- **测的是系统守卫**：工具分级是否真的不把明细工具给模型、证据判定（grounded/retried）、
  记忆原语与容量契约、重复提问的复制抑制、轮数上限。**不测「模型自己会不会选对工具」**。

| 类别 | 用例 | 通过 |
|---|---|---|
| 排行 | 2 | 2 |
| 点名检索 | 2 | 2 |
| 身份 | 1 | 1 |
| 事件 | 1 | 1 |
| 记忆写入 | 3 | 3 |
| 记忆召回 | 1 | 1 |
| 重复提问 | 1 | 1 |
| 证据纠正 | 5 | 5 |
| 分档 | 2 | 2 |
| 工具契约 | 2 | 2 |
| 循环护栏 | 1 | 1 |
| 不可答问 | 1 | 1 |
| 多轮 | 1 | 1 |

| id | 类别 | 结果 | 工具 | grounded | retried | 档位 | 模型往返 |
|---|---|---|---|---|---|---|---|
| `rank-global-01` | 排行 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `rank-memory-scope-02` | 排行 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `match-hit-01` | 点名检索 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `match-miss-01` | 点名检索 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `identity-miss-01` | 身份 | ✅ | get_process_identity | True | False | aggregate | 2 |
| `events-01` | 事件 | ✅ | get_events | True | False | aggregate | 2 |
| `memory-write-01` | 记忆写入 | ✅ | memory_insert | False | False | aggregate | 2 |
| `memory-dup-01` | 记忆写入 | ✅ | memory_insert | False | False | aggregate | 2 |
| `memory-recall-01` | 记忆召回 | ✅ | memory_insert | False | False | aggregate | 2 |
| `repeat-question-01` | 重复提问 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `grounding-retry-01` | 证据纠正 | ✅ | get_top_processes | True | True | aggregate | 3 |
| `grounding-unverified-02` | 证据纠正 | ✅ | - | False | True | aggregate | 2 |
| `grounding-memory-only-03` | 证据纠正 | ✅ | memory_insert | False | False | aggregate | 2 |
| `scope-detail-01` | 分档 | ✅ | get_live_connections | True | False | detail | 2 |
| `scope-aggregate-02` | 分档 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `args-invalid-01` | 工具契约 | ✅ | get_top_processes | False | False | aggregate | 2 |
| `max-turns-01` | 循环护栏 | ✅ | get_top_processes, get_top_processes, get_top_processes, get_top_processes, get_top_processes, get_top_processes | True | False | aggregate | 6 |
| `unsupported-process-domain-01` | 不可答问 | ✅ | - | False | True | aggregate | 2 |
| `args-invalid-02` | 工具契约 | ✅ | get_top_processes, get_top_processes | True | False | aggregate | 3 |
| `memory-write-02` | 记忆写入 | ✅ | memory_insert | False | False | aggregate | 2 |
| `guard-detail-without-evidence-01` | 证据纠正 | ✅ | - | False | True | detail | 2 |
| `multiturn-pronoun-01` | 多轮 | ✅ | get_top_processes | True | False | aggregate | 2 |
| `followup-inherit-01` | 证据纠正 | ✅ | get_top_processes | True | False | aggregate | 2 |

## live 档：19/19 通过

- **口径**：真模型 + 真数据（本机运行中的 flowwatch），只断言结构性判据
  （工具 / 档位 / 证据标志 / 前缀），不比对具体数字；模型与该次数据构成都会影响结果，
  **引用请带上模型名、日期与样本量**。

| 类别 | 用例 | 通过 |
|---|---|---|
| 排行 | 2 | 2 |
| 点名检索 | 2 | 2 |
| 身份 | 1 | 1 |
| 事件 | 1 | 1 |
| 重复提问 | 1 | 1 |
| 证据纠正 | 5 | 5 |
| 分档 | 2 | 2 |
| 工具契约 | 2 | 2 |
| 循环护栏 | 1 | 1 |
| 不可答问 | 1 | 1 |
| 多轮 | 1 | 1 |

| id | 类别 | 结果 | 工具 | grounded | retried | 档位 | 模型往返 |
|---|---|---|---|---|---|---|---|
| `rank-global-01` | 排行 | ✅ | get_top_processes | True | False | aggregate | - |
| `rank-memory-scope-02` | 排行 | ✅ | get_top_processes | True | False | aggregate | - |
| `match-hit-01` | 点名检索 | ✅ | get_top_processes | True | False | aggregate | - |
| `match-miss-01` | 点名检索 | ✅ | get_top_processes | True | False | aggregate | - |
| `identity-miss-01` | 身份 | ✅ | get_process_identity | True | True | aggregate | - |
| `events-01` | 事件 | ✅ | get_events | True | False | aggregate | - |
| `repeat-question-01` | 重复提问 | ✅ | get_top_processes | True | False | aggregate | - |
| `grounding-retry-01` | 证据纠正 | ✅ | get_top_domains | True | False | aggregate | - |
| `grounding-unverified-02` | 证据纠正 | ✅ | get_top_domains | True | False | aggregate | - |
| `grounding-memory-only-03` | 证据纠正 | ✅ | get_top_domains | True | False | aggregate | - |
| `scope-detail-01` | 分档 | ✅ | get_process_identity, get_live_connections | True | False | detail | - |
| `scope-aggregate-02` | 分档 | ✅ | get_top_processes | True | False | aggregate | - |
| `args-invalid-01` | 工具契约 | ✅ | get_top_processes, get_top_domains | True | False | aggregate | - |
| `max-turns-01` | 循环护栏 | ✅ | get_top_processes | True | False | aggregate | - |
| `unsupported-process-domain-01` | 不可答问 | ✅ | get_top_processes | True | True | aggregate | - |
| `args-invalid-02` | 工具契约 | ✅ | get_top_processes, get_top_domains | True | False | aggregate | - |
| `guard-detail-without-evidence-01` | 证据纠正 | ✅ | get_process_identity, get_live_connections | True | False | detail | - |
| `multiturn-pronoun-01` | 多轮 | ✅ | get_top_processes | True | False | aggregate | - |
| `followup-inherit-01` | 证据纠正 | ✅ | get_top_processes | True | False | aggregate | - |

## 口径与已知问题

- **两个档不能混着引用**：scripted = 系统守卫（零网络、确定性）；live = 真模型行为
  （受模型与数据构成影响，引用请带模型名 / 日期 / 样本量）。live 默认跳过会写记忆的用例。
- **评估集本身要被证伪过**：`python _deploy/_qa/evals_mutation_check.py` 注入两个已知缺陷
  （拆证据护栏 / 拆物理隔离），两个都能被抓住才算通过。
- 已知口径问题 ①：参数校验失败的取数调用仍算证据（见 `args-invalid-01`）——
  `grounded` 只看「调没调 `get_*`」，没看是否成功返回数据。
- 已知口径问题 ②：纯记忆请求也会被打「未核实」前缀（见 `memory-write-01`）——
  问题里点了 `.exe` 就命中数据意图，而记忆工具不算证据。

