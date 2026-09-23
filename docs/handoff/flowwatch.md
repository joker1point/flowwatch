# flowwatch 交接文档（独立自包含)

> 本文件只涉及 **flowwatch**。升级/排查 flowwatch 时**只需加载本文件**。
> 开源仓库:github.com/joker1point/flowwatch ｜ 本机路径:`frontend-works/flowwatch` ｜ 最近更新:2026-09-23(**v1.0.2 已发布**:没装 Npcap 也能打开界面;一键包 + 免 Python exe;tag `v1.0.2` → `25aa643`)。
>
> **本文件位置(2026-09-23 变更)**:原在 `frontend-works/docs/handoff/flowwatch.md`(工作区,**未纳版本管理**),
> 现搬进仓库本体 = **`flowwatch/docs/handoff/flowwatch.md`**(随仓库版本管理);工作区那份已删除。
> 搬入前脱敏:绝对路径里的用户名已换成 `%USERPROFILE%`(公开仓库不落本机用户名)。工作区索引见 `frontend-works/docs/handoff/README.md`。

---

## 1. 启动(⚠️ 最容易搞错的地方)

```powershell
cd %USERPROFILE%\Documents\trae_projects\frontend-works\flowwatch
python server.py --dev 4FC5DA1D        # 采集设备:GUID 片段(对应 \Device\NPF_{4FC5DA1D-...},描述"Microsoft")
cd web; npm run build; npx vite preview --port 4173   # 前端(构建后静态生效)

# 只想看数据(单端口:界面 + API 同源)→ http://127.0.0.1:8791
python run.py                          # 等价于双击 start.cmd(一键包入口)
```

- **v1.0.2(09-23 已发布)**:资产布局同 v1.0.1(两个包 + 各自 sha256),内容是"没装 Npcap 也能打开界面"的修复(第十/十一轮);`/api/meta` 报 `1.0.2`(版本号唯一维护点 = `server.py` 的 `VERSION`)
- **v1.0.1(09-21)**:Release 两个资产 —— `-windows.zip`(源码+预构建前端,双击 `start.cmd`)与 `-win64-exe.zip`(**免 Python**,双击 `flowwatch.exe`);两者都走**单端口 8791**、都需另装 **Npcap**(驱动级);⚠️ **该版 exe 在无 Npcap 的机器上 import 期就崩**(已被 v1.0.2 取代)
- **运行期数据路径统一走 `datadir.py`**:源码运行 = 项目目录;exe 运行 = **exe 旁边**;`FLOWWATCH_DATA_DIR` 可覆盖(exe 的 history.db 就在 exe 同目录)
- 打 exe:`packaging/flowwatch.spec` + **干净 venv**(33 MB;conda 基环境 207 MB);发版 = push `v*` → `.github/workflows/release.yml`(自带测试闸门 → 出两个包 + sha256)

- **底层是 WinPcap**(Windows 服务 `npf`),**不是 Npcap** —— 不要被名字误导
- **不要用 `--dev WLAN`**:这台机器没有叫 WLAN 的抓包设备,会采集 degraded(09-19 发生过)
- **重启前先查原参数**:`_run/` 目录历史日志的"设备:"行就是权威参数(全都是 `{4FC5DA1D}`)
- 端口别混:**8788** 后端 ｜ **5273** dev server(HMR) ｜ **4173** vite preview(改源码需重 build) ｜ **8791** 演示包
- 演示包 `_deploy/flowwatch/deploy_server.py` 与开发版**同一份后端代码**(唯一复制物 = `web/dist`);**判断采集真活只看 `packets` 是否增长**;health **无 `watchdog` 字段 = 跑了旧代码**(重启即修复)

## 2. 模型配置(为开源用户,09-19 上线)

- **后端**(`assistant.py`):
  - `GET /api/assistant/config` —— 当前配置(**key 只回掩码** + `source: file/env/none`)
  - `POST /api/assistant/config` —— 保存(**api_key 留空/掩码 = 保留原值**)
  - `POST /api/assistant/config/test` —— 真调一次模型(HTTP 错误原文回显)
- **前端**:`web/src/components/AssistantPanel.tsx` 右上「模型设置」按钮
- **存储**:`flowwatch/assistant_config.json`(**已 gitignore**);优先级 **UI 文件 > 环境变量 / `.env`**;**保存后无需重启**(每次直读文件)
- **当前 LLM**:DashScope 兼容模式 `https://dashscope.aliyuncs.com/compatible-mode/v1` + **`qwen-plus`**;key 在 `.env` 的 `FLOWWATCH_ASSISTANT_API_KEY`(已 gitignore)
- **"界面显示 mock" 八成是进程跑了旧代码** → 对比进程 StartTime 与 `assistant.py` LastWriteTime,或看 `/openapi.json` 是否缺 `/api/assistant/config`;重启即修复(实测过)

## 3. 代理流量哨兵 + Catrace 告警(09-19 集成)

**链路**:
```
proxy_sentinel 告警 → POST http://127.0.0.1:<port>/alert → Catrace 插件 sidecar → 桌面小窗卡片
(哨兵探测 23457→23458→23459;推不到自动退回原 MessageBox;桌面 ⚠️代理流量告警.txt 始终留档)
```

- **哨兵**:`scripts/proxy_sentinel.py` —— 数据源 = flowwatch 历史库(`history.db`,**只读** `mode=ro`,`buckets` 表按时间窗 SUM 代理进程上行);判定 **60min>10GB 或 30min>5GB**;冷却 30 分钟(落盘 `_run/sentinel_state.json`,因计划任务每次新进程);**常驻 = 计划任务 `ProxySentinel` 每 10 分钟 `pythonw proxy_sentinel.py --once`**(健康:LastTaskResult 0 / MissedRuns 0)
- **Catrace 插件**:`integrations/flowwatch-alert/`(7 文件;sidecar = `runtime/main.mjs`,本机 HTTP 服务默认 `127.0.0.1:23457`,**被占自动 +1**;`POST /alert` + `GET /health`;同标题 60s 去重,测试按钮绕过去重)
- **实测踩坑(务必继承)**:
  1. **23457 被 Catrace 本体占用**(它自己的 API:任何请求回 `401 {"error":"unauthorized"}`)→ 插件实际落在 **23458**,正常;哨兵打 23457 快速 401 后自动跳下一个
  2. 哨兵 `_catrace_notify()` **严格校验响应体 `{"ok":true}`**(不只看 200)—— 防同端口程序回 200 导致告警静默丢失
  3. 卡片 UI **`emit('action', a.id)` 必须是裸字符串**(对象形态 → 「知道了」无响应,实测踩过);`emit('close')` 无参;卡片自带右上角 ×
  4. **改插件代码后必须"禁用→重新启用"**(或重启 Catrace)才生效;已装副本在 `%APPDATA%\com.lanxiuyun.catrace\plugins\flowwatch-alert\`(改源文件后需同步过去再重启用)
  5. 设置页「自动关闭(秒)= 40」是用户配置(`0` = 常驻);卡片带倒计时条属设计行为,不是 bug

## 4. 待办

| 事项 | 备注 |
|---|---|
| "本机地址"标注:`10.44.99.5` = 本机 WLAN IP,目前被归到 IP 桶,AI 会误读 | 用户尚未拍板 |
| 推公开仓库的文档补充:README 增"UI 配置"说明 | 用户未表态 |
| 插件 UI 深色优化同步(可选):去 `opacity: .82` 的 `ui.mjs` 已在源码,重启用插件时同步到已装目录即可 | 亮色下差异可忽略 |

## 5. 相关文件与脚本

| 路径 | 说明 |
|---|---|
| `flowwatch/assistant.py` | 助手 / 模型配置(含 UI 三 API);SSE 事件 `meta`/`tool`/`done`/`end`,答案在 `done.text` |
| `flowwatch/notes.py` | AI 每日笔记(3 内置人设 + 自定义) |
| `flowwatch/integrations/flowwatch-alert/` | Catrace 小窗告警插件(见 §3) |
| `flowwatch/scripts/proxy_sentinel.py` | 代理流量哨兵(见 §3) |
| `flowwatch/run.py` | **单端口启动器**(界面+API 同源 8791):缺依赖自动 pip / 缺 Npcap 给提示 / 未配模型自动 mock |
| `flowwatch/start.cmd` | Windows 双击入口(纯 ASCII,`python`/`py -3` 兜底) |
| `flowwatch/datadir.py` | 运行期数据目录唯一出处(源码=项目目录 / exe=exe 旁边 / `FLOWWATCH_DATA_DIR`) |
| `flowwatch/packaging/flowwatch.spec` | PyInstaller onedir 打包定义(需**干净 venv**,见 §1) |
| `flowwatch/.github/workflows/release.yml` | 发版:push `v*` → tests → 源码包 + exe 包 + sha256 附到 Release |
| `_deploy/flowwatch/make_release_zip.py` | 本地打源码包(镜像 CI;`--skip-build` 可复用现有 dist) |
| `_deploy/flowwatch/make_exe_zip.py` | 本地打 exe 包(会**清掉运行期数据**再压,避免把本机流量历史发出去) |
| `_deploy/flowwatch/clean_builds.py` | 清理冗余构建(`--all` 含测试产物;打印释放体积) |
| `_deploy/flowwatch/commit_push.ps1` | 测试 → commit → push 一键(测试红则不提交) |
| `_deploy/flowwatch/sync_demo.ps1` | 演示包同步(停 8791 → 重建 dist → 启 8791 → 冒烟;第 6 步自动提交,`-NoCommit` 可关) |
| `_deploy/_qa/e2e_assistant_config.py` | 模型设置全链路 E2E |
| `_deploy/_qa/config_flowwatch_ai.py` | 一键配 AI(写 .env + gitignore + 补丁) |

## 6. 数据与保留策略速记

- 历史保留 **30 天**:`server.py: HISTORY_MAX_DAYS`(4 个 history 接口 `le` 上限 + `--retention-days` 默认)+ `history.py` 类默认;**events 走独立 30 天**;**前端未动**(HistoryPanel 仍固定近 60 分钟)
- 历史分析视图 `HistoryView.tsx`:1h/6h/24h/7d/30d → 桶 1/5/15/60/60min;横轴按真实时间定位(空洞留白);同网段的邻居流量不参与堆叠
- 本机归因口径:**Watt Toolkit 加速的流量全挂 `Steam++.Accelerator.exe` 名下**(机制正常,非"偷跑");未归因率随流量构成波动(4.5%~29.8%),**引用必带口径**

## 6.5 演示视频与 B 站投稿（✅ 已完成）

**看 `_deploy/_qa/HANDOFF-视频与投稿-20260920.md`**（自包含：成片清单与时长、制作链 8 步命令、待办、坑表、口径红线、环境状态、**§8 = 用 Tabbit CLI 投稿的完整流程与 10 条坑**）。
**已投出：BV `BV14ehv6REqU`** → https://www.bilibili.com/video/BV14ehv6REqU/（2026-09-21；成片 154.24 s；srt 字幕「中文」已发布；封面已返工为定制图）。
投稿走的是 **Tabbit CLI 驱动真实浏览器**（省掉 `biliup login` 扫码）；`_deploy/flowwatch/publish_bili.ps1`（分区 tid=231）保留为备用路径。
口径注意：**新投稿页是单层分区**（没有"计算机技术"这一项，实投 = 科技数码）；视频卡片里那句 `/api/assistant/meta` 是旧错路径，**真实端点是 `GET /api/assistant/status`**（已在评论区更正 + 卡片源码已修，见元原则 12）。

## 7. 助手证据纪律(2026-09-20 修;起因 = 一轮编造的"我查过了")
- **事故**:09-20 09:21 问「doubao发送和接收的是心跳包吗」,助手**一次工具都没调**却答出「查不到该进程/我查了实时帧与排行」整段;实测该窗口 `Doubao.exe` 是第 4 名(14.0MB)。根因 = 主循环 `if not calls: answer = content; break` 无条件采信零工具调用的回答。
- **修法**(`assistant.py` + `history.py`,已过单测):
  1. 首轮零工具调用 + 问题命中 `DATA_INTENT_PATTERNS` → 追加纠正一轮(`GROUNDING_NUDGE`);纠正后仍无证据 → 答复加 `⚠️ 未核实` 前缀,`done` 事件带 `grounded` / `retried`;
  2. 工具新增 **`match` 名字检索**(不区分大小写子串:小写 doubao 命中 Doubao.exe)与 `group`(按进程名合并多进程,Electron 应用不再被拆成十几行);`matched=false` 时明确提示"没有流量 ≠ 进程不存在"。历史层签名:`top_processes(minutes, limit, match, group)` / `top_domains(..., match)`,**默认行为不变(前端不受影响)**。
- **复测工具**:`_qa/qa_assistant_ask.py "<问题>"`(端到端,真模型真数据,打印工具调用与 grounded)｜`_qa/qa_assistant_match.py doubao`(真实历史库副本上验名字检索);端到端实测该问题 → 真调 `get_top_processes{match:doubao}` + `get_top_domains{match:doubao}`,`grounded=True`。
- **第二轮(同日,跟它实测 9 轮对话后)**:
  - 工具层:`get_events` 加 `match` / `minutes`(问"某应用最近有没有异常事件"不再只能给 pid);`match` 的描述里写死边界 —— **只按名字过滤**,且历史层**没有"进程↔域名"关联**(问"某进程连过哪些域名"只有明细档实时窗口能看,要如实说查不到)。
  - 记忆层:`memory_insert` 去重 + 写入后回读 `current`;`grounded` 只认取数工具(`get_*`)—— **记忆类工具不算证据**(实测:只调 `memory_insert` 就编出"占出向带宽 62%",旧口径还判 grounded=True)。
  - 提示词:记忆是背景不是范围(问全局必须查不带 match 的完整排行)/ match 语义与边界 / 某 pid 的"消失"≠ 应用没流量 / 内部过程不外泄。
  - **重复提问处理**:`Memory.times_asked()` + 把历史里同题的那对问答**整对剔除**。只加 system 提醒拦不住 —— 实测同题问 4 遍,它照抄前 3 遍的做法;剔除模板后第 4 次终于带上全局排行,答对 `GameViewerServer.exe`。
  - 已知未修:偶发单次模型调用 90s 超时(直接回 `TimeoutError`,无重试/降级)。
- **第三轮(同日)**:**新增工具 `get_process_identity`** —— 问"某进程是哪个软件"不再靠名字猜。给 `pid`,或给 `match`(名字片段,内部先查排行拿 pid);数据源 = psutil 取 exe 路径 + ctypes 读 PE 版本资源 → 厂商 / 产品 / 描述 / 版本。**路径按档位隔离**:aggregate 只回 厂商/产品/版本,**detail 才回完整路径**(路径含用户名)。工具体量 **12 个**(聚合档可见 11；清单可自助验证 = `GET /api/assistant/status` 的 `tools`,导出脚本 `_deploy/_qa/tools_table.py`)。
  - 踩坑(值得继承):`VerQueryValueW` 返回的长度单位**不统一** —— 二进制块(VarFileInfo\Translation)按**字节**,字符串值按**字符**。一开始统一按字节读(`string_at(ptr, len)`)→ 截断:`"NetEase"` 读成 `"NetE"`、产品名读成 `"网易UU"`(真值「网易UU远程服务」);字符串值本身就是 NUL 结尾,**直接 `ctypes.wstring_at`** 最稳。教训 = 先看工具原始输出再信模型复述(元原则 11)。
  - E2E:问「GameViewerServer.exe 是哪个软件」→ 真调该工具 → `NetEase / 网易UU远程服务 / 4.40.1.2090`;问「Tabbit Browser」→ 读到「北京酷迅互动科技有限公司 / 1.14.19.0」。
  - 第四轮(展示打磨):面板加轻量 markdown 渲染(不引库);纠正轮不再回灌草稿;截图 `_qa/shots_assistant.py` → `docs/screenshot-03~07-assistant-*.png`。
  - **第六轮(09-22 晚,联调驱动的两个护栏漏洞)**:①`needs_evidence` 与分档词表不一致 —— 问"连了谁/对端明细"时已升 detail 档却没要求证据 → 现在 `needs_evidence` 也认 `route_scope=="detail"`;②**短追问绕过护栏** —— "那 doubao 呢？"不含数据词,实测模型甚至在正文里写了一次没真发生的工具调用 → 现在**追问继承同会话上一句的数据意图**(`_previous_user_question`)。提示词补"代词先把指代查清楚"。`done` 再加 `needs_evidence` 字段。钉子 = `evals/cases.jsonl` 的 `guard-detail-without-evidence-01`、`followup-inherit-01`、`multiturn-pronoun-01`;联调脚本 `_qa/qa_assistant_batch.py`(8 轮真模型对话,修前 2/8 零工具调用 → 修后 0/8)。
  - **第五轮(09-22,评估集驱动的口径修复)**:`grounded` 改为**只认成功返回数据**的取数调用(参数校验失败返回 `{"error":...}` 不算证据);新增"纯记忆操作请求"豁免 —— "记忆操作类问句 + 只调记忆工具 + 答案里没有带单位的数字"不打未核实标,但 `grounded` 仍 false,且答案里出现 `62%`/`19.5 MiB` 这类数字时照标(09-20 红线的钉子);`done` 新增 `unverified` / `memory_request` 字段供评估集断言。钉子用例 = `evals/cases.jsonl` 的 `args-invalid-01/02`、`memory-write-01/02`、`grounding-memory-only-03`。
  - 未采纳:接 voidtools **Everything** 做定位 —— 只在"进程已退出+要按名字找安装目录"这一种场景有用,代价是外部依赖 + 全盘文件名索引暴露面(与"物理隔离"取向相反)。若确实要"历史进程身份",正路是**采集层顺带缓存 pid→exe 路径**(psutil 取 name 时可多取一次 `exe()`,落 `processes(pid,name,exe,first_seen,last_seen)` 小表),零外部依赖。
  - **第八轮(09-22 晚,只读承诺工程化: "写不了"而不是"我们不写")**:①**只读门面** `ReadOnlyStore` —— `configure()` 不再把整个 `HistoryStore` 交给助手,只传查询面(`stats/top_processes/top_domains/timeline/events/process_series`),写方法(`open/append/submit/start_writer/stop_writer/close/set_name_resolver`)在对象上**不存在**;②**执行前两道硬闸**(`run_tool`):档位闸(明细工具在非明细档直接拒 —— **修的是真洞:明细工具只是"不注入",模型可以凭名字幻觉调用**)与记忆写闸(`FLOWWATCH_ASSISTANT_MEMORY_WRITE=off` 时拒写记忆;`tools_for` 同时摘掉三个写工具=结构关);③**静态审计** `tests/test_readonly.py`(AST 调用图:工具可达代码里禁 os./shutil./subprocess./socket./urllib. 等危险调用;取数工具额外禁 sqlite3.;工具名禁写动词;两档并集==工具全集;门面不许有 `__getattr__`),进 CI 两个 job;④**字段级隔离钉子** `identity-path-scope-01`(完整路径只在明细档);⑤前端不变。**用例 25→30**(+`memory-write-off-01/02`、`injection-capability-01`、`injection-memory-seed-01`、`identity-path-scope-01`),新增判据/机制:用例级 `env`、参数占位符 `$PID`、每条用例顺带验门面。**变异测试扩到五个**(A 护栏/B 分档/C 执行闸/D 记忆写开关/E 只读门面),**五个全被抓到**(E 起初漏了 —— 桩数据源没有写方法,已给 `stub_source.FakeStore` 补同形写方法)。**实测**:scripted **30/30**、6 个单测全绿、`tsc` 过、`qa_fallback_e2e.py` 10/10(真实服务+真实数据经门面仍正常)、本机 8788 已重启。
    - **第八轮补(B 运行层,同日晚)**:`tests/test_readonly.py` **§5** 装 `sys.addaudithook` 真跑**全部 12 个工具 + 一轮对话**,断言真实副作用只有 `assistant_memory.db*`(含 `-wal/-shm`)、**零出站连接**、零子进程、零破坏性改动、建目录只在自己的数据目录里;两条**阳性对照**(故意写文件 / 把写副作用藏进 `get_health` 内部)证明"真出副作用会被抓到"。**边界(已写进文件头注释)**:审计在解释器层,看不见 ctypes 直调 Win32 的文件访问(读 exe 版本资源就是);SQLite 的写不经 `open`,DB 层只看 `sqlite3.connect` → 与静态层互补。CI 的 `test_readonly` 步骤自动带上,无需改配置。**提交**:`b03c954`(第七轮) + `fe8b8ea`(第八轮,含本节) —— **已于 2026-09-23 push**(`2be7a23..3d0e299`,该批共 7 个提交一起推;CI 全绿)。
  - **第七轮(09-22 晚,系统侧补查 + 协议层强制;本地纯离线方案,明确放弃引外部决策模型 Jev)**:①纠正轮向 provider 声明 **`tool_choice="required"`**(探测过 DashScope 兼容模式 auto/required/点名三种都接受;不支持该字段的 provider 由 `_completion()` 退回 `auto`,不让一轮问答因强制失败而报错);②**系统侧补查** —— 触发条件 = **整轮一个工具都没调用过**(比"这一步没调"更窄,否则会绕过 args-invalid-01 / grounding-memory-only-03 两条红线用例):`_fallback_fetch()` 按问题类型跑确定性取数(规则表与 `mock_turn` 同族 + 实体抽取当 `match`;明细档再补一步"排行定位 pid → `get_live_connections`"),结果作内部信息注回上下文重答,工具行带 `origin=system`,`done` 新增 `fallback` 字段如实列出;**空结果不算证据**(`_fallback_evidence`)→ 照打"未核实"。钉子 = `grounding-fallback-01`、`grounding-unverified-02`(改问 zebraapp:补查也空)、`guard-detail-without-evidence-01`(升级为补查拿到明细)、`guard-detail-fallback-empty-01`、`memory-recall-01` 第 2 轮。**live 档证不出补查**(真模型每次都自己调工具)→ 另加端到端 QA `_qa/qa_fallback_e2e.py`(stub provider 永远不调工具 + 真实服务/数据/SSE + 临时数据目录与独立端口;10/10 项通过,`tool_choice` 轨迹 `auto→required→auto`)。**scripted 25/25、单测全绿、变异测试仍双双抓到、live 证据组 5/5**;本机 8788 已重启到新代码。未做(留给下一轮):候选集窄化(12→2~3)与本地小模型/嵌入分类器当判定层。
  - **第九轮(09-23,文档层收尾,无代码改动)**:与用户一起对照外部教程的 `permission` 体系(判定种类 / 权限模式 / 检查点 / 策略来源 / 不可绕过的优先级)做了**现状盘点并收尾**。结论:**"只读"这条承诺可以宣布结束**(就当前定位:单机 / 单用户 / 只读 / 12 工具;三层证明 + 复合保证 + 变异测试钉死,没有已知绕过路径;且本路线不靠内容黑名单 —— 走"能力不可得",绕开了"字符串匹配不可靠"这个坑);**permission 作为体系没有结束**,三个缺口登记在案并各有触发条件:① **ask 档**(人机回路)——出现能不可逆改写用户环境的工具时必须补;② **可配置策略表**(allow/deny + 优先级)——多用户 / 企业策略时必须补;③ **参数级语义检查**——出现"同一工具既能读也能写"的能力时必须补。三者的载体都是 §3 Hook 注册表,前置条件(不变式测试)已满足,到点补时不必先补前置。**落点**:`flowwatch/README.md` 新增《权限模型:现在有什么、没有什么(2026-09-23 盘点,本轮收尾)》一节 + `docs/SPEC-assistant-roadmap.md` §3 末加"现状盘点(2026-09-23)"段落。**本轮无代码 / 用例改动,无需重跑回归**;顺带核对评估集口径:当前 **30 用例 / 15 类**,`scripted 30/30`(自动生成的 `evals/REPORT.md` 一致)。
  - **第十轮(09-23,无 Npcap 的机器上"页面打不开"——真实用户反馈驱动的修复)**:朋友的机器没装 Npcap,双击 exe 后浏览器死活打不开。**根因**:`run.py` 先打印"在此之前界面能打开,但不会有流量数据",紧接着 `import server` 就在**模块级**构造 `capturer = collector.Capturer()`,而 `Capturer.__init__` 里 `self.pcap = Pcap()` 立刻加载 wpcap.dll → 抛 `PcapError` → 进程退出,uvicorn 从未启动(崩溃栈 `run.py:125 → server.py:225 → collector.py:740 → collector.py:98`)。**复现手法(可复用)**:给 exe 目录放一个**坏的 `wpcap.dll`**(内容 `b"MZ"+b"\x00"*200`)—— 加载器优先命中应用目录,等价于"这台机器没装 Npcap",在真 exe 上复现出了完整崩溃栈。**修复**:`Capturer` 改**懒加载**(`self._pcap=None` + `pcap` property,首次真要抓包时才 `Pcap()`),异常因此落到 `_start_capturer()` 的既有兜底里 → 界面照开、`/api/health` 报 `degraded` 且 `error` 写明去装 Npcap。**配套**:① 新增 `tests/test_no_npcap.py`(子进程挂 sitecustomize 把 `ctypes.WinDLL("wpcap.dll")` 变成 OSError;断言"进程活着 / health 200 degraded / error 提到 Npcap / `/` 返回 HTML")——**先跑出红**(复现同一崩溃栈)再修,修后 7/7 绿;② `ci.yml` 两个 job + `release.yml` 发布前把关都加了这一步;③ 前端:`Header` 在 `health.error` 时显示「未启用采集」(不再永远停在"正在挑选网卡…"),`App.tsx` 加一条横幅说明原因与动作(复用既有的 `.banner`)。**回归**:7 个单测全绿(新增第 7 个)、`tsc` 过、`scripted 30/30`、变异测试仍敏感、正常路径(有 Npcap)实测照旧真采集(8s +325 包)。**⚠️ 当时未发的部分(已由 v1.0.2 / 第十一轮解决)**:v1.0.1 的 exe **仍带这个 bug**(已发布,改不了),朋友可先装 Npcap;修复要等 **v1.0.2**(打 tag → release.yml 会先跑这条新测试再发)。**未做**:虚拟机验证(本机有 VMware Workstation 但没有 Windows ISO;真 exe 上的坏 DLL 复现已是等价证据),本地重打 exe 验证冻结环境的想法没执行。
  - **第十一轮(09-23,v1.0.2 发版:先被自己的发布闸门挡下,修好再发出去)**:打 tag 后 **ci.yml 三个 job + release.yml 的发布前置全红**,release 的两个打包 job 全 skipped(没产出任何资产 → tag 可安全重建)。**根因不在业务代码,而在上一轮新加的那条测试自己**:`tests/test_no_npcap.py` 的启动参数是照 `run.py` 写死的(`--no-browser`),而它会**按构建产物选入口** —— 有 `web/dist` 走 `run.py`,没有则退回 `server.py`;CI 的测试 job 不构建前端 → 给 server.py 传了它不认识的参数 → argparse `exit(2)` → 进程当场死 → 「服务进程活着」「health 接口可用」必红。**本地为什么一直绿**:工作区里有 dist,永远走 run.py 那条 —— 典型的"测试只跑到本地恰好存在的那条分支"。**修法**:① 启动参数按入口构造(`--no-browser` 只在 run.py 分支加);② 进程已退出时打印 **exit code**,把"参数不认"与"采集层崩溃"分开;③ 文档串写明两条路都要过。**顺带补住真实缺口**:`release.yml` 的 exe job 在 `npm run build` **之后**补跑同一条测试 —— 那里 dist 已构建,测试走 `run.py` = **exe 的入口**(只放在 tests job 里永远只能测到 server.py,等于没覆盖用户双击那条路)。**版本号同步点(只有两处)**:`server.py` 的 `VERSION`(`/api/meta` 暴露)与 `README.md` 顶部徽章 —— 打包配置里没有版本元数据。**tag 处理**:首推的 v1.0.2 指向 `84a0203`(失败、零资产)→ 删远端 tag、重建指向 `25aa643`(修复提交)重推 → release 三 job 全绿;**资产** = `-windows.zip` 2.8 MB / `-win64-exe.zip` 16.56 MB + 两个 sha256。**交付前验收(下载发布资产实测,不是本地重打)**:下载 exe 包 → sha256 与资产一致(`2ddbb36378ff…138eaf`)→ 解压后放**坏的 `wpcap.dll`**(等价"没装 Npcap")实跑:`/api/meta` = `1.0.2`、`/api/health` = `degraded` 且 error 提到 Npcap、首页 **HTTP 200 且是真 HTML**、进程全程存活。**提交**:`84a0203`(版本号同步)+ `25aa643`(测试按入口给参数),均已 push。
