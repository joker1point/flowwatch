"""ETW 实时消费对照检查：成熟库 pywintrace（基线） vs flowwatch 自己的实现。

**为什么要有这个脚本**：实时路线曾经"会话建得起来、句柄有效、却零回调"，
我照 21 组（mode 偏移 × 回调偏移）网格瞎试过，全是 0。改成**与成熟库逐项对照结构体布局**后，
一次就撞出根因：`EVENT_TRACE_HEADER` 多 8 字节 → 回调指针落在 432 而 Windows 读 424。
本脚本把"对照"固化成可复跑的检查，四步都有明确判据：

  0. 布局一致性：我的结构体尺寸/偏移与 pywintrace 是否逐项相同（不需要权限）
  1. pywintrace 基线：同一 provider 上真能收到事件（证明环境、provider、权限都没问题）
  2. flowwatch 实现：收到事件 + 归因写入 ConnMemory + sanity 校验零失败（PID 是它们自己的）
  3. 受控延迟实测：本机 loopback 连接，从 `connect()` 到"归因就绪"的毫秒数 ——
     这是本项目真正要的指标（表归因对这类短命 socket 完全无能）

**需要管理员**（创建 ETW 会话）。用法（在管理员 PowerShell 里）：
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\run_elevated.ps1 scripts\\etw_realtime_check.py
"""
import ctypes as C
import importlib.util
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter

# stdout 可能被重定向到 GBK 控制台：强制 UTF-8 + errors=replace，
# 否则一个符号就能把整个检查打断（实测被 U+2717 打断过一次）。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                          # noqa: BLE001
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # flowwatch/
PROVIDER_STR = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
PROVIDER_NAME = "Microsoft-Windows-Kernel-Network"
KEYWORDS = 0x30                     # 0x10 IPv4 | 0x20 IPv6
EVENT_IDS = (12, 15, 28, 31, 13, 29)  # connect/accept/disconnect（v4+v6）
SECONDS = 10
LATENCY_ROUNDS = 3

# ── 先导入 pywintrace（它在 anaconda site-packages，包名就叫 etw）──────────────
# 顺序不能变：flowwatch 自己的模块也叫 etw.py，一旦先把它放进 sys.path，
# `import etw` 就拿到我自己的实现（这个坑实测踩过一次）。
try:
    import etw as pywt                                    # noqa: E402  （pip install pywintrace）
    import etw.evntrace as ref                            # noqa: E402
    from etw import ETW, ProviderInfo                     # noqa: E402
    HAVE_PYWT = True
except ImportError:
    # 参照库没装也能跑：跳过【0】【1】的对照，只做本实现的收事件 + 归因延迟检查。
    pywt = ref = ETW = ProviderInfo = None                 # type: ignore[assignment]
    HAVE_PYWT = False

spec = importlib.util.spec_from_file_location("flowwatch_etw", os.path.join(ROOT, "etw.py"))
mine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mine)


def is_admin() -> bool:
    try:
        return bool(C.windll.shell32.IsUserAnAdmin())
    except Exception:                                     # noqa: BLE001
        return False


def local_ips() -> set:
    """本机地址集合（采集层用的同款判据）。"""
    out = set()
    try:
        import psutil
        for _name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    out.add(addr.address)
                elif addr.family == socket.AF_INET6:
                    out.add(addr.address.split("%")[0].lower())
    except Exception:                                     # noqa: BLE001
        pass
    return out


class Memory:
    """代替真实 ConnMemory：记录 (四元组 → PID) 与写入时刻，供延迟测量用。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.items: dict[tuple, tuple[int, float]] = {}
        self.forgotten = 0

    def remember(self, key, pid) -> None:
        with self.lock:
            self.items[key] = (pid, time.perf_counter())

    def forget(self, key) -> None:
        with self.lock:
            self.items.pop(key, None)
            self.forgotten += 1

    def wait_for(self, key, timeout: float):
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            with self.lock:
                hit = self.items.get(key)
            if hit:
                return hit
            time.sleep(0.001)
        return None


print("=" * 78)
print(f"管理员: {is_admin()}   python: {sys.executable}")
print(f"provider: {PROVIDER_NAME} {PROVIDER_STR}   keywords=0x{KEYWORDS:x}   ids={EVENT_IDS}")
print(f"本机地址样本: {sorted(local_ips())[:6]}")
print("=" * 78)

# ── 0. 布局一致性 ────────────────────────────────────────────────────────────
ROWS = [] if not HAVE_PYWT else [
    ("sizeof(EVENT_TRACE_HEADER)", C.sizeof(ref.EVENT_TRACE_HEADER), C.sizeof(mine.EventTraceHeader)),
    ("sizeof(EVENT_TRACE)", C.sizeof(ref.EVENT_TRACE), C.sizeof(mine.EventTrace)),
    ("sizeof(EVENT_TRACE_LOGFILE)", C.sizeof(ref.EVENT_TRACE_LOGFILE), C.sizeof(mine.EventTraceLogfileW)),
    ("offset(LoggerName)", ref.EVENT_TRACE_LOGFILE.LoggerName.offset, mine.EventTraceLogfileW.LoggerName.offset),
    ("offset(ProcessTraceMode)", ref.EVENT_TRACE_LOGFILE.ProcessTraceMode.offset,
     mine.EventTraceLogfileW.ProcessTraceMode.offset),
    ("offset(LogfileHeader)", ref.EVENT_TRACE_LOGFILE.LogfileHeader.offset,
     mine.EventTraceLogfileW.LogfileHeader.offset),
    ("offset(EventRecordCallback)", ref.EVENT_TRACE_LOGFILE.EventRecordCallback.offset,
     mine.EventTraceLogfileW.EventRecordCallback.offset),
    ("offset(Context)", ref.EVENT_TRACE_LOGFILE.Context.offset, mine.EventTraceLogfileW.Context.offset),
]
print("\n【0】布局对照（基准：pywintrace 0.2.0）")
layout_bad = -1                      # -1 = 没装参照库，跳过对照（不算"不一致"）
if HAVE_PYWT:
    layout_bad = 0
    for name, a, b in ROWS:
        ok = a == b
        layout_bad += 0 if ok else 1
        print(f"  {name:<32}{a:>8}{b:>8}   {'OK' if ok else '**不一致**'}")
    print(f"  => {'布局一致' if layout_bad == 0 else str(layout_bad) + ' 项不一致（后面结果不必看了，先修布局）'}")
else:
    print("  跳过：未装参照库 pywintrace（pip install pywintrace）—— 只跑本实现的检查")
print(f"  本实现自检 LAYOUT_OK = {mine.LAYOUT_OK}   {mine.LAYOUT_DETAIL}")

# ── 1. pywintrace 基线 ──────────────────────────────────────────────────────
print(f"\n【1】pywintrace 基线（{SECONDS}s）")
py_counts: Counter = Counter()
py_total = [0]


def on_py_event(evt) -> None:
    py_counts[evt[0]] += 1
    py_total[0] += 1


py_ok, py_err = False, ""
if HAVE_PYWT:
    try:
        guid = pywt.GUID(PROVIDER_STR)
        with ETW(session_name="flowwatch-ab-pywt",
                 providers=[ProviderInfo(PROVIDER_NAME, guid, level=4, any_keywords=KEYWORDS)],
                 event_callback=on_py_event,
                 event_id_filters=list(EVENT_IDS),
                 ignore_exists_error=True):
            time.sleep(SECONDS)
        py_ok = py_total[0] > 0
    except Exception as exc:                                # noqa: BLE001
        py_err = f"{type(exc).__name__}: {exc}"
else:
    py_err = "未装参照库 pywintrace（跳过）"
print(f"  事件总数 {py_total[0]}   按 id: {dict(sorted(py_counts.items()))}   {'' if py_ok else 'FAIL ' + py_err}")

# ── 2. flowwatch 实现 ───────────────────────────────────────────────────────
print(f"\n【2】flowwatch 实现（{SECONDS}s，修好后的 etw.py）")
memory = Memory()
tracker = mine.EtwConnTracker(memory, local_ips, session_name="flowwatch-etw-ab")
tracker.start()
time.sleep(SECONDS)
stats = tracker.stats()
tracker.stop()
learned_keys = list(memory.items.items())
print(f"  state={stats['state']} events={stats['events']} learned={stats['learned']} "
      f"forgotten={stats['forgotten']} sanity_failures={stats['sanity_failures']}")
print(f"  detail={stats['detail'] or '(无)'}")
for key, (pid, _ts) in learned_keys[:5]:
    print(f"    {key[0]}:{key[1]} -> {key[2]}:{key[3]}   归因 PID={pid}")

# ── 3. 受控延迟实测（loopback，PID 必然是自己）───────────────────────────────
print(f"\n【3】归因延迟实测：本机 loopback 连接 × {LATENCY_ROUNDS}")
latencies = []
for _ in range(LATENCY_ROUNDS):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    sport = srv.getsockname()[1]

    def accept_once():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_once, daemon=True).start()
    cli = socket.socket()
    t0 = time.perf_counter()
    cli.connect(("127.0.0.1", sport))
    cport = cli.getsockname()[1]
    key = ("127.0.0.1", cport, "127.0.0.1", sport)
    hit = memory.wait_for(key, 3.0)
    cli.close()
    srv.close()
    if hit:
        pid, ts = hit
        latency_ms = (ts - t0) * 1000
        latencies.append(latency_ms)
        print(f"  connect(:{sport}) -> 归因就绪 {latency_ms:7.2f} ms   PID={pid} "
              f"{'是它自己(OK)' if pid == os.getpid() else 'PID 不符（本进程 %d）' % os.getpid()}")
    else:
        print(f"  connect(:{sport}) -> 3 秒内没有归因 (FAIL)")
if latencies:
    print(f"  延迟：min {min(latencies):.2f} ms · 中位 {statistics.median(latencies):.2f} ms · "
          f"max {max(latencies):.2f} ms（对比：表归因对短命 socket 是 0 覆盖）")

# ── 4. 结论 + 会话清理检查 ──────────────────────────────────────────────────
print("\n【4】结论与会话清理")
mine_ok = stats["state"] == "running" and stats["events"] > 0 and stats["learned"] > 0
layout_txt = "跳过（无参照库）" if layout_bad < 0 else ("一致" if layout_bad == 0 else f"{layout_bad} 项不一致")
print(f"  布局 {layout_txt} · pywintrace 收到事件 {py_ok} · flowwatch 收到事件并归因 {mine_ok} · "
      f"受控连接归因 {len(latencies)}/{LATENCY_ROUNDS}")
if not is_admin:
    print("  提示：本次不是管理员 —— ETW 会话创建会 state=denied，这属于如实降级，不是 bug")
try:
    out = subprocess.run(["logman", "query", "-ets"], capture_output=True, timeout=20)
    text = (out.stdout or b"").decode("utf-8", errors="replace")
    leftover = [ln.strip() for ln in text.splitlines() if "flowwatch" in ln.lower()]
    print(f"  残留 flowwatch 会话: {leftover if leftover else '无 (none)'}")
except Exception as exc:                                   # noqa: BLE001
    print(f"  会话列表查询失败：{exc}")
print("=" * 78)
print("ETW CHECK DONE")          # 哨兵：外层轮询用它判断"跑完了"（stdout 被重定向时会块缓冲）

