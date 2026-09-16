"""证据脚本：证明：挂到 logman 建的实时会话上，本层仍 0 次回调；自检显示交给 ETW 的字节正确（mode@28=0x10000100、回调指针已写、LoggerName 已设、句柄有效）。
结论：本层的 OpenTraceW + ProcessTrace 实时消费未打通（详见 README《ETW 归因》一节）。

（本文件是 6 轮提权诊断实验的一环，保留下来是为了让 README 的结论可复核。）
"""

from __future__ import annotations

import ctypes as C
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import etw  # noqa: E402

SESSION = "flowwatch-rt"
PROVIDER = "Microsoft-Windows-Kernel-Network"
MODE_VALUE = etw.PROCESS_TRACE_MODE_REAL_TIME | etw.PROCESS_TRACE_MODE_EVENT_RECORD

LIB = C.WinDLL("advapi32.dll")
LIB.OpenTraceW.argtypes = [C.POINTER(etw.EventTraceLogfileW)]
LIB.OpenTraceW.restype = C.c_uint64
LIB.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_uint32, C.c_void_p, C.c_void_p]
LIB.ProcessTrace.restype = C.c_uint32
LIB.CloseTrace.argtypes = [C.c_uint64]
LIB.CloseTrace.restype = C.c_uint32

calls = 0
errors: list[str] = []
samples: list[str] = []


def attach(label: str, seconds: float = 6.0) -> int:
    """挂上名为 SESSION 的实时会话，返回回调次数。"""
    global calls, errors, samples
    calls, errors, samples = 0, [], []

    proto = C.WINFUNCTYPE(None, C.POINTER(etw.EventRecord))

    def on_event(ptr) -> None:                       # noqa: ANN001
        global calls
        calls += 1
        try:
            record = ptr.contents
            if len(samples) < 3:
                samples.append(f"id={record.EventHeader.EventDescriptor.Id} pid={record.EventHeader.ProcessId}")
        except Exception as exc:
            if len(errors) < 3:
                errors.append(f"{type(exc).__name__}: {exc}")

    holder = {"cb": proto(on_event)}
    logfile = etw.EventTraceLogfileW()
    logfile.LoggerName = SESSION
    logfile.ProcessTraceMode = MODE_VALUE
    logfile.EventRecordCallback = C.cast(holder["cb"], C.c_void_p)

    # 自检：把我交给 ETW 的字节打出来（mode 在偏移 28，回调应在 432）
    raw = bytes((C.c_char * C.sizeof(etw.EventTraceLogfileW)).from_address(C.addressof(logfile)))
    print(f"[{label}] 结构体大小 {len(raw)} · mode@28 = 0x{struct.unpack_from('<I', raw, 28)[0]:08x}"
          f" · mode@32 = 0x{struct.unpack_from('<I', raw, 32)[0]:08x}"
          f" · cb@432 = 0x{struct.unpack_from('<Q', raw, 432)[0]:x}"
          f" · cb@440 = 0x{struct.unpack_from('<Q', raw, 440)[0]:x}", flush=True)
    print(f"[{label}] LoggerName 指针 = {bool(logfile.LoggerName)}，期望 mode = 0x{MODE_VALUE:08x}", flush=True)

    handle = LIB.OpenTraceW(C.byref(logfile))
    print(f"[{label}] OpenTraceW = {'INVALID' if handle in (0, 0xFFFFFFFFFFFFFFFF) else hex(handle)}", flush=True)
    if handle in (0, 0xFFFFFFFFFFFFFFFF):
        return 0
    trace_handle = C.c_uint64(handle)
    worker = threading.Thread(target=LIB.ProcessTrace, args=(C.byref(trace_handle), 1, None, None), daemon=True)
    worker.start()
    time.sleep(seconds)
    LIB.CloseTrace(C.c_uint64(handle))
    print(f"[{label}] 回调 {calls} 次" + (f" · 样例 {samples[:2]}" if samples else "")
          + (f" · 异常 {errors[:2]}" if errors else ""), flush=True)
    return calls


def main() -> int:
    code, out = LIB_helpers_start()
    if code != 0:
        print(f"logman 起实时会话失败 rc={code} {out}", flush=True)
        return 1
    time.sleep(1.5)
    traffic = subprocess.Popen(
        [sys.executable, str(REPO / "tools" / "traffic.py"), "--seconds", "30", "--interval", "1"],
        cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    calls_a = attach("attach-to-logman-session", 6)
    traffic.terminate()
    subprocess.run(["logman", "stop", SESSION, "-ets"], capture_output=True, text=True)
    print("\n判读：" + ("能收到回调 → 问题在我建会话的方式（properties/实时标志）"
                       if calls_a else "仍 0 回调 → 问题在我的 ProcessTrace 消费端"), flush=True)
    return 0


def LIB_helpers_start() -> tuple[int, str]:
    proc = subprocess.run(["logman", "start", SESSION, "-p", PROVIDER, "0x30", "4", "-ets"],
                          capture_output=True, text=True, errors="replace")
    return proc.returncode, ((proc.stdout or "").strip() or (proc.stderr or "").strip())


if __name__ == "__main__":
    raise SystemExit(main())
