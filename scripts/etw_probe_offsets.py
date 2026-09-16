"""证据脚本：证明：(mode 偏移 × 回调偏移) 21 组网格全部 0 次回调。
排除："回调偏移写错了"。同时修掉一个诊断盲点——把回调异常单独打出来，区分"没被调用"与"被调用但解析失败"。

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

PROVIDER = etw.PROVIDER_GUID
MODE_VALUE = etw.PROCESS_TRACE_MODE_REAL_TIME | etw.PROCESS_TRACE_MODE_EVENT_RECORD

LIB = C.WinDLL("advapi32.dll")
LIB.StartTraceW.argtypes = [C.POINTER(C.c_uint64), C.c_wchar_p, C.c_void_p]
LIB.StartTraceW.restype = C.c_uint32
LIB.ControlTraceW.argtypes = [C.c_uint64, C.c_wchar_p, C.c_void_p, C.c_uint32]
LIB.ControlTraceW.restype = C.c_uint32
LIB.EnableTraceEx2.argtypes = [C.c_uint64, C.POINTER(etw.GUID), C.c_uint32, C.c_ubyte,
                               C.c_uint64, C.c_uint64, C.c_uint32, C.c_void_p]
LIB.EnableTraceEx2.restype = C.c_uint32
LIB.OpenTraceW.argtypes = [C.POINTER(etw.EventTraceLogfileW)]
LIB.OpenTraceW.restype = C.c_uint64
LIB.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_uint32, C.c_void_p, C.c_void_p]
LIB.ProcessTrace.restype = C.c_uint32
LIB.CloseTrace.argtypes = [C.c_uint64]
LIB.CloseTrace.restype = C.c_uint32

calls = 0
errors: list[str] = []
samples: list[str] = []


def guid_of(provider_id: str) -> etw.GUID:
    raw = bytes.fromhex(provider_id.replace("{", "").replace("}", "").replace("-", ""))
    return etw.GUID(int.from_bytes(raw[0:4], "little"), int.from_bytes(raw[4:6], "little"),
                    int.from_bytes(raw[6:8], "little"), (C.c_ubyte * 8)(*raw[8:16]))


def run_candidate(label: str, mode_off: int, callback_off: int, seconds: float = 2.5) -> tuple[int, int, str]:
    """按给定偏移接线，返回 (回调调用次数, 解析成功数, 备注)。"""
    global calls, errors, samples
    calls, errors, samples = 0, [], []

    name = f"flowwatch-grid-{mode_off}-{callback_off}"
    name_bytes = (name + "\0").encode("utf-16-le")
    size = C.sizeof(etw.EventTraceProperties) + len(name_bytes)
    props_buf = C.create_string_buffer(size)
    props = C.cast(props_buf, C.POINTER(etw.EventTraceProperties)).contents
    props.Wnode.BufferSize = size
    props.LogFileMode = etw.EVENT_TRACE_REAL_TIME_MODE
    props.Wnode.Flags = 0x00000002
    props.LoggerNameOffset = C.sizeof(etw.EventTraceProperties)
    C.memmove(C.addressof(props_buf) + C.sizeof(etw.EventTraceProperties), name_bytes, len(name_bytes))

    session = C.c_uint64(0)
    rc = LIB.StartTraceW(C.byref(session), name, C.cast(props_buf, C.c_void_p))
    if rc not in (0, 183):
        return 0, 0, f"StartTraceW={rc}"
    guid = guid_of(PROVIDER)
    LIB.EnableTraceEx2(session, C.byref(guid), 1, 4, 0x30, 0, 0, None)

    proto = C.WINFUNCTYPE(None, C.POINTER(etw.EventRecord))

    def on_event(ptr) -> None:                       # noqa: ANN001
        global calls
        calls += 1
        try:
            record = ptr.contents
            event_id = record.EventHeader.EventDescriptor.Id
            pid = record.EventHeader.ProcessId
            length = record.UserDataLength
            if len(samples) < 3:
                samples.append(f"id={event_id} pid={pid} len={length}")
        except Exception as exc:                      # 以前这里被吞掉，正是诊断盲点
            if len(errors) < 3:
                errors.append(f"{type(exc).__name__}: {exc}")

    holder = {"cb": proto(on_event)}
    logfile = etw.EventTraceLogfileW()
    logfile.LoggerName = name
    logfile.ProcessTraceMode = MODE_VALUE
    logfile.EventRecordCallback = C.cast(holder["cb"], C.c_void_p)

    # 关键一步：按候选偏移在原始缓冲区里改写 mode 与 callback（绕开 ctypes 的布局）
    base = C.addressof(logfile)
    struct.pack_into("<I", (C.c_char * C.sizeof(etw.EventTraceLogfileW)).from_address(base), mode_off, MODE_VALUE)
    C.memmove(base + callback_off, C.byref(C.c_void_p(C.cast(holder["cb"], C.c_void_p).value)), 8)

    handle = LIB.OpenTraceW(C.byref(logfile))
    if handle in (0, 0xFFFFFFFFFFFFFFFF):
        LIB.ControlTraceW(session, name, C.cast(props_buf, C.c_void_p), 1)
        return 0, 0, "OpenTraceW=INVALID"
    trace_handle = C.c_uint64(handle)
    worker = threading.Thread(target=LIB.ProcessTrace, args=(C.byref(trace_handle), 1, None, None), daemon=True)
    worker.start()
    time.sleep(seconds)
    LIB.ControlTraceW(session, name, C.cast(props_buf, C.c_void_p), 1)
    LIB.CloseTrace(C.c_uint64(handle))
    worker.join(timeout=2)
    note = ("; ".join(samples[:2]) + (" | " + "; ".join(errors[:2]) if errors else "")) or "无回调"
    return calls, len(samples), note


def main() -> int:
    traffic = subprocess.Popen([sys.executable, str(REPO / "tools" / "traffic.py"),
                                "--seconds", "120", "--interval", "1"],
                               cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    print("=== 偏移网格搜索（mode 偏移 × 回调偏移）===", flush=True)
    winners = []
    # 候选必须落在结构体内部（sizeof = 456），否则就是越界写内存
    for mode_off in (28, 32, 36):
        for callback_off in (400, 408, 416, 424, 432, 440, 448):
            call_count, parsed, note = run_candidate(f"{mode_off}/{callback_off}", mode_off, callback_off)
            flag = "  <== 有回调" if call_count else ""
            print(f"  mode@{mode_off:>3} cb@{callback_off:>3} → 回调 {call_count:>3} 次 · {note}{flag}", flush=True)
            if call_count:
                winners.append((mode_off, callback_off, call_count))
            if call_count:
                break                      # 这一组 mode 已经找到能用的回调偏移，换下一个 mode
    traffic.terminate()
    print("\n=== 结论 ===", flush=True)
    if winners:
        print("有效组合: " + "; ".join(f"mode@{m} + cb@{c}（{n} 次回调）" for m, c, n in winners), flush=True)
    else:
        print("网格内没有任何组合被调用 —— 下一步该怀疑 ProcessTrace/会话实时模式本身，而不是偏移。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
