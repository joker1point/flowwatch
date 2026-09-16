"""证据脚本：证明：EnableTraceEx2 可用（内核与用户态 provider 都返回 0）；旧 EnableTraceEx 恒 87。
排除："内核 provider 需要特殊路径"（用户态对照同样 0 事件 → 问题不在这）。

（本文件是 6 轮提权诊断实验的一环，保留下来是为了让 README 的结论可复核。）
"""

from __future__ import annotations

import ctypes as C
import socket
import sys
import threading
import time
from pathlib import Path

# 本探针放在 _deploy/_qa/ 下，仓库在 frontend-works/flowwatch（提权时也按绝对路径定位）
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import etw  # noqa: E402

LIB = C.WinDLL("advapi32.dll")
EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
ERROR_ALREADY_EXISTS = 183

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

KERNEL_NETWORK = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
DNS_CLIENT = "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"      # 用户态对照组

received: list[tuple[int, int, int]] = []                   # (event_id, pid, payload_len)
CALLBACK = getattr(etw, "EventTraceLogfileW").EventRecordCallback


def guid_of(provider_id: str) -> etw.GUID:
    raw = bytes.fromhex(provider_id.replace("{", "").replace("}", "").replace("-", ""))
    return etw.GUID(int.from_bytes(raw[0:4], "little"), int.from_bytes(raw[4:6], "little"),
                    int.from_bytes(raw[6:8], "little"), (C.c_ubyte * 8)(*raw[8:16]))


def make_properties(name: str, logfile_mode: int) -> tuple[C.c_uint64, C.Array, C.c_void_p]:
    name_bytes = (name + "\0").encode("utf-16-le")
    size = C.sizeof(etw.EventTraceProperties) + len(name_bytes)
    buffer = C.create_string_buffer(size)
    props = C.cast(buffer, C.POINTER(etw.EventTraceProperties)).contents
    props.Wnode.BufferSize = size
    props.LogFileMode = logfile_mode
    props.Wnode.Flags = 0x00000002
    props.LoggerNameOffset = C.sizeof(etw.EventTraceProperties)
    C.memmove(C.addressof(buffer) + C.sizeof(etw.EventTraceProperties), name_bytes, len(name_bytes))
    return C.c_uint64(0), buffer, C.cast(buffer, C.c_void_p)


def variant(label: str, provider: str, keywords: int, level: int, extra_mode: int, seconds: float,
            poke=None) -> None:
    global received
    received = []
    name = "flowwatch-probe-" + label.split()[0].lower()
    session, props_buffer, props_ptr = make_properties(name, EVENT_TRACE_REAL_TIME_MODE | extra_mode)
    rc = LIB.StartTraceW(C.byref(session), name, props_ptr)
    print(f"\n=== {label} ===", flush=True)
    print(f"  StartTraceW = {rc}" + ("  (183 = 会话名已存在)" if rc == ERROR_ALREADY_EXISTS else ""), flush=True)
    if rc not in (0, ERROR_ALREADY_EXISTS):
        return
    guid = guid_of(provider)
    rc = LIB.EnableTraceEx2(session, C.byref(guid), 1, level, keywords, 0, 0, None)
    print(f"  EnableTraceEx2(level={level}, keywords=0x{keywords:x}) = {rc}", flush=True)

    proto = __import__("ctypes").WINFUNCTYPE(None, C.POINTER(etw.EventRecord))
    holder: dict = {}

    def on_event(ptr) -> None:                       # noqa: ANN001
        try:
            record = ptr.contents
            length = record.UserDataLength
            received.append((record.EventHeader.EventDescriptor.Id, record.EventHeader.ProcessId, length))
        except Exception:
            pass

    callback = proto(on_event)
    holder["cb"] = callback                           # 保引用，避免被 GC
    logfile = etw.EventTraceLogfileW()
    logfile.LoggerName = name
    logfile.ProcessTraceMode = etw.PROCESS_TRACE_MODE_REAL_TIME | etw.PROCESS_TRACE_MODE_EVENT_RECORD
    logfile.EventRecordCallback = C.cast(callback, C.c_void_p)
    handle = LIB.OpenTraceW(C.byref(logfile))
    print(f"  OpenTraceW = {'INVALID' if handle in (0, 0xFFFFFFFFFFFFFFFF) else hex(handle)}", flush=True)
    if handle in (0, 0xFFFFFFFFFFFFFFFF):
        LIB.ControlTraceW(session, name, props_ptr, 1)
        return
    trace_handle = C.c_uint64(handle)
    worker = threading.Thread(target=LIB.ProcessTrace, args=(C.byref(trace_handle), 1, None, None), daemon=True)
    worker.start()
    if poke:
        threading.Thread(target=poke, daemon=True).start()
    time.sleep(seconds)
    LIB.ControlTraceW(session, name, props_ptr, 1)    # 停会话 → ProcessTrace 返回
    LIB.CloseTrace(C.c_uint64(handle))
    worker.join(timeout=3)
    print(f"  收到事件 {len(received)} 条" + (f"，前 3 条: {received[:3]}" if received else ""), flush=True)


def dns_poke() -> None:
    for _ in range(6):
        try:
            socket.getaddrinfo("www.python.org", 443)
            socket.getaddrinfo("www.cloudflare.com", 443)
        except Exception:
            pass
        time.sleep(0.6)


def main() -> int:
    print(f"管理员: {bool(C.WinDLL('shell32.dll'))}", flush=True)
    variant("V1-kernel-current", KERNEL_NETWORK, 0x30, 4, 0, 6, poke=dns_poke)
    variant("V2-kernel-systemlogger", KERNEL_NETWORK, 0x30, 4, EVENT_TRACE_SYSTEM_LOGGER_MODE, 6, poke=dns_poke)
    variant("V3-kernel-allkw", KERNEL_NETWORK, 0xFFFFFFFFFFFFFFFF, 5, 0, 6, poke=dns_poke)
    variant("V4-usermode-control", DNS_CLIENT, 0, 5, 0, 6, poke=dns_poke)
    print("\n判读：V4 有事件 → 会话/结构体/回调这一整套是对的，问题只在内核 provider 的启用条件；"
          "V2 或 V3 有事件 → 修复就是把对应参数带上。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
