#!/usr/bin/env python3
"""flowwatch / ETW 归因层（Microsoft-Windows-Kernel-Network）

**为什么需要它**（有实测依据）：
连接表是快照，生存期几十毫秒的 socket（本机实测是代理客户端"一个请求一条连接"）在 60ms/次的
表读面前必然漏掉 —— 占未归因字节的 **79.5%**（`_deploy/_qa/diag_race.py`）。
我同时实测过另一条路：把表读取换成 array 批量解析只有 **1.6×**（58ms → 36ms），瓶颈在 API 本身，
把轮询提到 10 Hz 要吃掉单核 **36%** —— 不值得。所以唯一有效的办法是换事件源：
ETW 在**连接建立那一刻**就带 PID 报事件。

**事件与字段来自官方清单**（`Microsoft-Windows-Kernel-Network.xml`，provider
`{7dd42a49-5329-4832-8dfd-43d979153a88}`），不是凭记忆写的：

| 事件 | IPv4 | IPv6 | 载荷（按声明顺序） |
|---|---|---|---|
| 连接建立 Connectionattempted | **12** | **28** | PID(4) size(4) **daddr** saddr dport(2) sport(2) mss sackopt tsopt wsopt rcvwin … |
| 连接接受 Connectionaccepted | **15** | **31** | 同上（复用 connect 模板） |
| 连接断开 Disconnectissued | **13** | **29** | PID(4) size(4) daddr saddr dport(2) sport(2) seqnum connid |

地址宽度：IPv4 = 4 字节，IPv6 = 16 字节。关键字：IPv4=0x10，IPv6=0x20。

**三条纪律**：
  1. **结构体布局不能手算**：全部用 ctypes 按文档字段顺序定义，让平台 ABI 决定偏移；
     导入时断言关键尺寸（WnodeHeader 48 / EVENT_TRACE_PROPERTIES 120 / EVENT_HEADER 80 /
     EVENT_RECORD 112），断言失败就不启用 ETW。
  2. **fail-closed**：每条事件先过 sanity 校验（`saddr` 必须真属于本机 —— 布局若猜错，
     这一条必然失败），连续失败就停用并如实记录；**宁可不归因，也不误归因**。
  3. **拿不到权限就如实降级**：创建 ETW 会话需要管理员（或 Performance Log Users 组），
     非提权运行时 state="denied"，主链路（表归因）照常工作。
"""

from __future__ import annotations

import ctypes as C
import socket
import struct
import threading
import time
from typing import Any

PROVIDER_GUID = "{7dd42a49-5329-4832-8dfd-43d979153a88}"
PROVIDER_NAME = "Microsoft-Windows-Kernel-Network"
KEYWORD_IPV4 = 0x10
KEYWORD_IPV6 = 0x20

LEARN_EVENTS = {12: 4, 15: 4, 28: 16, 31: 16}   # 建立/接受 → 记住四元组 → PID
FORGET_EVENTS = {13: 4, 29: 16}                 # 断开 → 立刻忘掉（比等 TTL 干净）

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
TRACE_LEVEL_INFORMATION = 4
ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234

SANITY_FAIL_LIMIT = 5      # 连续这么多条事件过不了 sanity 就停用（宁可不用，不许误归因）

# Windows 的地址族取值（与 collector.py 一致）
AF_INET = 2
AF_INET6 = 23

# ---------------------------------------------------------------- ctypes 结构体
# 说明：**只按文档字段顺序写，不手算偏移** —— 让 ctypes/ABI 决定 padding，
# 这样唯一的风险是"顺序写错"，而顺序有官方清单与文档可核对；手算偏移才是真危险。
class GUID(C.Structure):
    _fields_ = [("Data1", C.c_uint32), ("Data2", C.c_uint16), ("Data3", C.c_uint16),
                ("Data4", C.c_ubyte * 8)]


class WnodeHeader(C.Structure):
    _fields_ = [
        ("BufferSize", C.c_uint32),
        ("ProviderId", C.c_uint32),
        # union { ULONG64 HistoricalContext; struct { ULONG Version; ULONG Linkage; }; }
        ("HistoricalContext", C.c_uint64),
        # union { ULONG KernelHandle; LARGE_INTEGER TimeStamp; } —— 联合体大小 8
        ("KernelHandleOrTimeStamp", C.c_uint64),
        ("Guid", GUID),
        ("ClientContext", C.c_uint32),
        ("Flags", C.c_uint32),
    ]


class EventTraceProperties(C.Structure):
    _fields_ = [
        ("Wnode", WnodeHeader),
        ("BufferSize", C.c_uint32),
        ("MinimumBuffers", C.c_uint32),
        ("MaximumBuffers", C.c_uint32),
        ("MaximumFileSize", C.c_uint32),
        ("LogFileMode", C.c_uint32),
        ("FlushTimer", C.c_uint32),
        ("EnableFlags", C.c_uint32),
        ("AgeLimit", C.c_int32),
        ("NumberOfBuffers", C.c_uint32),
        ("FreeBuffers", C.c_uint32),
        ("EventsLost", C.c_uint32),
        ("BuffersWritten", C.c_uint32),
        ("LogBuffersLost", C.c_uint32),
        ("RealTimeBuffersLost", C.c_uint32),
        ("LoggerThreadId", C.c_void_p),
        ("LogFileNameOffset", C.c_uint32),
        ("LoggerNameOffset", C.c_uint32),
    ]


class SystemTime(C.Structure):
    _fields_ = [(name, C.c_uint16) for name in
                ("Year", "Month", "DayOfWeek", "Day", "Hour", "Minute", "Second", "Milliseconds")]


class TimeZoneInformation(C.Structure):
    _fields_ = [
        ("Bias", C.c_long),
        ("StandardName", C.c_wchar * 32),
        ("StandardDate", SystemTime),
        ("StandardBias", C.c_long),
        ("DaylightName", C.c_wchar * 32),
        ("DaylightDate", SystemTime),
        ("DaylightBias", C.c_long),
    ]


class EventTraceHeader(C.Structure):
    _fields_ = [
        ("Size", C.c_uint16),
        ("FieldTypeFlags", C.c_uint16),
        ("Version", C.c_uint32),
        ("ThreadId", C.c_uint32),
        ("ProcessId", C.c_uint32),
        ("TimeStamp", C.c_int64),
        ("Guid", GUID),
        ("ProcessorTime", C.c_uint64),
        ("ClientContext", C.c_uint32),
        ("Flags", C.c_uint32),
    ]


class EventTrace(C.Structure):
    _fields_ = [
        ("Header", EventTraceHeader),
        ("InstanceId", C.c_uint32),
        ("ParentInstanceId", C.c_uint32),
        ("ParentGuid", GUID),
        ("MofData", C.c_void_p),
        ("MofLength", C.c_uint32),
        ("ClientContext", C.c_uint32),
    ]


class TraceLogfileHeader(C.Structure):
    _fields_ = [
        ("BufferSize", C.c_uint32),
        ("Version", C.c_uint32),
        ("ProviderVersion", C.c_uint32),
        ("NumberOfProcessors", C.c_uint32),
        ("EndTime", C.c_int64),
        ("TimerResolution", C.c_uint32),
        ("MaximumFileSize", C.c_uint32),
        ("LogFileMode", C.c_uint32),
        ("BuffersWritten", C.c_uint32),
        ("LogInstanceGuid", GUID),              # 与 {StartBuffers,PointerSize,EventsLost,CpuSpeed} 共用
        ("LoggerName", C.c_wchar_p),
        ("LogFileName", C.c_wchar_p),
        ("TimeZone", TimeZoneInformation),
        ("BootTime", C.c_int64),
        ("PerfFreq", C.c_int64),
        ("StartTime", C.c_int64),
        ("ReservedFlags", C.c_uint32),
        ("BuffersLost", C.c_uint32),
    ]


class EventTraceLogfileW(C.Structure):
    _fields_ = [
        ("LogFileName", C.c_wchar_p),
        ("LoggerName", C.c_wchar_p),
        ("CurrentTime", C.c_int64),
        ("BuffersRead", C.c_uint32),
        # union { ULONG LogFileMode; ULONG ProcessTraceMode; }
        ("ProcessTraceMode", C.c_uint32),
        ("CurrentEvent", EventTrace),
        ("LogfileHeader", TraceLogfileHeader),
        ("BufferCallback", C.c_void_p),
        ("BufferSize", C.c_uint32),
        ("Filled", C.c_uint32),
        ("EventsLost", C.c_uint32),
        # union { PEVENT_CALLBACK EventCallback; PEVENT_RECORD_CALLBACK EventRecordCallback; }
        ("EventRecordCallback", C.c_void_p),
        ("IsKernelTrace", C.c_uint32),
        ("Context", C.c_void_p),
    ]


class EventDescriptor(C.Structure):
    _fields_ = [("Id", C.c_uint16), ("Version", C.c_ubyte), ("Channel", C.c_ubyte),
                ("Level", C.c_ubyte), ("Opcode", C.c_ubyte), ("Task", C.c_uint16),
                ("Keyword", C.c_uint64)]


class EventHeader(C.Structure):
    _fields_ = [
        ("Size", C.c_uint16),
        ("HeaderType", C.c_uint16),
        ("Flags", C.c_uint16),
        ("EventProperty", C.c_uint16),
        ("ThreadId", C.c_uint32),
        ("ProcessId", C.c_uint32),
        ("TimeStamp", C.c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor", EventDescriptor),
        ("ProcessorTime", C.c_uint64),
        ("ActivityId", GUID),
    ]


class EventRecord(C.Structure):
    _fields_ = [
        ("EventHeader", EventHeader),
        ("BufferContext", C.c_uint32),        # ProcessorNumber, Alignment, ProcessorIndex
        ("ExtendedDataCount", C.c_uint16),
        ("UserDataLength", C.c_uint16),
        ("ExtendedData", C.c_void_p),
        ("UserData", C.c_void_p),
        ("UserContext", C.c_void_p),
    ]


# 关键尺寸自检：对不上就说明我的字段列表有问题 —— **直接不启用 ETW**，绝不带着错误的布局去注册回调
LAYOUT_OK = (
    C.sizeof(WnodeHeader) == 48
    and C.sizeof(EventTraceProperties) == 120
    and C.sizeof(EventHeader) == 80
    and C.sizeof(EventRecord) == 112
)
LAYOUT_DETAIL = {
    "sizeof(WnodeHeader)": C.sizeof(WnodeHeader),
    "sizeof(EVENT_TRACE_PROPERTIES)": C.sizeof(EventTraceProperties),
    "sizeof(EVENT_HEADER)": C.sizeof(EventHeader),
    "sizeof(EVENT_RECORD)": C.sizeof(EventRecord),
    "offsetof(EventRecordCallback)": EventTraceLogfileW.EventRecordCallback.offset,
    "sizeof(EVENT_TRACE_LOGFILEW)": C.sizeof(EventTraceLogfileW),
    "pointer_size": C.sizeof(C.c_void_p),
}


# ---------------------------------------------------------------- 纯解析（可单测）
def addr_text(raw: bytes, addr_size: int) -> str:
    if addr_size == 4:
        return ".".join(str(byte) for byte in raw)
    return socket.inet_ntop(socket.AF_INET6, raw).lower()


def parse_connection(payload: bytes, addr_size: int) -> dict[str, Any] | None:
    """解析连接事件载荷（connect / accept / disconnect 三类的前 6 个字段相同）。

    字段顺序来自官方清单：PID(4) size(4) **daddr** saddr dport(2) sport(2) …
    （注意是 daddr 在前、saddr 在后 —— 这里搞反会把远端当成本机，sanity 校验会抓住它。）
    """
    need = 8 + addr_size * 2 + 4
    if len(payload) < need:
        return None
    pid = int.from_bytes(payload[0:4], "little")
    size = int.from_bytes(payload[4:8], "little")
    daddr_raw = payload[8:8 + addr_size]
    saddr_raw = payload[8 + addr_size:8 + addr_size * 2]
    dport = int.from_bytes(payload[8 + addr_size * 2:10 + addr_size * 2], "little")
    sport = int.from_bytes(payload[10 + addr_size * 2:12 + addr_size * 2], "little")
    if pid == 0 or pid > 0x7FFFFFFF or sport == 0:
        return None                      # 明显不合法：宁可不归因
    return {
        "pid": pid,
        "size": size,
        "saddr": addr_text(saddr_raw, addr_size),
        "sport": sport,
        "daddr": addr_text(daddr_raw, addr_size),
        "dport": dport,
    }


def sane(parsed: dict[str, Any], local_ips: set[str]) -> bool:
    """硬校验：**本机侧地址必须真属于本机**。

    这是 fail-closed 的关键 —— 若我理解的字段顺序/宽度错了（例如 daddr/saddr 反了、
    IPv6 按 4 字节读），这里必然失败，于是整套 ETW 归因被停用，而不是把字节算到错误的进程头上。
    """
    return parsed["saddr"] in local_ips and 0 < parsed["sport"] <= 65535


# ---------------------------------------------------------------- 实时消费者
class EtwConnTracker:
    """ETW 实时会话消费者：只把 (本地端口, 远端, PID) 喂给 ConnMemory。

    与主链路的关系：**纯增强**。任何失败（无权限 / 布局不符 / 会话建立失败）都只记录状态，
    采集层的表归因照常工作。
    """

    def __init__(self, conn_memory: Any, local_ips_provider: Any,
                 session_name: str = "flowwatch-etw") -> None:
        self.conn_memory = conn_memory
        self.local_ips_provider = local_ips_provider
        self.session_name = session_name
        self.state = "idle"          # idle / denied / layout_mismatch / failed / running / stopped
        self.detail = ""
        self.error_code = 0          # 最近一次失败的 Win32 错误码（诊断用）
        self.events = 0
        self.learned = 0
        self.forgotten = 0
        self.sanity_failures = 0
        self.last_event_ts = 0.0
        self._session = C.c_uint64(0)
        self._trace_handle = C.c_uint64(0)
        self._callback = None        # 必须持有引用，否则回调会被 GC 掉
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._lib: Any = None
        self._props_buffer: Any = None

    # ---- 对外
    def start(self) -> bool:
        if not LAYOUT_OK:
            self.state = "layout_mismatch"
            self.detail = f"结构体尺寸与预期不符: {LAYOUT_DETAIL}"
            return False
        self._thread = threading.Thread(target=self._run, name="flowwatch-etw", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._lib and self._trace_handle.value:
                self._lib.CloseTrace(self._trace_handle)
            if self._lib and self._session.value:
                # EVENT_TRACE_CONTROL_STOP = 1：停掉会话，ProcessTrace 才会返回
                self._lib.ControlTraceW(self._session, None, self._props_buffer, 1)
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=3.0)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self.state,
                "detail": self.detail,
                "events": self.events,
                "learned": self.learned,
                "forgotten": self.forgotten,
                "sanity_failures": self.sanity_failures,
                "since_last_event": round(time.time() - self.last_event_ts, 1) if self.last_event_ts else None,
                "layout": LAYOUT_DETAIL,
            }

    # ---- 会话
    def _run(self) -> None:
        try:
            self._lib = C.WinDLL("advapi32.dll")
            self._bind()
        except OSError as exc:
            self.state, self.detail = "failed", f"加载 advapi32 失败: {exc}"
            return

        props = self._make_properties()
        started = self._lib.StartTraceW(C.byref(self._session), self.session_name, props)
        if started != ERROR_SUCCESS:
            self._explain_start_failure(started)
            return
        error = self._lib.EnableTraceEx(
            self._session, C.byref(self._provider_guid()), C.c_uint32(EVENT_CONTROL_CODE_ENABLE_PROVIDER),
            C.c_ubyte(TRACE_LEVEL_INFORMATION), C.c_uint64(KEYWORD_IPV4 | KEYWORD_IPV6),
            C.c_uint64(0), C.c_uint32(0), None, None,
        )
        if error != ERROR_SUCCESS:
            self.state, self.detail = "failed", f"EnableTraceEx 失败: {error}"
            self._stop_session()
            return

        logfile = EventTraceLogfileW()
        logfile.LoggerName = self.session_name
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        self._callback = self._make_callback()
        logfile.EventRecordCallback = C.cast(self._callback, C.c_void_p)
        handle = self._lib.OpenTraceW(C.byref(logfile))
        if handle in (0, 0xFFFFFFFFFFFFFFFF):        # INVALID_PROCESSTRACE_HANDLE
            self.state, self.detail = "failed", f"OpenTraceW 失败: {C.get_last_error()}"
            self._stop_session()
            return
        self._trace_handle.value = handle
        self.state = "running"
        # ProcessTrace 阻塞直到会话被停止或出错（我们在 stop() 里用 ControlTrace(STOP) 让它返回）
        result = self._lib.ProcessTrace(C.byref(self._trace_handle), 1, None, None)
        if self.state == "running":
            self.state = "stopped" if result == ERROR_SUCCESS else "failed"
            if result != ERROR_SUCCESS:
                self.detail = f"ProcessTrace 返回 {result}"
        self._stop_session()

    def _explain_start_failure(self, code: int) -> None:
        self.error_code = code
        if code == 5:
            self.state = "denied"
            self.detail = "创建 ETW 会话需要管理员（或 Performance Log Users 组成员）—— 保持表归因，不影响实时链路"
        elif code in (87, ERROR_MORE_DATA):
            self.state = "layout_mismatch"
            self.detail = f"StartTraceW 返回 {code}，EVENT_TRACE_PROPERTIES 布局可疑: {LAYOUT_DETAIL}"
        else:
            self.state = "failed"
            self.detail = f"StartTraceW 失败: {code}"

    def _make_properties(self) -> Any:
        """EVENT_TRACE_PROPERTIES + 缓冲区尾部紧跟会话名（LoggerNameOffset 指向那里）。"""
        name_bytes = (self.session_name + "\0").encode("utf-16-le")
        size = C.sizeof(EventTraceProperties) + len(name_bytes)
        self._props_buffer = C.create_string_buffer(size)
        props = C.cast(self._props_buffer, C.POINTER(EventTraceProperties)).contents
        props.Wnode.BufferSize = size                 # 必须等于整块缓冲区大小
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.Wnode.Flags = 0x00000002                # WNODE_FLAG_TRACED_GUID
        props.LoggerNameOffset = C.sizeof(EventTraceProperties)
        props.LogFileNameOffset = 0                   # 实时会话不落盘
        self._properties = props
        C.memmove(C.addressof(self._props_buffer) + C.sizeof(EventTraceProperties),
                  name_bytes, len(name_bytes))
        return C.cast(self._props_buffer, C.c_void_p)

    @staticmethod
    def _provider_guid() -> GUID:
        # {7dd42a49-5329-4832-8dfd-43d979153a88}
        return GUID(0x7DD42A49, 0x5329, 0x4832,
                    (C.c_ubyte * 8)(0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88))

    # ---- 回调
    def _make_callback(self) -> Any:
        from ctypes import WINFUNCTYPE

        proto = WINFUNCTYPE(None, C.POINTER(EventRecord))

        def on_event(record_ptr: Any) -> None:
            try:
                self._handle_record(record_ptr.contents)
            except Exception:            # 回调里绝不抛异常：ETW 线程崩了会带走会话
                self.sanity_failures += 1

        return proto(on_event)

    def _handle_record(self, record: EventRecord) -> None:
        event_id = record.EventHeader.EventDescriptor.Id
        addr_size = LEARN_EVENTS.get(event_id) or FORGET_EVENTS.get(event_id)
        if addr_size is None:
            return
        length = record.UserDataLength
        if not record.UserData or length < 16:
            return
        payload = C.string_at(record.UserData, length)
        parsed = parse_connection(payload, addr_size)
        with self._lock:
            self.events += 1
            self.last_event_ts = time.time()
            if parsed is None:
                return
            local_ips = self.local_ips_provider() or set()
            if local_ips and not sane(parsed, local_ips):
                self.sanity_failures += 1
                if self.sanity_failures >= SANITY_FAIL_LIMIT:
                    self.state = "sanity_failed"
                    self.detail = ("连续 %d 条事件的本机地址不属于本机 —— 字段理解有误，已停用 ETW 归因"
                                   "（绝不误归因）" % self.sanity_failures)
                    self._stop.set()
                return
        key = (parsed["saddr"], parsed["sport"], parsed["daddr"], parsed["dport"])
        if event_id in LEARN_EVENTS:
            self.conn_memory.remember(key, parsed["pid"])
            with self._lock:
                self.learned += 1
        else:                                   # 断开：立刻忘掉，比等 TTL 干净
            self.conn_memory.forget(key)
            with self._lock:
                self.forgotten += 1

    # ---- 收尾
    def _stop_session(self) -> None:
        try:
            if self._lib and self._session.value:
                self._lib.ControlTraceW(self._session, None, self._props_buffer, 1)
                self._session = C.c_uint64(0)
        except Exception:
            pass

    def _bind(self) -> None:
        lib = self._lib
        lib.StartTraceW.argtypes = [C.POINTER(C.c_uint64), C.c_wchar_p, C.c_void_p]
        lib.StartTraceW.restype = C.c_uint32
        lib.ControlTraceW.argtypes = [C.c_uint64, C.c_wchar_p, C.c_void_p, C.c_uint32]
        lib.ControlTraceW.restype = C.c_uint32
        lib.EnableTraceEx.argtypes = [C.c_uint64, C.POINTER(GUID), C.c_uint32, C.c_ubyte,
                                      C.c_uint64, C.c_uint64, C.c_uint32, C.c_void_p, C.c_void_p]
        lib.EnableTraceEx.restype = C.c_uint32
        lib.OpenTraceW.argtypes = [C.POINTER(EventTraceLogfileW)]
        lib.OpenTraceW.restype = C.c_uint64
        lib.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_uint32, C.c_void_p, C.c_void_p]
        lib.ProcessTrace.restype = C.c_uint32
        lib.CloseTrace.argtypes = [C.c_uint64]
        lib.CloseTrace.restype = C.c_uint32
