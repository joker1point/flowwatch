#!/usr/bin/env python3
"""flowwatch / API 层

在采集层之上提供实时速率接口，**结构刻意与 portwatch 保持同构**（单例采集 + SSE 增量）：

    GET /api/health  —— 采集状态（设备、包数、未归因比例、端点表成本、订阅数）
    GET /api/meta    —— 参数（采样窗口、端点刷新周期、schema）
    GET /api/rates   —— 当前窗口的按进程速率快照
    GET /api/stream  —— SSE：首帧 snapshot，之后每秒一帧 rates，15s 空闲发 heartbeat

两个与 portwatch 一致的安全约定：
  1. 只监听 127.0.0.1 —— 流量数据比端口数据更敏感，绝不暴露到局域网；
  2. CORS 只放行 localhost。

与 portwatch 的一个关键区别：**速率是每秒刷新的连续量**，因此 SSE 推的是"窗口速率"这一
时间序列快照（不是事件增量）；历史留档也必须是时间桶聚合，不能逐条落事件表。

用法:
    python server.py                 # → http://127.0.0.1:8788
    python server.py --dev WLAN --port 8789
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

import assistant
import collector
import history
import localconn
import notes

logger = logging.getLogger("flowwatch.server")

HOST = "127.0.0.1"
PORT = 8788
HISTORY_DB = Path(__file__).with_name("history.db")   # 与项目同目录，便于连同库一起备份
FLUSH_INTERVAL = 1.0        # 速率窗口：每秒出一次速率
TOP_N = 50                  # 单帧最多带多少个进程（前端只渲染可见范围）
SSE_IDLE = 15.0             # 传输层心跳
# 历史保留/查询上限（天）：--retention-days 的默认值 + 四个 history 接口的 minutes 上限共用这一个数。
# 改动提醒：history.HistoryStore 的 retention_days 默认值也表达同一语义，两处要一起改。
HISTORY_MAX_DAYS = 30


class NameCache:
    """pid → 进程名，带缓存与宽限期。

    三条约束（都有实测依据）：
      1. 每帧都问一遍很贵（每秒几十个 pid × psutil.Process）→ 必须缓存；
      2. **"?" 不能永久缓存**：进程可能是刚启动、名字还取不到，下次要再试；
      3. **进程消失后名字要留一会儿**（宽限 10 分钟）：否则历史层给"消失"事件落库时
         进程早已不在，事件里只剩 `?` —— 而"它走了"恰恰是最需要名字的时刻（实测踩到）。
    """

    GRACE = 600.0     # 进程不在当前帧里之后，名字仍保留这么久
    RETRY = 5.0       # "?" 只缓存这么久，允许重试

    def __init__(self) -> None:
        self._names: dict[int, tuple[str, float]] = {}

    def name(self, pid: int) -> str:
        now = time.monotonic()
        cached = self._names.get(pid)
        if cached is not None:
            value, stamp = cached
            if value != "?" or now - stamp < self.RETRY:
                return value
        if pid < 0:
            # 端点已知但属主拿不到（非提权调用）：如实标注，不冒充任何进程
            name = "（属主受限·需管理员）"
        else:
            try:
                name = psutil.Process(pid).name()
            except Exception:
                name = "?"
        self._names[pid] = (name, now)
        return name

    def prune(self, alive: set[int]) -> None:
        now = time.monotonic()
        for pid, (_name, stamp) in list(self._names.items()):
            if pid not in alive and now - stamp > self.GRACE:
                self._names.pop(pid, None)


class RateHub:
    """把采集层的窗口速率变成对外帧，并广播给所有 SSE 订阅者。"""

    def __init__(self, capturer: collector.Capturer) -> None:
        self.capturer = capturer
        self.names = NameCache()
        self.subscribers: set[asyncio.Queue] = set()
        self.latest: dict[str, Any] = {}
        self.frames = 0
        # 本机连接归属：抓包看不到环回与代理那一层，按系统连接表补上（见 localconn.py）
        self.localconn = localconn.LocalConnTable()

    def describe(self, remote: str) -> dict[str, Any]:
        """给一条连接附上域名（拿不到就是 None，不猜）。"""
        found = self.capturer.resolver.describe(remote)
        if found is None:
            return {"name": None, "name_source": None}
        return {"name": found["name"], "name_source": found["source"]}

    # ---- 帧构造
    def build_frame(self, window: dict[str, Any]) -> dict[str, Any]:
        agg = self.capturer.aggregator
        stats = agg.stats()
        secs = max(1e-3, window["window"])
        by_pid = []
        for pid, item in window["by_pid"].items():
            by_pid.append(
                {
                    "pid": pid,
                    "process": self.names.name(pid),
                    "out_bps": item["out_bytes"] / secs,
                    "in_bps": item["in_bytes"] / secs,
                    "packets": item["packets"],
                    "conns": [
                        {
                            **self.describe(conn["remote"]),
                            "remote": conn["remote"],
                            "out_bps": conn["out_bytes"] / secs,
                            "in_bps": conn["in_bytes"] / secs,
                        }
                        for conn in item["conns"]
                    ],
                }
            )
        by_pid.sort(key=lambda row: row["out_bps"] + row["in_bps"], reverse=True)
        self.names.prune({row["pid"] for row in by_pid})

        # 总量按**全部进程**汇总（不只是 Top-N）；未归因字节单独统计，不混进收发速率
        # 属主受限桶：端点已知、但非提权调用拿不到 owning PID（采集层记成哨兵 PID -1）
        masked_bytes = sum(
            item["out_bytes"] + item["in_bytes"]
            for pid, item in window["by_pid"].items()
            if pid < 0
        )
        quality = window.get("quality", {})
        total_out = sum(row["out_bps"] for row in by_pid)
        total_in = sum(row["in_bps"] for row in by_pid)
        unknown = window["unknown_bytes"]
        attributed_bytes = sum(item["out_bytes"] + item["in_bytes"] for item in window["by_pid"].values())
        frame = {
            "schema": collector.SCHEMA,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "window": round(window["window"], 3),
            "totals": {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "packets_window": sum(row["packets"] for row in by_pid) + window["unknown_packets"],
                "unknown_bytes_window": unknown,
                "unknown_ratio": (unknown / (attributed_bytes + unknown)) if (attributed_bytes or unknown) else 0.0,
                "masked_bytes": masked_bytes,      # 端点已知、属主受权限限制的那部分
                # 滚动口径（近 N 个窗口的合计比率）：单窗口比率在空闲窗口会因为分母太小而剧烈波动
                "unknown_ratio_rolling": quality.get("unknown_ratio", 0.0),
                "masked_ratio_rolling": quality.get("masked_ratio", 0.0),
                "rolling_windows": quality.get("windows", 0),
                "out_bps": total_out,
                "in_bps": total_in,
                "foreign_packets": stats["foreign_packets"],    # 别人的流量：不算本机、也不算未归因
                "skipped_packets": stats["skipped_packets"],    # 非 TCP/UDP 或头部不全
            },
            "unknown_flows": window.get("unknown_flows", []),   # 未归因明细（前 8 条，诊断用）
            "domains": window.get("domains", [])[:24],          # 本窗口域名排行（全量连接汇总）
            "by_pid": by_pid[:TOP_N],
            # 本机连接归属（系统连接表快照）：抓包只看得见代理进程，
            # 这里回答"谁在连代理 / 本地服务"—— 重试风暴时按连接数一眼定位（见 localconn.py）
            "local_conns": self.localconn.snapshot(),
        }
        self.latest = frame
        self.frames += 1
        return frame

    # ---- 订阅
    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self.subscribers.discard(queue)

    async def broadcast(self, event: str, payload: dict[str, Any]) -> None:
        for queue in list(self.subscribers):
            try:
                queue.put_nowait((event, payload))
            except asyncio.QueueFull:
                # 消费不过来的连接直接丢弃，绝不拖慢采集
                self.subscribers.discard(queue)

    # ---- 主循环
    async def run(self) -> None:
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            window = self.capturer.aggregator.flush()
            # 先喂历史层再组帧：两者读的是同一份窗口数据，顺序不影响正确性，
            # 但先落库能让"这一分钟"的查询尽快有条目。
            if store.enabled:
                store.submit(window)     # 非阻塞投递：历史层再怎么慢也不会反压实时帧
            frame = self.build_frame(window)
            await self.broadcast("rates", frame)


capturer = collector.Capturer()
hub = RateHub(capturer)
store = history.HistoryStore(HISTORY_DB)

# 流量助手：把只读数据入口注入进去，它自己管工具分级、记忆层与 provider 配置
assistant.configure(hub=hub, store=store, capturer=capturer)


async def _start_capturer() -> None:
    """在后台启动采集层。

    选设备要试抓（每台 1 秒），是阻塞调用 —— 不能挡住 HTTP 服务启动，
    否则页面要在"服务在但没数据"和"连不上服务"之间多等好几秒。
    启动期间 /api/health 的 status 是 degraded，前端可以据此显示"正在选网卡"。
    """
    try:
        await asyncio.to_thread(capturer.start)
        logger.info("采集层已启动，设备: %s", capturer.device_name)
    except Exception as exc:  # PcapError 或任何启动异常：接口照常可用
        capturer.error = f"{type(exc).__name__}: {exc}"
        logger.warning("采集层启动失败（接口仍可用，只是没有数据）: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if store.enabled:
        await asyncio.to_thread(store.open)          # 建表/PRAGMA 是阻塞 IO，别占事件循环
        store.set_name_resolver(hub.names.name)      # 进程名冗余落库：pid 会被复用
        store.start_writer()                         # 写库搬到独立线程：实时链路零等待
        logger.info("历史层已开启: %s（桶 %ds，保留 %g 天）",
                    store.path, store.bucket_seconds, store.retention_days)
    hub.localconn.start()                            # 独立线程：不依赖抓包，随时可用
    starter = asyncio.create_task(_start_capturer(), name="flowwatch-start")
    ticker = asyncio.create_task(hub.run(), name="flowwatch-ticker")
    try:
        yield
    finally:
        hub.localconn.stop()
        for task in (ticker, starter):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await asyncio.to_thread(capturer.stop)
        if store.enabled:
            await asyncio.to_thread(store.close)


app = FastAPI(title="flowwatch API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(assistant.router)

# 笔记区（用户笔记 + AI 每日流量笔记）：注入只读历史库
notes.configure(store=store)
app.include_router(notes.router)


def sse(event: str, payload: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


@app.get("/api/health")
def health() -> dict[str, Any]:
    stats = capturer.aggregator.stats()
    return {
        "status": "ok" if capturer.device_name and not capturer.error else "degraded",
        "device": capturer.device_name,
        "error": capturer.error,                      # 抓包级致命错误（粘性）
        "refresh_error": capturer.refresh_error,      # 刷新级抖动（下次成功即清除）
        "packets": stats["packets"],
        "bytes": stats["bytes"],
        "parse_errors": stats["parse_errors"],
        "endpoint": {
            "source": capturer.index.source,
            "count": capturer.index.endpoints,
            "refresh_ms": round(capturer.index.last_cost_ms, 1),
            "refresh_interval": capturer.index.refresh_interval,
        },
        "subscribers": len(hub.subscribers),
        "frames": hub.frames,
        "last_packet_ts": (datetime.fromtimestamp(capturer.last_packet_ts).isoformat(timespec="seconds")
                           if capturer.last_packet_ts else None),   # 采集静默时一眼可见
        "watchdog": capturer.watchdog_stats(),                        # 看门狗状态（重开次数 / 错误）
        "foreign_packets": stats.get("foreign_packets", 0),   # 别人的流量：不计入本机统计
        "skipped_packets": stats.get("skipped_packets", 0),
        "masked_bytes": stats.get("masked_bytes", 0),         # 端点已知、属主受权限限制
        "sticky_hits": capturer.index.sticky_hits,            # 端点短时记忆救回次数
        "memory_hits": capturer.conn_memory.hits,             # 四元组记忆救回次数
        "attribution_sources": capturer.conn_memory.source_stats(),   # 按来源分账（table / etw / etw-udp）
        "history": store.stats(),
        "names": capturer.resolver.stats(),
        "etw": capturer.etw.stats(),          # 实时路线状态（实验性，默认关闭）
        "etw_batch": capturer.etw_batch.stats(),  # 批量路线状态（opt-in，需管理员）
        "ts": datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/api/meta")
async def meta() -> dict[str, Any]:
    return {
        "schema": collector.SCHEMA,
        "flush_interval": FLUSH_INTERVAL,
        "top_n": TOP_N,
        "endpoint_refresh": capturer.index.refresh_interval,
        "devices": capturer.device_name,
        "snaplen": collector.SNAPLEN,
        "privacy": "只统计元数据（IP/端口/字节数），不保存包体",
    }


@app.get("/api/rates")
async def rates(limit: int = Query(TOP_N, ge=1, le=500)) -> dict[str, Any]:
    frame = hub.latest or hub.build_frame(capturer.aggregator.flush())
    return {**frame, "by_pid": frame["by_pid"][:limit]}


@app.get("/api/history/process")
def history_process(
    pid: int = Query(..., description="进程 PID"),
    minutes: int = Query(60, ge=1, le=60 * 24 * HISTORY_MAX_DAYS),
    bucket: int = Query(1, ge=1, le=60, description="重采样桶宽（分钟）"),
) -> dict[str, Any]:
    """某进程的历史曲线。「它从什么时候开始跑的」看 first_seen。"""
    return store.process_series(pid, minutes=minutes, bucket_minutes=bucket)


@app.get("/api/history/top")
def history_top(
    minutes: int = Query(60, ge=1, le=60 * 24 * HISTORY_MAX_DAYS),
    limit: int = Query(10, ge=1, le=100),
) -> dict[str, Any]:
    """区间内的进程排行（按累计字节），带每个进程的首末观测时刻。"""
    return {"minutes": minutes, "items": store.top_processes(minutes=minutes, limit=limit)}


@app.get("/api/history/timeline")
def history_timeline(
    minutes: int = Query(180, ge=1, le=60 * 24 * HISTORY_MAX_DAYS),
    bucket: int = Query(5, ge=1, le=60),
) -> dict[str, Any]:
    """整机时间序列：已归因 / 属主受限 / 未归因 / 别人的流量 分开给。"""
    return store.timeline(minutes=minutes, bucket_minutes=bucket)


@app.get("/api/events")
def events(
    limit: int = Query(50, ge=1, le=500),
    pid: int | None = Query(None, description="只看某个进程"),
) -> dict[str, Any]:
    """变化事件流：出现 / 消失 / 尖峰 —— 全部由已落库的观测值比较得出。"""
    return {"items": store.events(limit=limit, pid=pid)}


@app.get("/api/history/domains")
def history_domains(
    minutes: int = Query(60, ge=1, le=60 * 24 * HISTORY_MAX_DAYS),
    limit: int = Query(20, ge=1, le=200),
    named_only: bool = Query(False, description="只看有域名的（排除按 IP 归的）"),
) -> dict[str, Any]:
    """区间内的域名排行 —— 回答"哪个域名用了多少流量"。"""
    return {
        "minutes": minutes,
        "named_only": named_only,
        "items": store.top_domains(minutes=minutes, limit=limit, named_only=named_only),
    }


@app.get("/api/stream")
async def stream(request: Request) -> StreamingResponse:
    async def generate():
        queue = hub.subscribe()
        try:
            if hub.latest:
                yield sse("snapshot", hub.latest)
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event, payload = await asyncio.wait_for(queue.get(), timeout=SSE_IDLE)
                except asyncio.TimeoutError:
                    yield sse("heartbeat", {"ts": datetime.now().isoformat(timespec="seconds"),
                                            "frames": hub.frames})
                    continue
                yield sse(event, payload)
        finally:
            hub.unsubscribe(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


def main(argv: list[str] | None = None) -> int:
    global FLUSH_INTERVAL, PORT
    parser = argparse.ArgumentParser(description="flowwatch API 层")
    parser.add_argument("--dev", help="抓包设备名/描述片段（默认自动挑最忙的）")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--interval", type=float, default=FLUSH_INTERVAL, help="速率窗口（秒）")
    parser.add_argument("--db", default=str(HISTORY_DB), help="历史库路径（SQLite）")
    parser.add_argument("--retention-days", type=float, default=float(HISTORY_MAX_DAYS),
                        help="时间桶保留天数（默认 30）")
    parser.add_argument("--no-history", action="store_true", help="不落历史（纯实时模式）")
    parser.add_argument("--etw", action="store_true",
                        help="实时消费 ETW 补全归因（需管理员；非提权时如实降级为 denied，不影响实时链路）")
    parser.add_argument("--etw-udp", action="store_true",
                        help="配合 --etw：额外消费 UDP 事件（opt-in，覆盖 DNS 等；事件量大且内容不齐，见 etw.py 头部）")
    args = parser.parse_args(argv)

    PORT = args.port
    FLUSH_INTERVAL = args.interval
    if args.dev:
        capturer.device = args.dev
    capturer.use_etw = args.etw      # 必须在 lifespan 启动采集层之前设置（它在 Capturer.start 里生效）
    capturer.use_etw_udp = args.etw_udp
    store.path = Path(args.db)
    store.retention_days = args.retention_days
    store.enabled = not args.no_history

    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
