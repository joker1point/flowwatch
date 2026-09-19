#!/usr/bin/env python3
"""代理流量异常哨兵 —— 用 flowwatch 历史库盯住代理进程的上行流量。

背景：2026-09-17 单日 FlClash 上行 124 GB（Hysteria2 重传风暴），
6 小时后才被发现。本脚本让同类事件在 30 分钟内就能被看见。

判定（基于代理进程的时间桶数据，两个条件任一命中即告警）：
  A 快速累积：近 60 分钟代理上行 > 10 GB
  B 持续高速：近 30 分钟代理上行 >  5 GB
（正常使用 1 小时上行通常 < 1 GB；事故当天峰值 34 GB/h）

报警方式：桌面告警文件 + 置顶弹窗（带提示音）；同类告警 30 分钟冷却。

用法:
    python proxy_sentinel.py            # 常驻：每 5 分钟检查一次
    python proxy_sentinel.py --once     # 单次检查后退出（适合计划任务）
    python proxy_sentinel.py --test     # 弹一次测试告警（验证通道）
    python proxy_sentinel.py --status   # 只打印当前状态
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import sqlite3
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # flowwatch/
DB = ROOT / "history.db"
STATE = ROOT / "_run" / "sentinel_state.json"

# 代理内核进程名（mihomo 系：FlClash / Clash Verge / 原版；SQLite LIKE 对 ASCII 不区分大小写）
PROXY_LIKE = ("%flclash%", "%mihomo%", "%clash%")

W_MIN, W_WARN, W_ALERT = 600, 1800, 3600               # 10 / 30 / 60 分钟窗
LIMIT_ALERT_GB = 10.0                                  # 60 分钟上行阈值
LIMIT_WARN_GB = 5.0                                    # 30 分钟上行阈值
COOLDOWN = 1800                                        # 同类告警冷却（秒）
CHECK_INTERVAL = 300                                   # 常驻模式周期（秒）

# Catrace「flowwatch-alert」插件（桌面小窗告警）：sidecar 监听的回环端口，按序探测
CATRACE_PORTS = (23457, 23458, 23459)
CATRACE_TIMEOUT = 2.0


def usage(now: float | None = None) -> dict:
    """返回各窗口代理上行/下行与今日累计（GB）。"""
    now = now or time.time()
    where = " OR ".join(["process LIKE ?"] * len(PROXY_LIKE))
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        def agg(seconds: float) -> tuple[float, float]:
            row = conn.execute(
                f"SELECT SUM(out_bytes), SUM(in_bytes) FROM buckets"
                f" WHERE bucket_ts >= ? AND bucket_ts <= ? AND ({where})",
                (now - seconds, now, *PROXY_LIKE),
            ).fetchone()
            return (row[0] or 0) / 1e9, (row[1] or 0) / 1e9

        m10, m30, m60 = agg(W_MIN), agg(W_WARN), agg(W_ALERT)
        today0 = dt.datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0).timestamp()
        row = conn.execute(
            f"SELECT SUM(out_bytes), SUM(in_bytes) FROM buckets"
            f" WHERE bucket_ts >= ? AND bucket_ts <= ? AND ({where})",
            (today0, now, *PROXY_LIKE),
        ).fetchone()
        day = ((row[0] or 0) / 1e9, (row[1] or 0) / 1e9)
    finally:
        conn.close()
    return {"10m": m10, "30m": m30, "60m": m60, "day": day}


def desktop_dir() -> Path:
    home = Path.home()
    for cand in (home / "Desktop", home / "OneDrive" / "Desktop",
                 home / "OneDrive" / "桌面", home / "桌面"):
        if cand.is_dir():
            return cand
    return home


_MSGBOX_FLAGS = 0x30 | 0x1000          # MB_ICONWARNING | MB_TOPMOST
_POPUP_TIMEOUT_MS = 120_000            # 弹窗 120 秒后自动关闭


def _show_popup(title: str, body: str) -> None:
    """置顶警告弹窗。优先用可自动关闭的 MessageBoxTimeoutW：
    用户不在场时不会挂住计划任务实例；桌面文件兜底、冷却到期会再提醒。"""
    u32 = ctypes.windll.user32
    try:
        fn = getattr(u32, "MessageBoxTimeoutW", None)
        if fn is not None:
            fn.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                           ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
            fn.restype = ctypes.c_int
            fn(None, body, title, _MSGBOX_FLAGS, 0, _POPUP_TIMEOUT_MS)
            return
    except Exception:
        pass
    try:  # 老系统兜底：普通弹窗（等待被点掉）
        fn = u32.MessageBoxW
        fn.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        fn(None, body, title, _MSGBOX_FLAGS)
    except Exception:
        pass


def _catrace_notify(title: str, body: str, level: str = "warning") -> bool:
    """把告警推给 Catrace 小窗（本机回环 HTTP）。成功返回 True。"""
    payload = json.dumps({"title": title, "body": body, "level": level},
                         ensure_ascii=False).encode("utf-8")
    for port in CATRACE_PORTS:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/alert",
                data=payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=CATRACE_TIMEOUT) as resp:
                # 严格校验响应体：同端口若是别的程序（例如 Catrace 本体占着 23457），
                # 也可能回 200；只看状态码会误判成功、静默丢告警。
                if resp.status == 200:
                    try:
                        body = json.loads(resp.read(4096).decode("utf-8", "replace"))
                        if isinstance(body, dict) and body.get("ok") is True:
                            return True
                    except Exception:
                        pass
        except Exception:
            continue
    return False


def alert(title: str, body: str) -> None:
    """告警出口：Catrace 小窗优先，置顶弹窗兜底；桌面文件始终留档。"""
    try:
        path = desktop_dir() / "⚠️代理流量告警.txt"
        path.write_text(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S}\n{title}\n\n{body}\n",
                        encoding="utf-8")
    except Exception:
        pass
    if _catrace_notify(title, body, level="warning"):
        print("（已推送 Catrace 小窗）")
        return
    threading.Thread(target=_show_popup, args=(title, body), name="sentinel-popup").start()


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict) -> None:
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def fmt(u: dict) -> str:
    (o10, _), (o30, _), (o60, _) = u["10m"], u["30m"], u["60m"]
    day_o, day_i = u["day"]
    return (f"代理上行  10 分钟 {o10:.2f} GB | 30 分钟 {o30:.2f} GB | 60 分钟 {o60:.2f} GB\n"
            f"今日累计  上行 {day_o:.2f} GB / 下行 {day_i:.2f} GB")


def check(verbose: bool = True) -> int:
    u = usage()
    o30, o60 = u["30m"][0], u["60m"][0]
    if verbose:
        print(fmt(u))
    reason = None
    if o60 > LIMIT_ALERT_GB:
        reason = f"近 60 分钟代理上行 {o60:.1f} GB（阈值 {LIMIT_ALERT_GB:.0f} GB）"
    elif o30 > LIMIT_WARN_GB:
        reason = f"近 30 分钟代理上行 {o30:.1f} GB（阈值 {LIMIT_WARN_GB:.0f} GB）"
    if not reason:
        if verbose:
            print("状态正常。")
        return 0

    now = time.time()
    state = load_state()
    if now - state.get("last_alert_ts", 0) < COOLDOWN:
        if verbose:
            print(f"** 异常：{reason}（冷却期内，不重复弹窗）")
        return 1
    state["last_alert_ts"] = now
    save_state(state)
    alert("⚠️ 代理流量异常",
          f"{reason}\n\n{fmt(u)}\n\n"
          f"2026-09-17 曾以同样形态单日打出 124 GB（hy2 重传风暴）。\n"
          f"建议立即打开 FlClash：切换节点或断开代理。\n"
          f"如果你正在主动上传大文件，可忽略本提醒。")
    print(f"** 已告警：{reason}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="代理流量异常哨兵（数据来自 flowwatch 历史库）")
    ap.add_argument("--once", action="store_true", help="单次检查后退出（适合计划任务）")
    ap.add_argument("--test", action="store_true", help="弹一次测试告警")
    ap.add_argument("--status", action="store_true", help="只打印当前状态")
    args = ap.parse_args()

    if args.test:
        alert("流量哨兵测试",
              "这是一条测试告警：桌面文件 + Catrace 小窗（未装/未启用则退回置顶弹窗）通道正常。\n\n"
              "实际告警会在代理上行异常时自动弹出（阈值：30 分钟 5 GB / 60 分钟 10 GB）。")
        print("测试告警已触发。")
        return 0
    if args.status:
        print(fmt(usage()))
        return 0
    if args.once:
        return check()

    print(f"常驻模式：每 {CHECK_INTERVAL // 60} 分钟检查一次（Ctrl+C 退出）")
    while True:
        try:
            check()
        except Exception as exc:
            print(f"检查失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
