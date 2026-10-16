#!/usr/bin/env python3
"""flowwatch / 进程流量告警规则引擎。

**它是什么**：`scripts/proxy_sentinel.py`（2026-09-17 单日上行 124GB 事故催生）的泛化版——
从「写死代理进程 + 两个固定阈值」升级为「任意进程 × 可组合条件 × Web 配置」。
首次启用会把 sentinel 的保护等价种为默认规则，原脚本与计划任务可随后退役。

**两类条件（可同规则叠加，match=any 任一命中 / all 全部命中）**：
  · window_bytes      窗口累计流量超限（如「近 60 分钟上行 > 10 GB」）
  · sustained_minutes 持续传输时长超限（如「连续忙 60 分钟不休息」）
      —— 分钟桶缺列（采集断过的分钟）视为断裂，不把断线时段算成连续（诚实优先）。

**告警出口**（与 sentinel / patrol 同源，随产品自包含）：
桌面文件留档 + Catrace「flowwatch-alert」小窗（未装/未启用则置顶弹窗兜底，120s 自动关闭）。
每条规则独立冷却（默认 30 分钟），冷却期内命中不重复弹。

**数据源**：只读 flowwatch 历史库 buckets 表（bucket_ts / pid / process / out_bytes / in_bytes）。

用法（被 server.py 集成；也可独立）：
    python alert_rules.py --check     # 立即评估一轮（命中即告警）
    python alert_rules.py --status    # 只打印各规则当前值
    python alert_rules.py --test      # 弹一次测试告警（验证通道）
"""
from __future__ import annotations

import argparse
import ctypes
import json
import logging
import secrets
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import datadir

logger = logging.getLogger("flowwatch.alert_rules")

RULES_PATH = datadir.data_path("alert_rules.json")
CHECK_INTERVAL = 300                      # 后台评估周期（秒）
CATRACE_PORTS = (23457, 23458, 23459)     # Catrace「flowwatch-alert」插件：sidecar 回环端口
CATRACE_TIMEOUT = 2.0
_POPUP_FLAGS = 0x30 | 0x1000              # MB_ICONWARNING | MB_TOPMOST
_POPUP_TIMEOUT_MS = 120_000               # 弹窗 120 秒自动关闭（用户不在场不挂住）

_DIRECTIONS = ("out", "in", "total")
_CONDITION_TYPES = ("window_bytes", "sustained_minutes")
_MAX_WINDOW_MINUTES = 1440                # 单条件最长考察 24 小时
_MAX_CONDITIONS = 6

router = APIRouter()
_lock = threading.Lock()
_db_path: Path | None = None              # server 启动时注入（history.db 路径）
_stop = threading.Event()
_thread: threading.Thread | None = None


# ---------------------------------------------------------------- 规则模型

def _new_id() -> str:
    return "r_" + secrets.token_hex(4)


def default_rules() -> list[dict]:
    """首次启用时种入的保护（sentinel 等价 + 用户点名的持续形态）。"""
    return [
        {
            "id": _new_id(),
            "name": "大流量上传（通用保护）",
            "processes": ["%"],
            "enabled": True,
            "match": "any",
            "conditions": [
                {"type": "window_bytes", "window_minutes": 60,
                 "bytes": 10 * 1024 ** 3, "direction": "out"},
                {"type": "window_bytes", "window_minutes": 30,
                 "bytes": 5 * 1024 ** 3, "direction": "out"},
            ],
            "cooldown_minutes": 30,
            "note": "全机大流量上行兜底（% = 所有进程；2026-09-17 单日上行 124GB 的事故形态催生）",
        },
        {
            "id": _new_id(),
            "name": "持续传输提醒（全机）",
            "processes": ["%"],
            "enabled": False,          # 默认关：常开代理的机器上会周期性触发，由用户按需开启
            "match": "any",
            "conditions": [
                {"type": "sustained_minutes", "minutes": 60},
            ],
            "cooldown_minutes": 60,
            "note": "某进程连续传输超过 1 小时即提醒（被挂去长时间上传/下载时的形态）；默认关闭——需要时在面板一键开",
        },
    ]


def _load() -> dict:
    try:
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            return data
    except Exception:
        pass
    return {"version": 1, "rules": []}


def _save(data: dict) -> None:
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    RULES_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def configure(db_path: Path | None = None) -> None:
    """server 启动时注入 history.db 路径；首次调用种入默认规则。"""
    global _db_path
    with _lock:
        _db_path = db_path
        data = _load()
        if not data["rules"]:
            data["rules"] = default_rules()
            _save(data)
            logger.info("已种入默认告警规则 %d 条：%s", len(data["rules"]), RULES_PATH)


# ---------------------------------------------------------------- 评估引擎（纯查询 + 纯计算）

def _like_clause(processes: list[str]) -> tuple[str, list[str]]:
    where = " OR ".join(["process LIKE ?"] * len(processes))
    return f"({where})", list(processes)


def _sum_expr(direction: str) -> str:
    if direction == "out":
        return "SUM(out_bytes)"
    if direction == "in":
        return "SUM(in_bytes)"
    return "SUM(out_bytes + in_bytes)"


def _window_bytes(conn: sqlite3.Connection, processes: list[str],
                  window_minutes: int, direction: str, now: float) -> int:
    where, params = _like_clause(processes)
    row = conn.execute(
        f"SELECT {_sum_expr(direction)} FROM buckets"
        f" WHERE bucket_ts >= ? AND bucket_ts <= ? AND {where}",
        (int(now - window_minutes * 60), int(now), *params),
    ).fetchone()
    return int(row[0] or 0)


def _sustained_minutes(conn: sqlite3.Connection, processes: list[str],
                       minutes: int, now: float) -> tuple[int, bool]:
    """从最新桶往前数连续活跃的分钟数。返回 (连续分钟数, 当前是否正在传)。

    分钟桶缺列（采集断过的分钟没有行）= 断裂，从断点后重新起算——
    绝不把"没采到"的时段算成"一直在传"。
    """
    where, params = _like_clause(processes)
    rows = conn.execute(
        f"SELECT bucket_ts / 60 AS m, SUM(out_bytes + in_bytes) AS b FROM buckets"
        f" WHERE bucket_ts >= ? AND bucket_ts <= ? AND {where}"
        f" GROUP BY m ORDER BY m DESC",
        (int(now - minutes * 60), int(now), *params),
    ).fetchall()
    if not rows:
        return 0, False
    latest = rows[0][0]
    streak = 0
    expect = latest
    for m, b in rows:
        if m != expect:
            break                      # 中间缺了分钟（断裂）或已超出考察窗
        if not b:
            break                      # 这一分钟没有任何流量：连续到此为止
        streak += 1
        expect -= 1
    return streak, bool(rows[0][1])


def rule_status(conn: sqlite3.Connection, rule: dict, now: float) -> dict:
    """一条规则的当前状态：每个条件的当前值与命中情况（不弹告警）。"""
    processes = rule.get("processes") or []
    conds: list[dict] = []
    hits = 0
    for c in rule.get("conditions") or []:
        entry: dict[str, Any] = {"type": c["type"]}
        if c["type"] == "window_bytes":
            value = _window_bytes(conn, processes, c["window_minutes"],
                                  c.get("direction", "total"), now)
            entry.update(window_minutes=c["window_minutes"], direction=c.get("direction", "total"),
                         threshold=c["bytes"], current=value)
            entry["hit"] = value >= c["bytes"]
        elif c["type"] == "sustained_minutes":
            streak, active = _sustained_minutes(conn, processes, c["minutes"], now)
            entry.update(minutes=c["minutes"], current=streak, active=active)
            entry["hit"] = streak >= c["minutes"]
        else:
            entry.update(hit=False, error=f"未知条件类型 {c['type']}")
        hits += 1 if entry.get("hit") else 0
        conds.append(entry)
    match = rule.get("match", "any")
    hit = all(e.get("hit") for e in conds) if match == "all" else any(e.get("hit") for e in conds)
    cooldown = rule.get("cooldown_minutes", 30) * 60
    last = float(rule.get("last_alert_ts") or 0)
    return {
        "conditions": conds,
        "hit": bool(hit) and bool(conds),
        "matched": hits,
        "cooling": bool(last) and (now - last) < cooldown,
        "cooldown_left_min": max(0, int((cooldown - (now - last)) / 60)) if last else 0,
        "last_alert_ts": last or None,
    }


def evaluate_all(now: float | None = None) -> list[dict]:
    """所有规则的当前状态（含禁用）。库不存在时返回空状态（服务没采过数据）。"""
    now = now or time.time()
    with _lock:
        rules = _load()["rules"]
        db = _db_path
    if not db or not Path(db).exists():
        return [dict(r, status={"conditions": [], "hit": False, "matched": 0,
                                "cooling": False, "cooldown_left_min": 0,
                                "error": "历史库不存在（采集未启动）"}) for r in rules]
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return [dict(r, status=rule_status(conn, r, now)) for r in rules]
    finally:
        conn.close()


# ---------------------------------------------------------------- 告警出口（sentinel 同源）

def desktop_dir() -> Path:
    home = Path.home()
    for cand in (home / "Desktop", home / "OneDrive" / "Desktop",
                 home / "OneDrive" / "桌面", home / "桌面"):
        if cand.is_dir():
            return cand
    return home


def _catrace_notify(title: str, body: str, level: str = "warning") -> bool:
    payload = json.dumps({"title": title, "body": body, "level": level},
                         ensure_ascii=False).encode("utf-8")
    for port in CATRACE_PORTS:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/alert", data=payload,
                headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
            with urllib.request.urlopen(req, timeout=CATRACE_TIMEOUT) as resp:
                # 严格校验响应体：同端口若是别的程序（例如 Catrace 本体占着 23457），
                # 也可能回 200；只看状态码会误判成功、静默丢告警。
                if resp.status == 200:
                    try:
                        got = json.loads(resp.read(4096).decode("utf-8", "replace"))
                        if isinstance(got, dict) and got.get("ok") is True:
                            return True
                    except Exception:
                        pass
        except Exception:
            continue
    return False


def _show_popup(title: str, body: str) -> None:
    u32 = ctypes.windll.user32
    try:
        fn = getattr(u32, "MessageBoxTimeoutW", None)
        if fn is not None:
            fn.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                           ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
            fn.restype = ctypes.c_int
            fn(None, body, title, _POPUP_FLAGS, 0, _POPUP_TIMEOUT_MS)
            return
    except Exception:
        pass
    try:  # 老系统兜底：普通弹窗（等待被点掉）
        fn = u32.MessageBoxW
        fn.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        fn(None, body, title, _POPUP_FLAGS)
    except Exception:
        pass


def alert(title: str, body: str) -> None:
    """告警出口：桌面文件始终留档；Catrace 小窗优先，未装/未启用则置顶弹窗兜底。"""
    try:
        path = desktop_dir() / "⚠️进程流量告警.txt"
        path.write_text(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n{title}\n\n{body}\n",
                        encoding="utf-8")
    except Exception:
        pass
    if _catrace_notify(title, body):
        logger.info("告警已推送 Catrace 小窗：%s", title)
        return
    threading.Thread(target=_show_popup, args=(title, body), name="alert-popup").start()


def _fmt_hit(entry: dict) -> str:
    if entry["type"] == "window_bytes":
        gb = entry["current"] / 1024 ** 3
        limit = entry["threshold"] / 1024 ** 3
        arrow = {"out": "上行", "in": "下行", "total": "总流量"}[entry.get("direction", "total")]
        return f"近 {entry['window_minutes']} 分钟{arrow} {gb:.2f} GB（阈值 {limit:.2f} GB）"
    return f"持续传输 {entry['current']} 分钟（阈值 {entry['minutes']} 分钟）"


def alert_for_rule(rule: dict, status: dict, test: bool = False) -> None:
    conds = [e for e in status["conditions"] if e.get("hit")]
    procs = "、".join(rule.get("processes") or [])
    title = ("【测试】" if test else "") + f"⚠️ 进程流量告警：{rule['name']}"
    body = (f"进程匹配：{procs}\n"
            f"命中条件（{'任一' if rule.get('match', 'any') == 'any' else '全部'}）：\n"
            + "\n".join(f"  · {_fmt_hit(e)}" for e in conds)
            + f"\n\n时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            + (f"规则备注：{rule['note']}\n" if rule.get("note") else "")
            + "（这是一条按你的阈值规则弹出的提醒，可在 flowwatch 告警面板调整）")
    alert(title, body)


def check_all(now: float | None = None, respect_cooldown: bool = True) -> dict:
    """评估一轮；命中、启用且过冷却的规则弹告警并记录 last_alert_ts。

    返回 {"items": 各规则状态, "alerted": 实际弹了告警的规则 id 列表}——
    alerted 只算真弹的（禁用/冷却中的命中不算），前端提示「已按通道告警」必须与事实一致。
    """
    now = now or time.time()
    items = evaluate_all(now)
    alerted: list[str] = []
    with _lock:
        data = _load()
        by_id = {r.get("id"): r for r in data["rules"]}
        changed = False
        for item in items:
            st = item.get("status") or {}
            rule = by_id.get(item.get("id"))
            if rule is None or not rule.get("enabled") or not st.get("hit"):
                continue
            if respect_cooldown and st.get("cooling"):
                continue
            alert_for_rule(rule, st)
            alerted.append(rule["id"])
            rule["last_alert_ts"] = now
            changed = True
        if changed:
            _save(data)
    return {"items": items, "alerted": alerted}


# ---------------------------------------------------------------- 后台守护循环

def _watch_loop() -> None:
    logger.info("告警评估守护已启动（每 %ds 一轮）", CHECK_INTERVAL)
    while not _stop.wait(CHECK_INTERVAL):
        try:
            check_all()
        except Exception:
            # 单轮失败不退出循环（sentinel 同款纪律）；死因进日志，不留静默死亡
            logger.exception("告警评估一轮失败")


def start_watchdog(interval: int = CHECK_INTERVAL) -> None:
    global _thread, CHECK_INTERVAL
    CHECK_INTERVAL = interval
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_watch_loop, name="flowwatch-alert-watchdog", daemon=True)
    _thread.start()


def stop_watchdog() -> None:
    _stop.set()


# ---------------------------------------------------------------- HTTP 接口（web 配置面板）

def _validate(payload: "RuleIn", existing: dict | None = None) -> dict:
    processes = [p.strip() for p in payload.processes if p and p.strip()]
    if not processes:
        raise HTTPException(status_code=400, detail="至少要有一个进程匹配串")
    if len(processes) > 10:
        raise HTTPException(status_code=400, detail="进程匹配串最多 10 个")
    if len(set(processes)) != len(processes):
        raise HTTPException(status_code=400, detail="进程匹配串重复")
    if not payload.conditions:
        raise HTTPException(status_code=400, detail="至少要有一个条件")
    if len(payload.conditions) > _MAX_CONDITIONS:
        raise HTTPException(status_code=400, detail=f"条件最多 {_MAX_CONDITIONS} 个")
    conds = []
    for c in payload.conditions:
        if c.type == "window_bytes":
            if c.window_minutes is None or not (1 <= c.window_minutes <= _MAX_WINDOW_MINUTES):
                raise HTTPException(status_code=400, detail="考察窗口需在 1~1440 分钟")
            if c.bytes is None or c.bytes < 1024 * 1024:
                raise HTTPException(status_code=400, detail="流量阈值至少 1 MiB")
            if c.direction not in _DIRECTIONS:
                raise HTTPException(status_code=400, detail="方向需为 out / in / total")
            conds.append({"type": "window_bytes", "window_minutes": c.window_minutes,
                          "bytes": c.bytes, "direction": c.direction})
        else:
            if c.minutes is None or not (1 <= c.minutes <= _MAX_WINDOW_MINUTES):
                raise HTTPException(status_code=400, detail="持续时长需在 1~1440 分钟")
            conds.append({"type": "sustained_minutes", "minutes": c.minutes})
    rule = {
        "id": (existing or {}).get("id") or _new_id(),
        "name": payload.name.strip()[:60],
        "processes": processes,
        "enabled": payload.enabled,
        "match": payload.match,
        "conditions": conds,
        "cooldown_minutes": payload.cooldown_minutes,
    }
    for key in ("created_ts", "last_alert_ts", "note"):
        if existing and existing.get(key) is not None:
            rule[key] = existing[key]
    rule.setdefault("created_ts", time.time())
    return rule


class ConditionIn(BaseModel):
    type: str = Field(description="window_bytes / sustained_minutes")
    window_minutes: Optional[int] = None
    bytes: Optional[int] = None
    direction: str = "total"
    minutes: Optional[int] = None


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    processes: list[str] = Field(min_length=1)
    enabled: bool = True
    match: str = "any"
    conditions: list[ConditionIn] = Field(min_length=1)
    cooldown_minutes: int = Field(default=30, ge=0, le=1440)


@router.get("/api/alert-rules")
def list_rules() -> dict[str, Any]:
    return {"items": evaluate_all(), "path": str(RULES_PATH),
            "interval_sec": CHECK_INTERVAL}


@router.post("/api/alert-rules")
def create_rule(payload: RuleIn) -> dict[str, Any]:
    if payload.match not in ("any", "all"):
        raise HTTPException(status_code=400, detail="match 需为 any / all")
    rule = _validate(payload)
    with _lock:
        data = _load()
        data["rules"].append(rule)
        _save(data)
    return {"ok": True, "item": rule}


@router.put("/api/alert-rules/{rule_id}")
def update_rule(rule_id: str, payload: RuleIn) -> dict[str, Any]:
    if payload.match not in ("any", "all"):
        raise HTTPException(status_code=400, detail="match 需为 any / all")
    with _lock:
        data = _load()
        existing = next((r for r in data["rules"] if r.get("id") == rule_id), None)
        if existing is None:
            raise HTTPException(status_code=404, detail="规则不存在")
        rule = _validate(payload, existing)
        data["rules"][data["rules"].index(existing)] = rule
        _save(data)
    return {"ok": True, "item": rule}


@router.delete("/api/alert-rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, Any]:
    with _lock:
        data = _load()
        left = [r for r in data["rules"] if r.get("id") != rule_id]
        if len(left) == len(data["rules"]):
            raise HTTPException(status_code=404, detail="规则不存在")
        data["rules"] = left
        _save(data)
    return {"ok": True}


@router.post("/api/alert-rules/check")
def api_check() -> dict[str, Any]:
    """立即评估一轮（命中且过冷却 → 弹告警）。不等后台周期。"""
    result = check_all()
    items = result["items"]
    return {"ok": True, "alerted": len(result["alerted"]),
            "alerted_ids": result["alerted"], "items": items}


@router.post("/api/alert-rules/{rule_id}/test")
def api_test(rule_id: str) -> dict[str, Any]:
    """用该规则的当前值弹一次告警（无视冷却，验证通道与阈值形态）。"""
    items = evaluate_all()
    item = next((i for i in items if i.get("id") == rule_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    status = item.get("status") or {}
    if status.get("error"):
        raise HTTPException(status_code=409, detail=status["error"])
    alert_for_rule(item, status, test=True)
    return {"ok": True, "status": status}


# ---------------------------------------------------------------- 独立运行（调试 / 计划任务）

def main() -> int:
    ap = argparse.ArgumentParser(description="flowwatch 进程流量告警规则引擎")
    ap.add_argument("--check", action="store_true", help="立即评估一轮（命中即告警）")
    ap.add_argument("--status", action="store_true", help="只打印各规则当前值")
    ap.add_argument("--test", action="store_true", help="弹一次测试告警（验证通道）")
    args = ap.parse_args()

    if args.test:
        alert("flowwatch 告警通道测试",
              "这是一条测试告警：桌面文件 + Catrace 小窗（未装/未启用则退回置顶弹窗）通道正常。\n\n"
              "实际告警按「告警面板」里的规则触发（默认已含代理进程保护规则）。")
        print("测试告警已触发。")
        return 0

    configure(db_path=Path(__file__).resolve().parent / "history.db")
    if args.check:
        result = check_all()
        for item in result["items"]:
            st = item.get("status") or {}
            mark = "🔔" if st.get("hit") else "·"
            print(f"{mark} {item['name']}：命中 {st.get('matched', 0)}/{len(item.get('conditions') or [])}")
            for e in st.get("conditions", []):
                print(f"    {e}")
        print(f"（本轮实际告警 {len(result['alerted'])} 条）")
        return 0

    items = evaluate_all()
    for item in items:
        st = item.get("status") or {}
        print(f"{'✅' if item.get('enabled') else '⏸'} {item['name']}（{item.get('match', 'any')}）")
        for e in st.get("conditions", []):
            print(f"    {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
