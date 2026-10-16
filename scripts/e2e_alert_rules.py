#!/usr/bin/env python3
"""告警规则功能端到端验收（2026-10-15）。

起 server（同自启参数）→ 验种子规则 → 验 CRUD → 验 check 评估 →
验 web 页面可访问 → 停掉。用「不存在的进程」构造规则，保证 check 不误弹窗。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:8788"
DEV = "4FC5DA1D"
LOG = ROOT / "_run" / "e2e_alert.log"
RULES = ROOT / "alert_rules.json"
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK ' if ok else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def get(path, timeout=5):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.loads(r.read())


def post(path, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else b"{}"
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def req(method, path, payload=None, timeout=10):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read())


def wait_health(deadline_s=60):
    """先等 run.py 打印实际端口（8788 可能被 resident 采集占着，run.py 会顺延），
    再轮 health。不能反过来：默认 BASE 打到 resident 的裸 server 上 API 全 200，
    会早退并带着错端口（首页 404——裸 server 没有静态挂载）。"""
    global BASE
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        m = re.search(r"界面与 API 都在 http://127\.0\.0\.1:(\d+)",
                      LOG.read_text(encoding="utf-8", errors="replace"))
        if m:
            BASE = f"http://127.0.0.1:{m.group(1)}"
            break
        time.sleep(0.5)
    else:
        return None
    while time.time() - t0 < deadline_s:
        try:
            return get("/api/health")
        except Exception:
            time.sleep(1.5)
    return None


if __name__ == "__main__":
    if RULES.exists():
        RULES.unlink()          # 从干净状态开始，验证种子逻辑
    LOG.write_text("", encoding="utf-8")
    with open(LOG, "a", encoding="utf-8") as log:
        # 打在真实交付入口上（元原则 13：单端口形态 = 官方一键包的 run.py），而不是裸 server.py
        proc = subprocess.Popen([sys.executable, "run.py", "--no-browser", "--no-install",
                                 "--dev", DEV],
                                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    try:
        health = wait_health()
        check("server 启动且 health 可达", health is not None)
        if health is None:
            raise SystemExit(1)

        # 1. 种子规则
        data = get("/api/alert-rules")
        names = [r["name"] for r in data["items"]]
        check("默认种入 2 条规则", len(data["items"]) == 2, str(names))
        check("规则文件已落盘", RULES.exists(), str(RULES))
        check("评估周期 300s", data["interval_sec"] == 300)

        # 2. 新建（不存在的进程 → 绝不命中，不弹窗）
        rule_in = {
            "name": "e2e 测试规则",
            "processes": ["%zzz-not-exist%"],
            "enabled": True,
            "match": "any",
            "conditions": [
                {"type": "window_bytes", "window_minutes": 5, "bytes": 2 * 1024 * 1024, "direction": "total"},
                {"type": "sustained_minutes", "minutes": 1},
            ],
            "cooldown_minutes": 5,
        }
        created = post("/api/alert-rules", rule_in)["item"]
        rid = created["id"]
        check("新建规则返回 id", bool(rid), rid)

        # 3. 列表里出现 + 状态带两个条件的当前值
        item = next(r for r in get("/api/alert-rules")["items"] if r["id"] == rid)
        st = item["status"]
        check("状态含 2 个条件", len(st["conditions"]) == 2)
        check("不存在的进程不命中", st["hit"] is False)
        check("sustained 当前值=0", any(c.get("current") == 0 for c in st["conditions"]))

        # 4. 校验拒绝：坏输入（pydantic 层 422 与业务校验层 400 都算拒绝）
        try:
            post("/api/alert-rules", {**rule_in, "processes": []})
            check("拒绝空进程列表", False)
        except urllib.error.HTTPError as e:
            check("拒绝空进程列表", e.code in (400, 422), f"HTTP {e.code}")
        try:
            post("/api/alert-rules", {**rule_in, "conditions": [
                {"type": "window_bytes", "window_minutes": 60, "bytes": 10}]})
            check("拒绝过小字节阈值", False)
        except urllib.error.HTTPError as e:
            check("拒绝过小字节阈值", e.code == 400)

        # 5. 更新（改阈值/改名）
        upd = post(f"/api/alert-rules/{rid}", {**rule_in, "name": "e2e 测试规则·改"}) if False else None
        status, body = req("PUT", f"/api/alert-rules/{rid}",
                           {**rule_in, "name": "e2e 测试规则·改"})
        check("PUT 更新规则", status == 200 and body["item"]["name"] == "e2e 测试规则·改")

        # 6. 立即检查一轮：接口可用；**只断言测试规则未命中**（不假设全局无命中——
        #    种子规则是否命中取决于真实流量；alerted 只数真弹的，禁用规则不算）
        r = post("/api/alert-rules/check")
        check("check 接口可用", r["ok"] is True)
        mine = next(i for i in r["items"] if i["id"] == rid)
        check("测试规则未命中", mine["status"]["hit"] is False,
              f"（本轮真实告警 alerted={r['alerted']}）")

        # 7. 删除
        status, _ = req("DELETE", f"/api/alert-rules/{rid}")
        check("DELETE 删除规则", status == 200)
        left = [x["id"] for x in get("/api/alert-rules")["items"]]
        check("删除后回到 2 条种子", len(left) == 2 and rid not in left)

        # 8. web 页面可访问（dist 已构建）
        with urllib.request.urlopen(BASE + "/", timeout=5) as resp:
            html = resp.read().decode("utf-8", "replace")
        check("web 首页 200 且是 SPA 壳", resp.status == 200 and "<div id=\"root\">" in html)

        # 9. 守护线程已起（日志有据）
        log_text = LOG.read_text(encoding="utf-8", errors="replace")
        check("后台守护线程已启动", "告警评估守护已启动" in log_text)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        print("（server 已停止）")

    print()
    if FAILURES:
        print(f"失败 {len(FAILURES)} 项：{FAILURES}")
        raise SystemExit(1)
    print("端到端全部通过 ✓")
