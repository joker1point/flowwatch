"""alert_rules.py 单元测试：双条件评估、缺桶断裂、冷却抑制、规则 CRUD 校验。

不需要网络、不弹窗（alert 打桩）、不碰正式库——构造临时 buckets 数据，全部断言离线跑完。
要钉死的四件事：
  1. window_bytes 的三种 direction 各自取对列（out / in / total）；
  2. sustained 的「缺桶 = 断裂」：采集断过的分钟绝不并进连续时长（诚实优先）；
  3. 冷却期内重复命中不二次弹窗；
  4. match=all 时全部条件才命中（任一不命中即不命中）。
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import alert_rules  # noqa: E402

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


# ---------------------------------------------------------------- 临时库 + 数据

NOW = 1_800_000_000.0          # 固定"现在"，让断言与 wall-clock 无关
NOW_BUCKET = int(NOW) // 60 * 60


def make_db() -> Path:
    path = Path(tempfile.gettempdir()) / "alert_rules_test.db"
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE buckets (
          bucket_ts INTEGER NOT NULL, pid INTEGER NOT NULL, process TEXT NOT NULL,
          out_bytes INTEGER NOT NULL DEFAULT 0, in_bytes INTEGER NOT NULL DEFAULT 0,
          packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (bucket_ts, pid));
        """
    )
    # demoapp：最近 5 分钟每分钟 300 MB 上行（窗内累计 1.5 GB），第 6 分钟起断档
    for i in range(5):
        conn.execute("INSERT INTO buckets VALUES (?,?,?,?,?,?)",
                     (NOW_BUCKET - i * 60, 100, "demoapp.exe", 300 * 1024 * 1024, 10 * 1024 * 1024, 5))
    conn.commit()
    conn.close()
    return path


def rule(processes=("%demoapp%",), conditions=None, **kw) -> dict:
    base = {"id": "r_test", "name": "t", "processes": list(processes), "enabled": True,
            "match": "any", "conditions": conditions or [], "cooldown_minutes": 30}
    base.update(kw)
    return base


# ---------------------------------------------------------------- window_bytes

def test_window_bytes() -> None:
    db = make_db()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    # 近 10 分钟总流量：5 × (300+10) MB = 1550 MB → 超 1 GB 阈值
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "window_bytes", "window_minutes": 10, "bytes": 1024 ** 3, "direction": "total"},
    ]), NOW)
    check("window total 命中", st["conditions"][0]["hit"], True)
    # 只看上行：5 × 300 MB = 1500 MB → 同样超 1 GB
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "window_bytes", "window_minutes": 10, "bytes": 1024 ** 3, "direction": "out"},
    ]), NOW)
    check("window out 命中", st["conditions"][0]["hit"], True)
    # 只看下行：5 × 10 MB = 50 MB → 不超
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "window_bytes", "window_minutes": 10, "bytes": 1024 ** 3, "direction": "in"},
    ]), NOW)
    check("window in 不命中", st["conditions"][0]["hit"], False)
    # 进程不匹配（大小写不敏感 LIKE，中文/不存在进程零命中）
    st = alert_rules.rule_status(conn, rule(processes=("%不存在%",), conditions=[
        {"type": "window_bytes", "window_minutes": 10, "bytes": 1, "direction": "total"},
    ]), NOW)
    check("不匹配进程零命中", st["conditions"][0]["hit"], False)
    conn.close()


# ---------------------------------------------------------------- sustained

def test_sustained() -> None:
    db = make_db()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    # 最近 5 分钟连续有流量 → streak=5，阈值 5 命中、阈值 6 不命中
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "sustained_minutes", "minutes": 5},
    ]), NOW)
    check("sustained 连 5 分钟（阈值 5 命中）", st["conditions"][0]["hit"], True)
    check("sustained current=5", st["conditions"][0]["current"], 5)
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "sustained_minutes", "minutes": 6},
    ]), NOW)
    check("sustained 连 5 分钟（阈值 6 不命中）", st["conditions"][0]["hit"], False)
    conn.close()

    # 缺桶断裂：在中间挖掉一分钟，streak 应从断点后重算（4 → 3 → …）
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM buckets WHERE bucket_ts = ?", (NOW_BUCKET - 2 * 60,))
    conn.commit()
    conn.close()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "sustained_minutes", "minutes": 5},
    ]), NOW)
    check("缺桶断裂后 current=2", st["conditions"][0]["current"], 2)
    check("缺桶断裂后阈值 2 命中",
          alert_rules.rule_status(conn, rule(conditions=[
              {"type": "sustained_minutes", "minutes": 2}]), NOW)["conditions"][0]["hit"], True)
    check("缺桶断裂后阈值 3 不命中",
          alert_rules.rule_status(conn, rule(conditions=[
              {"type": "sustained_minutes", "minutes": 3}]), NOW)["conditions"][0]["hit"], False)
    conn.close()

    # 最新一分钟无流量 → streak=0、active=False（"当前没在传"不报持续）
    conn = sqlite3.connect(db)
    conn.execute("INSERT OR REPLACE INTO buckets VALUES (?,?,?,?,?,?)",
                 (NOW_BUCKET, 100, "demoapp.exe", 0, 0, 0))
    conn.commit()
    conn.close()
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    st = alert_rules.rule_status(conn, rule(conditions=[
        {"type": "sustained_minutes", "minutes": 3},
    ]), NOW)
    check("当前分钟无流量 → current=0", st["conditions"][0]["current"], 0)
    check("当前分钟无流量 → active=False", st["conditions"][0]["active"], False)
    check("当前分钟无流量 → 不命中", st["conditions"][0]["hit"], False)
    conn.close()


# ---------------------------------------------------------------- match / 冷却 / 告警

def test_match_and_cooldown() -> None:
    db = make_db()
    alert_rules.configure(db_path=db)
    # 覆盖规则文件为测试规则（两个条件：总量 1GB / 下行 1MB——后者不命中）
    test_rules = {"version": 1, "rules": [
        rule(conditions=[
            {"type": "window_bytes", "window_minutes": 10, "bytes": 1024 ** 3, "direction": "total"},
            {"type": "window_bytes", "window_minutes": 10, "bytes": 1024 ** 2, "direction": "in"},
        ]),
    ]}
    # in 条件实际不命中（下行仅 50MB < 1GB，但 > 1MB）——换成 2GB 让 in 不命中
    test_rules["rules"][0]["conditions"][1]["bytes"] = 2 * 1024 ** 3
    alert_rules.RULES_PATH.write_text(__import__("json").dumps(test_rules), encoding="utf-8")

    # any：总量条件命中 → 整条命中
    items = alert_rules.evaluate_all(NOW)
    check("match=any 命中", items[0]["status"]["hit"], True)
    # all：in 条件不命中 → 整条不命中
    test_rules["rules"][0]["match"] = "all"
    alert_rules.RULES_PATH.write_text(__import__("json").dumps(test_rules), encoding="utf-8")
    items = alert_rules.evaluate_all(NOW)
    check("match=all 不命中", items[0]["status"]["hit"], False)

    # 冷却 + 告警打桩：第一轮弹一次，冷却期内第二轮不弹，冷却结束再弹
    # （注意：测试库的桶只到 NOW，check_all 的 now 必须仍取 NOW——把 now 推后会让
    #   查询窗口跑到数据之前，SUM=0 直接不命中。冷却用 last_alert_ts 回拨来模拟。）
    calls: list[str] = []
    real_alert = alert_rules.alert
    alert_rules.alert = lambda title, body: calls.append(title)  # type: ignore[assignment]
    try:
        test_rules["rules"][0]["match"] = "any"
        alert_rules.RULES_PATH.write_text(__import__("json").dumps(test_rules), encoding="utf-8")
        alert_rules.check_all(now=NOW)
        check("首轮弹窗一次", len(calls), 1)
        alert_rules.check_all(now=NOW + 60)          # 1 分钟后仍在 30 分钟冷却内
        check("冷却期内不重复弹", len(calls), 1)
        # 冷却结束：把 last_alert_ts 回拨到 1 小时前再评估
        test_rules["rules"][0]["last_alert_ts"] = NOW - 3600
        alert_rules.RULES_PATH.write_text(__import__("json").dumps(test_rules), encoding="utf-8")
        alert_rules.check_all(now=NOW)
        check("冷却结束再弹", len(calls), 2)

        # 禁用规则：命中也不弹
        test_rules["rules"][0]["enabled"] = False
        test_rules["rules"][0]["last_alert_ts"] = 0
        alert_rules.RULES_PATH.write_text(__import__("json").dumps(test_rules), encoding="utf-8")
        alert_rules.check_all(now=NOW)
        check("禁用规则不弹", len(calls), 2)
    finally:
        alert_rules.alert = real_alert  # type: ignore[assignment]


# ---------------------------------------------------------------- CRUD 校验

def test_validate() -> None:
    from fastapi import HTTPException

    ok = alert_rules._validate(alert_rules.RuleIn(
        name="  demoapp ", processes=["%demoapp%", "%demoproc%"], match="any",
        conditions=[{"type": "sustained_minutes", "minutes": 60}], cooldown_minutes=0))
    check("name 去空白", ok["name"], "demoapp")
    check("默认规则带 id/created_ts", bool(ok.get("id")) and bool(ok.get("created_ts")), True)

    for label, payload in [
        ("空白进程匹配串", dict(processes=["  "], conditions=[{"type": "sustained_minutes", "minutes": 5}])),
        ("bytes 缺失(None)", dict(processes=["%x%"], conditions=[
            {"type": "window_bytes", "window_minutes": 60, "bytes": None}])),
        ("窗口越界(0)", dict(processes=["%x%"], conditions=[
            {"type": "window_bytes", "window_minutes": 0, "bytes": 1024 ** 3}])),
        ("窗口越界(2000)", dict(processes=["%x%"], conditions=[
            {"type": "window_bytes", "window_minutes": 2000, "bytes": 1024 ** 3}])),
        ("字节阈值过小", dict(processes=["%x%"], conditions=[
            {"type": "window_bytes", "window_minutes": 60, "bytes": 1024}])),
        ("方向非法", dict(processes=["%x%"], conditions=[
            {"type": "window_bytes", "window_minutes": 60, "bytes": 1024 ** 3, "direction": "both"}])),
        ("持续时长越界", dict(processes=["%x%"], conditions=[
            {"type": "sustained_minutes", "minutes": 9999}])),
    ]:
        try:
            alert_rules._validate(alert_rules.RuleIn(name="t", **payload))
            check(f"拒绝：{label}", "未抛错", "HTTPException")
        except HTTPException:
            check(f"拒绝：{label}", "HTTPException", "HTTPException")


if __name__ == "__main__":
    test_window_bytes()
    test_sustained()
    test_match_and_cooldown()
    test_validate()
    print()
    if FAILURES:
        print(f"失败 {len(FAILURES)} 项：{FAILURES}")
        raise SystemExit(1)
    print("全部通过 ✓")
