"""etw_batch 解析层测试：从 tracerpt 的 XML dump 里抽连接事件。

三类输入：
  1. **合成片段**：只放我关心的连接事件与干扰事件（send/recv），验证筛选与字段解析；
  2. **真实片段**：本机 logman 采出的 dump 里截出来的一条真实 connect 事件
     （`PID=112368 · daddr=127.0.0.1 · saddr=127.0.0.1 · dport=7890 · sport=63098`），
     用来钉住"字段名与语义和官方清单一致"这件事；
  3. **畸形片段**：缺字段、PID=0、端口 0、非连接事件 —— 一律丢弃，绝不产出可疑归因。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import etw_batch  # noqa: E402

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


def event(event_id: int, **fields: str) -> bytes:
    data = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return f"<Event ><System><EventID>{event_id}</EventID></System>{data}</Event >".encode()


CONNECT_V4 = event(12, PID="4321", size="0", daddr="93.184.216.34", saddr="10.0.0.5",
                   dport="443", sport="51234", mss="1460")
SEND_V4 = event(10, PID="4321", size="1400", daddr="93.184.216.34", saddr="10.0.0.5",
                dport="443", sport="51234")
DISCONNECT_V4 = event(13, PID="4321", size="0", daddr="93.184.216.34", saddr="10.0.0.5",
                      dport="443", sport="51234")
ACCEPT_V6 = event(31, PID="999", size="0", daddr="2001:db8::5", saddr="2001:db8::1",
                  dport="51000", sport="443")
REAL_CONNECT = (b'<Event ><System><EventID>12</EventID></System>'
                b'<Data Name="PID">  112368 </Data><Data Name="size">       0 </Data>'
                b'<Data Name="daddr">127.0.0.1 </Data><Data Name="saddr">127.0.0.1 </Data>'
                b'<Data Name="dport">7890 </Data><Data Name="sport">63098 </Data>'
                b'<Data Name="mss">1460 </Data></Event >')

print("=== 筛选与字段解析 ===")
events = etw_batch.parse_dump(CONNECT_V4 + SEND_V4 + DISCONNECT_V4 + ACCEPT_V6)
check("只保留连接类事件（send 被丢掉）", len(events), 3)
check("connect 的 PID", events[0]["pid"], 4321)
check("connect 的本机地址/端口", (events[0]["saddr"], events[0]["sport"]), ("10.0.0.5", 51234))
check("connect 的远端地址/端口", (events[0]["daddr"], events[0]["dport"]), ("93.184.216.34", 443))
check("connect 归类为 learn", events[0]["kind"], "learn")
check("disconnect 归类为 forget", events[1]["kind"], "forget")
check("IPv6 accept 也能解析", (events[2]["pid"], events[2]["sport"], events[2]["daddr"]),
      (999, 443, "2001:db8::5"))

print("\n=== 真实 dump 片段（钉住字段名与语义）===")
real = etw_batch.parse_dump(REAL_CONNECT)
check("真实 connect 事件被解析出来", len(real), 1)
check("字段与官方清单一致（PID/daddr/saddr/dport/sport）",
      (real[0]["pid"], real[0]["daddr"], real[0]["saddr"], real[0]["dport"], real[0]["sport"]),
      (112368, "127.0.0.1", "127.0.0.1", 7890, 63098))
check("首尾空白被清理", real[0]["saddr"], "127.0.0.1")

print("\n=== 畸形输入一律丢弃（fail-closed）===")
check("缺 PID", etw_batch.parse_dump(event(12, daddr="1.1.1.1", saddr="2.2.2.2", dport="443", sport="1")), [])
check("PID=0", etw_batch.parse_dump(event(12, PID="0", daddr="1.1.1.1", saddr="2.2.2.2", dport="443", sport="1")), [])
check("sport=0", etw_batch.parse_dump(event(12, PID="9", daddr="1.1.1.1", saddr="2.2.2.2", dport="443", sport="0")), [])
check("非连接事件（send）", etw_batch.parse_dump(SEND_V4), [])
check("空输入", etw_batch.parse_dump(b""), [])

print("\n=== 事件表与 etw.py 保持一致（**TCP 子集**）===")
# 批量路线**有意只覆盖 TCP**：它的定位是取证/补充（3–6 秒延迟，救不了短命 socket），
# 而 UDP 事件是逐数据报、内容又大多不可用（etw.py 头部实测：96% 事件的地址两侧都不属于本机）——
# 所以这里对齐的是 TCP 子集，而不是含 UDP 的完整表。实时层若要 UDP 用 `--etw-udp` 单独开。
_etw = __import__("etw")
check("learn 表就是 etw.TCP_LEARN_EVENTS", etw_batch.LEARN, _etw.TCP_LEARN_EVENTS)
check("forget 表就是 etw.FORGET_EVENTS", etw_batch.FORGET, _etw.FORGET_EVENTS)

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
