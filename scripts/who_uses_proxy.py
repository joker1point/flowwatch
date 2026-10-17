#!/usr/bin/env python3
"""who_uses_proxy —— 此刻谁在连代理端口（7890）的实时快照。

比历史桶更直接的对比判据：分流改造前记录「连 7890 的客户端进程集合」，
改造后应只剩 ChatGPT（域名/进程规则命中的那一个）。
"""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8788"
PROXY_PORT = 7890


def main() -> int:
    with urllib.request.urlopen(f"{BASE}/api/rates", timeout=5) as r:
        d = json.loads(r.read())
    lc = d.get("local_conns") or {}
    print(f"local_conns source={lc.get('source')} error={lc.get('error')}")
    print("\n== 指向本机的连接（按进程，只看 >0） ==")
    for row in lc.get("by_pid", []):
        if row.get("local_conns", 0) > 0:
            print(f"  {row['process'][:34]:34s} 本机连接 {row['local_conns']:3d} / 总 {row['conns']:3d}")
    print(f"\n== 监听端口 ← 客户端（标出 {PROXY_PORT}） ==")
    for s in lc.get("services", []):
        mark = "  ← 代理端口" if s["port"] == PROXY_PORT else ""
        print(f"  :{s['port']:<6} clients={s['clients']:<3} conns={s['conns']:<3} "
              f"{str(s['process'])}{mark}")
    clients = [s for s in lc.get("services", []) if s["port"] == PROXY_PORT]
    print(f"\n判读：7890 上 {clients[0]['clients'] if clients else 0} 个客户端进程"
          f"{'（代理在用）' if clients else '（代理空闲）'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
