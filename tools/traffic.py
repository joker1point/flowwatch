#!/usr/bin/env python3
"""生成少量**真实**流量（系统 DNS 查询 + 真实 TLS 握手），用于演示与手工验证。

为什么需要它：域名解析是**观测式**的 —— 只认我们亲眼看过的 DNS 应答与 TLS ClientHello。
已经在跑的进程，它们的域名查询早在采集开始之前就发生过了，因此不会 retroactively 出现名字。
这个脚本现场建立连接，让解析链路（DNS → SNI → IP:端口）走一遍。

用法:
    python tools/traffic.py                      # 默认站点，跑 30 秒
    python tools/traffic.py --seconds 120 --interval 5 www.python.org github.com
"""

from __future__ import annotations

import argparse
import socket
import ssl
import time

DEFAULT_HOSTS = ("www.baidu.com", "github.com", "www.python.org", "www.cloudflare.com")


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 DNS + TLS 流量（演示用）")
    parser.add_argument("hosts", nargs="*", default=list(DEFAULT_HOSTS))
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--interval", type=float, default=3.0)
    args = parser.parse_args()

    context = ssl.create_default_context()
    deadline = time.monotonic() + args.seconds
    rounds = 0
    while time.monotonic() < deadline:
        for host in args.hosts:
            stamp = time.strftime("%H:%M:%S")
            try:
                with socket.create_connection((host, 443), timeout=6) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        tls.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        tls.recv(8192)          # 只读一小块：够产生可观测的字节数
                print(f"{stamp} {host} ok", flush=True)
            except Exception as exc:            # 演示工具：失败如实打印，继续下一轮
                print(f"{stamp} {host} 失败: {type(exc).__name__}: {exc}", flush=True)
        rounds += 1
        time.sleep(args.interval)
    print(f"完成 {rounds} 轮", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
