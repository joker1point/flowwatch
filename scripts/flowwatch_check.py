"""flowwatch 前端端到端检查：真实加载页面 → 断言有数据 → 点一行看明细 → 截图留证。

用法: python flowwatch_check.py [URL]
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5273/"
OUT = Path(__file__).with_name("flowwatch.png")


def main() -> int:
    errors: list[str] = []
    api_calls: list[tuple[int, str]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1.5)

        page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
        page.on(
            "console",
            lambda msg: errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None,
        )
        page.on(
            "response",
            lambda resp: api_calls.append((resp.status, resp.url)) if "/api/" in resp.url else None,
        )

        page.goto(URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_selector(".row", timeout=30000)   # 等到第一帧速率数据
        page.wait_for_timeout(6500)                     # 攒几帧历史（曲线才有形）

        rows = page.locator(".row").count()
        stats = page.locator(".stat").all_inner_texts()
        chart_points = page.locator(".chart__line--in").get_attribute("d") or ""
        page.locator(".row").first.click()              # 选中排第一的进程 → 右侧明细
        page.wait_for_timeout(1200)
        conns = page.locator(".conn").count()

        page.screenshot(path=str(OUT))
        body = page.inner_text("body")

        print(f"进程行数: {rows}")
        print(f"连接明细行数: {conns}")
        print("头部读数: " + " | ".join(s.replace("\n", "=") for s in stats))
        print(f"曲线点数(路径长度): {len(chart_points)}")
        print("API 调用: " + ", ".join(f"{status} {url.split('/api/')[-1][:24]}" for status, url in api_calls[:6]))
        print("错误: " + ("；".join(errors[:5]) if errors else "无"))
        # 隐私自检：页面不该出现本机用户目录（截图/日志会被贴出去）
        leaked = "C:\\Users\\" in body or "\\Users\\" in body
        print("疑似本机用户路径泄漏: " + str(leaked))
        print(f"截图: {OUT}")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
