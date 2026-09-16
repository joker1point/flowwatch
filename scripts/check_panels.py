"""检查历史面板 / 事件流是否真的渲染出来了（含位置与文本），并出整页截图。"""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:5273/"
OUT = Path(__file__).with_name("flowwatch_full.png")


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1.4)
        page.goto(URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_selector(".row", timeout=30000)
        page.wait_for_timeout(4000)

        for selector in (".grid > *", ".panel--events", ".panel--list", ".column > *"):
            locator = page.locator(selector)
            print(f"{selector} → {locator.count()} 个")
            for index in range(min(locator.count(), 6)):
                box = locator.nth(index).bounding_box() or {}
                text = (locator.nth(index).inner_text() or "").replace("\n", " | ")[:70]
                print(f"   [{index}] y={box.get('y', -1):.0f} h={box.get('height', -1):.0f}  {text}")

        # 域名视图：切换后用整页截图留证
        page.locator(".tabs button", has_text="域名").click()
        page.wait_for_timeout(2500)
        domain_rows = page.locator(".list--domains .row")
        print(f"\n域名视图: {domain_rows.count()} 行")
        for index in range(min(domain_rows.count(), 6)):
            text = (domain_rows.nth(index).inner_text() or "").replace("\n", " | ")[:90]
            print(f"   [{index}] {text}")
        note = page.locator(".panel--list .panel__note")
        if note.count():
            print("   页脚: " + (note.first.inner_text() or "").replace("\n", " | ")[:140])
        page.screenshot(path=str(OUT.with_name("flowwatch_domains.png")), full_page=True)
        page.locator(".tabs button", has_text="进程").click()   # 切回进程视图继续后面的检查
        page.wait_for_timeout(800)

        page.locator(".row").first.click()
        page.wait_for_timeout(3500)
        print(f"\n点击后：.bars={page.locator('.bars').count()} .history__stats={page.locator('.history__stats').count()} "
              f".events li={page.locator('.events li').count()}")
        panels = page.locator("section.panel")
        for index in range(panels.count()):
            text = (panels.nth(index).inner_text() or "").replace("\n", " | ")[:110]
            print(f"   panel[{index}]: {text}")

        page.screenshot(path=str(OUT), full_page=True)
        print(f"\n整页截图: {OUT}")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
