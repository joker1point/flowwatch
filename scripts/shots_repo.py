"""生成 README 用的截图，并在截图前做**脱敏**（公开仓库不该出现本机用户路径、内网地址、个人域名）。

做法：替换 DOM 文本节点与 title 属性 → 截图 → **断言**可视文本里不再出现任何敏感模式。
脱敏不能靠"应该没问题"，所以断言是硬要求（失败就非零退出）。

默认规则只含通用模式（用户目录、RFC1918 内网、公网 IPv6、当前用户名）——
需要脱敏自己的代理域名 / 公司内网段时用 `--extra` 传正则，**不要把个人特征写进仓库**。

用法:
    python scripts/shots_repo.py                       # 需要本机仪表盘已在 127.0.0.1:5273 运行
    python scripts/shots_repo.py --extra "example\\.corp" --extra "10\\.9\\."
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"
URL = "http://127.0.0.1:5273/"


def default_rules() -> tuple[list[tuple[str, str]], list[str]]:
    """通用脱敏规则 + 断言用的"绝不允许出现"清单。"""
    rules: list[tuple[str, str]] = [
        (r"[A-Za-z]:\\Users\\[^\\\s]+", "C:\\Users\\user"),          # 本机用户目录
        (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "10.0.0.5"),              # 内网地址（通用的 10/8）
        (r"192\.168\.\d{1,3}\.\d{1,3}", "192.168.0.10"),
        (r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "172.16.0.10"),
        (r"2001:[0-9a-fA-F]{1,4}:[0-9a-fA-F:]+", "2001:db8::1"),      # 公网 IPv6
    ]
    forbidden = ["C:\\Users\\", "10.", "192.168.", "2001:"]           # 断言用（宽口径）
    for name in {os.environ.get("USERNAME") or "", getpass.getuser() or ""}:
        if name and name.lower() not in ("user", "root"):
            rules.append((re.escape(name), "user"))
            forbidden.append(name)
    # 断言里 "10." 这种宽口径会误伤（比如 "10.3%"），这里做精确化：只保留路径与用户名 + IPv6
    forbidden = [item for item in forbidden if item != "10." and item != "192.168." and item != "2001:"]
    forbidden += ["2001:", "192.168."]
    return rules, forbidden


def redact(page, rules: list[list[str]]) -> None:
    page.evaluate(
        """(rules) => {
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const nodes = [];
            while (walker.nextNode()) nodes.push(walker.currentNode);
            for (const node of nodes) {
                let text = node.nodeValue;
                for (const [pattern, replacement] of rules) {
                    text = text.replace(new RegExp(pattern, 'g'), replacement);
                }
                if (text !== node.nodeValue) node.nodeValue = text;
            }
            document.querySelectorAll('[title]').forEach((el) => {
                let value = el.getAttribute('title');
                for (const [pattern, replacement] of rules) {
                    value = value.replace(new RegExp(pattern, 'g'), replacement);
                }
                el.setAttribute('title', value);
            });
        }""",
        rules,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="生成脱敏后的 README 截图")
    parser.add_argument("--extra", action="append", default=[],
                        help="额外的脱敏正则（自己的域名 / 内网段），可多次传入")
    parser.add_argument("--url", default=URL)
    args = parser.parse_args()

    rules, forbidden = default_rules()
    rules += [(pattern, "redacted") for pattern in args.extra]
    # --extra 的正则顺带当断言用的字面串（去掉转义符），保证"传了就必须被替换掉"
    forbidden += [pattern.replace("\\", "") for pattern in args.extra if len(pattern) >= 4]
    DOCS.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1460, "height": 940}, device_scale_factor=1.5)
        page.goto(args.url, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_selector(".row", timeout=30000)
        page.wait_for_timeout(8000)                 # 攒几帧：曲线与历史面板才有内容

        page.locator(".row").first.click()          # 进程视图：连接明细 + 历史
        page.wait_for_timeout(2500)
        redact(page, rules)
        page.screenshot(path=str(DOCS / "screenshot-01-dashboard.png"))
        text = page.inner_text("body")

        page.locator(".tabs button", has_text="域名").click()   # 域名视图
        page.wait_for_timeout(2000)
        redact(page, rules)
        page.screenshot(path=str(DOCS / "screenshot-02-domains.png"))
        text += page.inner_text("body")
        browser.close()

    failures = [needle for needle in forbidden if needle in text]
    print(f"截图: {DOCS / 'screenshot-01-dashboard.png'}")
    print(f"截图: {DOCS / 'screenshot-02-domains.png'}")
    print("脱敏断言: " + ("通过" if not failures else "失败，仍出现: " + "、".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
