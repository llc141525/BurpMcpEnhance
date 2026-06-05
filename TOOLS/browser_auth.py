"""browser-use agent：登录 + surface discovery + 写 DB。

用法:
  python3 TOOLS/browser_auth.py --target "目标名" --url "https://example.com/login"

输出:
  - auth_sessions 表写入 cookies（cookie_source='browser_use'）
  - pages 表写入认证后发现的 URL（source='browser_use', status='queued'）
  - scan_state.phase 更新为 'auth_ready'（成功）或 'auth_timeout'（超时）

环境变量:
  DEEPSEEK_API        DeepSeek API key（必填）
  FEISHU_CHAT_ID      飞书 chat_id（必填）
  CAIDO_PORT          Caido 代理端口（默认 8181）

注意: browser-use 实际 API:
  - BrowserConfig 不存在，使用 BrowserSession(cdp_url=..., headless=...)
  - ChatAnthropic 从 browser_use 导入（内置 LLM 适配层）
  - Agent 无 max_steps 参数，使用 max_failures 控制
"""

import argparse
import asyncio
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"
TMP_DIR = PROJECT_ROOT / "tmp"

SKIP_EXTENSIONS = re.compile(
    r"\.(css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz)(\?.*)?$",
    re.IGNORECASE,
)


# ── Pure functions (testable without browser) ─────────────────────────────────


def parse_surface_urls(raw: list[dict], base_domain: str) -> list[dict]:
    """过滤：同域 + 排除纯静态资源（CSS/图片/字体）。JS 文件保留。"""
    from urllib.parse import urlparse

    # Strip leading "www." properly — not via lstrip (which strips chars, not prefix)
    base = base_domain
    if base.startswith("www."):
        base = base[4:]

    result = []
    for item in raw:
        url = item.get("url", "")
        if not url.startswith("http"):
            continue
        try:
            host = urlparse(url).netloc
        except Exception as exc:  # noqa: BLE001
            print(f"[parse_surface_urls] skipping malformed url {url!r}: {exc}", file=sys.stderr)
            continue
        if not (host == base_domain or host == f"www.{base}" or host.endswith(f".{base}")):
            continue
        if SKIP_EXTENSIONS.search(url.split("?")[0]):
            continue
        result.append(item)
    return result


def write_surface_urls_to_db(db_path: str, urls: list[dict]) -> int:
    """写 pages 表，返回新增条数。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    count = 0
    for item in urls:
        cur = conn.execute(
            "INSERT INTO pages (url, depth, status, source) VALUES (?, 1, 'queued', 'browser_use') "
            "ON CONFLICT(url) DO NOTHING",
            (item["url"],),
        )
        count += cur.rowcount
    conn.commit()
    conn.close()
    return count


def write_cookies_to_db(db_path: str, cookies: list[dict]) -> None:
    """写 auth_sessions 表。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    for c in cookies:
        conn.execute(
            """INSERT INTO auth_sessions
               (token_type, token_name, token_value, domain, path, is_active, cookie_source)
               VALUES ('cookie', ?, ?, ?, ?, 1, 'browser_use')
               ON CONFLICT DO NOTHING""",
            (c.get("name", ""), c.get("value", ""), c.get("domain", ""), c.get("path", "/")),
        )
    conn.commit()
    conn.close()


def set_phase(db_path: str, phase: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE scan_state SET phase=? WHERE id=1", (phase,))
    conn.commit()
    conn.close()


def find_db(target: str) -> str | None:
    matches = sorted(DBS_DIR.glob(f"{target}_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    return str(matches[0]) if matches else None


# ── Browser-use agent ─────────────────────────────────────────────────────────


async def run_browser_auth(target: str, login_url: str, cdp_url: str, db_path: str) -> bool:
    """browser-use agent 登录 + surface discovery。成功返回 True，失败/超时返回 False。

    API 说明（browser-use 实际版本）:
      - BrowserSession 替代 BrowserConfig，支持 cdp_url + headless 参数
      - ChatAnthropic 从 browser_use 导入（内置适配，非 langchain_anthropic）
      - Agent 无 max_steps 参数
    """
    from browser_use import Agent, BrowserSession, ChatAnthropic, Controller

    chat_id = os.environ.get("FEISHU_CHAT_ID", "")
    if not chat_id:
        print("[error] 环境变量 FEISHU_CHAT_ID 未设置", file=sys.stderr)
        return False

    llm = ChatAnthropic(
        model="deepseek-v4-flash",
        api_key=os.environ["DEEPSEEK_API"],
        base_url="https://api.deepseek.com/anthropic",
        timeout=60,
    )

    browser_session = BrowserSession(
        cdp_url=cdp_url,
        headless=False,
    )

    controller = Controller()

    @controller.action("Ask operator via Feishu — send screenshot and wait for reply")
    async def ask_feishu(message: str, screenshot_path: str | None = None) -> str:
        from TOOLS.feishu_notify import send_image_wait_reply, send_text_wait_reply

        if screenshot_path and Path(screenshot_path).exists():
            reply = send_image_wait_reply(chat_id, screenshot_path, message, timeout=180)
        else:
            reply = send_text_wait_reply(chat_id, message, timeout=180)
        return reply or "TIMEOUT"

    from urllib.parse import urlparse

    base_domain = urlparse(login_url).netloc

    task = f"""
你是一个安全研究员，帮助测试员完成对 {target} 的登录并发现认证后的页面。

步骤：
1. 导航到登录页: {login_url}
2. 检测登录阻断类型：
   - 若出现二维码（canvas 或 img 元素）：截图保存到 {TMP_DIR}/qr_{target}.png，
     然后调用 ask_feishu 发送截图，消息为"请用手机扫码登录 {target}"，
     等待成功跳转（轮询页面 URL 变化，最多等 3 分钟）。
   - 若出现图形验证码：截图保存到 {TMP_DIR}/captcha_{target}.png，
     调用 ask_feishu 发送截图，消息为"请回复图中验证码内容"，
     拿到回复后填入验证码输入框并提交。
   - 若出现短信验证码输入框：点击"发送短信"按钮，
     调用 ask_feishu（无截图），消息为"短信验证码已发送，请回复验证码"，
     拿到回复后填入输入框并提交。
   - 若只需用户名/密码：提示 ask_feishu "请在浏览器中手动输入账号密码并登录"，等待跳转。
3. 登录成功后，浏览以下区域并展开所有菜单：dashboard / 首页 / 用户中心 / 设置 / 管理后台。
4. 完成后输出 JSON（放在最后一行）：
   {{"urls": [{{"url": "...", "title": "..."}}]}}

约束：不提交表单，不点击删除，不点击退出登录。
"""

    try:
        agent = Agent(
            task=task,
            llm=llm,
            browser_session=browser_session,
            controller=controller,
        )
        result = await asyncio.wait_for(agent.run(), timeout=300)

        output_text = str(result)
        json_match = re.search(r'\{"urls":\s*\[.*?\]\}', output_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            raw_urls = data.get("urls", [])
            filtered = parse_surface_urls(raw_urls, base_domain)
            added = write_surface_urls_to_db(db_path, filtered)
            print(
                f"[browser_auth] surface discovery: {len(raw_urls)} 原始 → {added} 条写入 pages",
                file=sys.stderr,
            )

        # Extract cookies via patchright CDP connection
        try:
            from patchright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.connect_over_cdp(cdp_url)
                context = browser.contexts[0] if browser.contexts else None
                if context:
                    cookies = await context.cookies()
                    write_cookies_to_db(db_path, cookies)
                    print(f"[browser_auth] 写入 {len(cookies)} 条 cookies", file=sys.stderr)
        except Exception as cookie_err:
            print(f"[browser_auth] cookie 提取失败（非致命）: {cookie_err}", file=sys.stderr)

        return True

    except asyncio.TimeoutError:
        print("[browser_auth] agent 超时（300s）", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[browser_auth] 错误: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="browser-use 登录 + surface discovery")
    parser.add_argument("--target", required=True)
    parser.add_argument("--url", required=True, help="登录页 URL")
    args = parser.parse_args()

    if not os.environ.get("DEEPSEEK_API"):
        sys.exit("[error] 请设置环境变量 DEEPSEEK_API")
    if not os.environ.get("FEISHU_CHAT_ID"):
        sys.exit("[error] 请设置环境变量 FEISHU_CHAT_ID")

    db_path = find_db(args.target)
    if not db_path:
        sys.exit(f"[error] 找不到目标 DB: {args.target}")

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT cdp_url FROM scan_state WHERE id=1").fetchone()
    conn.close()
    cdp_url = row[0] if row and row[0] else "http://localhost:9222"

    TMP_DIR.mkdir(exist_ok=True)

    success = asyncio.run(run_browser_auth(args.target, args.url, cdp_url, db_path))

    if success:
        set_phase(db_path, "auth_ready")
        print("[browser_auth] 登录成功，phase → auth_ready", file=sys.stderr)
    else:
        set_phase(db_path, "auth_timeout")
        print("[browser_auth] 登录失败，phase → auth_timeout", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
