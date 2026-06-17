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
  BURP_PROXY          Burp 代理（默认 127.0.0.1:8080，Chrome 通过 CDP 连接，无需此变量）

注意: browser-use 实际 API:
  - BrowserConfig 不存在，使用 BrowserSession(cdp_url=..., headless=...)
  - 使用 browser_use.llm.deepseek.chat.ChatDeepSeek（OpenAI 兼容端点，无 thinking 模式冲突）
  - ChatAnthropic 的 /anthropic 端点会触发 thinking mode，与 tool_choice 冲突，不要使用
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # auth/ → TOOLS/ → SRC/
_TOOLS_DIR = Path(__file__).resolve().parent.parent  # auth/ → TOOLS/
sys.path.insert(0, str(_TOOLS_DIR))
from auth.auth_state import capture_to_db  # noqa: E402

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


def write_cookies_to_db(db_path: str, cookies: list[dict], role: str = "primary") -> None:
    """写 auth_sessions 表，包括 expires_at。"""
    from datetime import datetime, timezone

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    for c in cookies:
        # Playwright expiry is Unix timestamp (float) or None
        expires_at: str | None = None
        raw_exp = c.get("expires")
        if raw_exp and raw_exp > 0:
            try:
                expires_at = datetime.fromtimestamp(raw_exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, OverflowError, ValueError):
                expires_at = None
        conn.execute(
            """INSERT INTO auth_sessions
               (token_type, token_name, token_value, domain, path, expires_at, is_active, cookie_source, role)
               VALUES ('cookie', ?, ?, ?, ?, ?, 1, 'browser_use', ?)
               ON CONFLICT(role, token_name, domain) DO UPDATE SET
                 token_value=excluded.token_value,
                 expires_at=excluded.expires_at,
                 is_active=1,
                 last_checked_at=datetime('now','localtime')""",
            (c.get("name", ""), c.get("value", ""), c.get("domain", ""), c.get("path", "/"), expires_at, role),
        )
    conn.commit()
    conn.close()


def write_credentials_to_db(
    db_path: str,
    username: str,
    password: str,
    login_url: str = "",
    account_label: str = "primary",
) -> None:
    """写 username/password 到 auth_credentials（供 session_manager 续期使用）。"""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    # 写 auth_credentials（含 login_url，session_manager 优先从这里取）
    conn.execute(
        "INSERT INTO auth_credentials (account_label, username, password, login_url) VALUES (?, ?, ?, ?)",
        (account_label, username, password, login_url),
    )
    # 同时更新最近一条 is_active=1 的 cookie 行（向后兼容）
    conn.execute(
        "UPDATE auth_sessions SET username=?, password=? "
        "WHERE id=(SELECT MAX(id) FROM auth_sessions WHERE is_active=1 AND COALESCE(role, 'primary')=?)",
        (username, password, account_label),
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


def persist_cdp_auth_state(target: str, db_path: str, cdp_url: str, role: str = "primary") -> bool:
    """登录成功后统一捕获 cookies + storage token。"""
    try:
        counts = capture_to_db(target, db_path, cdp_url, role=role)
        print(
            f"[browser_auth] CDP auth state: cookies={counts.get('cookies', 0)} "
            f"storage_tokens={counts.get('storage_tokens', 0)}",
            file=sys.stderr,
        )
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[browser_auth] CDP auth state 捕获失败（非致命）: {e}", file=sys.stderr)
        return False


# ── Browser-use agent ─────────────────────────────────────────────────────────


async def run_browser_auth(
    target: str,
    login_url: str,
    cdp_url: str,
    db_path: str,
    username: str = "",
    password: str = "",
    role: str = "primary",
) -> bool:
    """browser-use agent 登录 + surface discovery。成功返回 True，失败/超时返回 False。

    API 说明（browser-use 实际版本）:
      - BrowserSession 替代 BrowserConfig，支持 cdp_url + headless 参数
      - ChatAnthropic 从 browser_use 导入（内置适配，非 langchain_anthropic）
      - Agent 无 max_steps 参数
    """
    from browser_use import Agent, BrowserSession, Controller
    from browser_use.llm.deepseek.chat import ChatDeepSeek

    chat_id = os.environ.get("FEISHU_CHAT_ID", "")
    if not chat_id:
        print("[error] 环境变量 FEISHU_CHAT_ID 未设置", file=sys.stderr)
        return False

    # 使用 ChatDeepSeek（OpenAI 兼容 /v1 端点）而非 ChatAnthropic：
    # ChatAnthropic 走 /anthropic 端点时 DeepSeek 默认开启 thinking 模式，
    # browser-use 发送 tool_choice 时 API 报 400。ChatDeepSeek 无此问题。
    llm = ChatDeepSeek(
        model="deepseek-chat",
        api_key=os.environ["DEEPSEEK_API"],
    )

    browser_session = BrowserSession(
        cdp_url=cdp_url,
        headless=False,
    )

    controller = Controller()

    @controller.action("Ask operator via Feishu — send screenshot and wait for reply")
    async def ask_feishu(message: str, screenshot_path: str | None = None) -> str:
        from auth.feishu_notify import send_image_wait_reply, send_text_wait_reply  # noqa: PLC0415

        if screenshot_path and Path(screenshot_path).exists():
            reply = send_image_wait_reply(chat_id, screenshot_path, message, timeout=180)
        else:
            reply = send_text_wait_reply(chat_id, message, timeout=180)
        return reply or "TIMEOUT"

    from urllib.parse import urlparse

    base_domain = urlparse(login_url).netloc

    login_method_hint = (
        '请优先点击"账号密码"或"用户名密码"登录选项卡/按钮，切换到账号密码表单，然后继续。'
        if username
        else "选择合适的登录方式继续。"
    )
    cred_step = (
        f"直接填入账号 {username} 和密码 {password} 并提交，无需询问操作员。"
        if username
        else '提示 ask_feishu "请在浏览器中手动输入账号密码并登录"，等待跳转。'
    )
    task = f"""
你是一个安全研究员，帮助测试员完成对 {target} 的登录。

步骤：
1. 导航到登录页: {login_url}
2. 页面可能有多种登录方式（微信/钉钉/QQ/账号密码等）。{login_method_hint}
3. 检测登录阻断类型：
   - 若出现二维码（canvas 或 img 元素）：截图保存到 {TMP_DIR}/qr_{target}.png，
     然后调用 ask_feishu 发送截图，消息为"请用手机扫码登录 {target}"，
     等待成功跳转（轮询页面 URL 变化，最多等 3 分钟）。
   - 若出现图形验证码：截图保存到 {TMP_DIR}/captcha_{target}.png，
     调用 ask_feishu 发送截图，消息为"请回复图中验证码内容"，
     拿到回复后填入验证码输入框并提交。
   - 若出现短信验证码输入框：点击"发送短信"按钮，
     调用 ask_feishu（无截图），消息为"短信验证码已发送，请回复验证码"，
     拿到回复后填入输入框并提交。
   - 若只需用户名/密码：{cred_step}
4. 判断登录是否成功：当前页面 URL 已不再包含 "login"、"sso"、"passport"、"signin" 等关键词，
   或页面出现用户名/头像/个人中心等已登录标志，即视为登录成功。
5. 登录成功后立即输出 JSON（最后一行），然后结束任务，不要继续点击或导航：
   {{"urls": []}}

约束：不提交表单，不点击删除，不点击退出登录。登录成功即结束，不做任何额外探索。
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

        persist_cdp_auth_state(target, db_path, cdp_url, role=role)

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
    parser.add_argument("--username", default="", help="账号（可选，直接嵌入 task）")
    parser.add_argument("--password", default="", help="密码（可选，直接嵌入 task）")
    parser.add_argument("--role", default="primary", choices=["primary", "secondary"], help="写入 auth_sessions 的账号角色")
    parser.add_argument("--account-label", default=None, help="写入 auth_credentials 的账号标签，默认等于 --role")
    args = parser.parse_args()

    if not os.environ.get("DEEPSEEK_API"):
        sys.exit("[error] 请设置环境变量 DEEPSEEK_API")
    if not os.environ.get("FEISHU_CHAT_ID"):
        sys.exit("[error] 请设置环境变量 FEISHU_CHAT_ID")

    db_path = find_db(args.target)
    if not db_path:
        sys.exit(f"[error] 找不到目标 DB: {args.target}")

    from auth.chrome_manager import ensure_chrome  # noqa: PLC0415

    cdp_url = ensure_chrome(args.target)

    TMP_DIR.mkdir(exist_ok=True)

    account_label = args.account_label or args.role
    success = asyncio.run(
        run_browser_auth(args.target, args.url, cdp_url, db_path, args.username, args.password, role=args.role)
    )

    if success:
        set_phase(db_path, "auth_ready")
        if args.username:
            write_credentials_to_db(db_path, args.username, args.password, args.url, account_label=account_label)
        print("[browser_auth] 登录成功，phase → auth_ready", file=sys.stderr)
    else:
        set_phase(db_path, "auth_timeout")
        print("[browser_auth] 登录失败，phase → auth_timeout", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
