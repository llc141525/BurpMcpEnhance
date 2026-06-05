# Browser Auth Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 集成单 Chrome 实例 + browser-use + feishu_notify，解决凭证过期、验证码阻断、认证资产覆盖不到三个核心痛点。

**Architecture:** chrome_manager.py 管理单一 Chrome 进程（CDP 9222 + Caido 代理 8181）；browser_auth.py 用 browser-use agent 完成登录流程，通过自定义 action 把截图发飞书等操作员手机回复；登录成功后立即做一次 surface discovery，把认证区域入口 URL 写入 BFS 管线。

**Tech Stack:** patchright（Chrome 启动/CDP 连接）, browser-use 0.x（AI 登录 agent）, langchain-anthropic（Claude Haiku LLM）, lark-cli（飞书通知+轮询）, SQLite, Python 3.11+

---

## File Map

| 操作 | 路径 | 职责 |
|------|------|------|
| 新增 | `migrations/008_browser_auth.sql` | 添加 `scan_state.cdp_url` 和 `auth_sessions.cookie_source` |
| 新增 | `TOOLS/chrome_manager.py` | Chrome 生命周期：检测/启动/CDP URL 写 DB |
| 新增 | `TOOLS/feishu_notify.py` | lark-cli 封装：发消息/图片 + 轮询等回复 |
| 新增 | `TOOLS/browser_auth.py` | browser-use agent：登录 + surface discovery |
| 新增 | `tests/test_chrome_manager.py` | chrome_manager 单元测试 |
| 新增 | `tests/test_feishu_notify.py` | feishu_notify 单元测试 |
| 新增 | `tests/test_browser_auth.py` | browser_auth 单元测试 |
| 修改 | `TOOLS/bfs_crawl.py` | main() 首行调用 chrome_manager |
| 修改 | `TOOLS/init_scan.py` | 检测 302/401 → 写 auth_pending → 调 browser_auth.py |
| 修改 | `.mcp.json` | 移除 stealth-browser，新增 caido（TODO 占位） |
| 删除 | `.mcp-browser.json` | stealth-agent-browser-mcp 配置 |
| 修改 | `.claude/skills/stealth-scanner/SKILL.md` | 通过 skill-editor 更新状态机和工具速查 |

---

## Task 1: 安装依赖 + 创建 DB Migration

**Files:**
- Create: `migrations/008_browser_auth.sql`

- [ ] **Step 1: 安装 Python 依赖**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/pip install browser-use langchain-anthropic
```

预期输出：`Successfully installed browser-use-... langchain-anthropic-...`

- [ ] **Step 2: 验证 lark-cli 已安装**

```bash
lark --version
```

若未安装，按 https://github.com/larksuite/cli/blob/main/README.zh.md 安装，然后运行 `lark login` 完成认证。

- [ ] **Step 3: 创建 migration 文件**

创建 `migrations/008_browser_auth.sql`：

```sql
-- 008: browser_auth integration
-- chrome_manager 写入 CDP 连接地址
ALTER TABLE scan_state ADD COLUMN cdp_url TEXT DEFAULT NULL;

-- 区分 cookie 来源：manual(Burp手动) / browser_use(自动提取)
ALTER TABLE auth_sessions ADD COLUMN cookie_source TEXT DEFAULT 'manual';
```

- [ ] **Step 4: 对现有 DB 执行迁移**

```bash
cd "e:/SRC挖掘/SRC"
python3 TOOLS/migrate.py --target "人民教育出版社"
```

预期输出包含 `[008] 执行 008_browser_auth.sql ... OK`

- [ ] **Step 5: Commit**

```bash
git add migrations/008_browser_auth.sql
git commit -m "feat: add migration 008 for browser_auth columns"
```

---

## Task 2: TOOLS/chrome_manager.py

**Files:**
- Create: `TOOLS/chrome_manager.py`
- Create: `tests/test_chrome_manager.py`

- [ ] **Step 1: 写失败测试**

创建 `tests/test_chrome_manager.py`：

```python
"""Tests for chrome_manager.py"""
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_is_chrome_running_returns_true_when_port_responds():
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        from TOOLS.chrome_manager import is_chrome_running
        assert is_chrome_running(9222) is True


def test_is_chrome_running_returns_false_when_port_closed():
    import requests
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        from TOOLS.chrome_manager import is_chrome_running
        assert is_chrome_running(9222) is False


def test_wait_for_chrome_returns_cdp_url_when_ready():
    with patch("TOOLS.chrome_manager.is_chrome_running", side_effect=[False, False, True]):
        with patch("time.sleep"):
            from TOOLS.chrome_manager import wait_for_chrome
            result = wait_for_chrome(port=9222, timeout=5)
            assert result == "http://localhost:9222"


def test_wait_for_chrome_raises_on_timeout():
    with patch("TOOLS.chrome_manager.is_chrome_running", return_value=False):
        with patch("time.sleep"):
            with patch("time.time", side_effect=[0, 1, 2, 3, 4, 5, 6]):
                from TOOLS.chrome_manager import wait_for_chrome
                with pytest.raises(TimeoutError):
                    wait_for_chrome(port=9222, timeout=5)


def test_write_cdp_url_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE scan_state (id INTEGER PRIMARY KEY, cdp_url TEXT)")
    conn.execute("INSERT INTO scan_state (id) VALUES (1)")
    conn.commit()
    conn.close()

    from TOOLS.chrome_manager import write_cdp_url_to_db
    write_cdp_url_to_db(db_path, "http://localhost:9222")

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT cdp_url FROM scan_state WHERE id=1").fetchone()
    conn.close()
    assert row[0] == "http://localhost:9222"
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_chrome_manager.py -v 2>&1 | head -30
```

预期：`ModuleNotFoundError: No module named 'TOOLS.chrome_manager'`

- [ ] **Step 3: 创建 TOOLS/chrome_manager.py**

```python
"""Chrome 单实例管理：检测/启动 Chrome，写 CDP URL 到 DB。

用法:
  python3 TOOLS/chrome_manager.py --target "目标名"
  # 输出: http://localhost:9222

  python3 TOOLS/chrome_manager.py --port 9223 --caido-port 8181 --target "目标名"
"""

import argparse
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBS_DIR = PROJECT_ROOT / "dbs"
BROWSER_PROFILE = PROJECT_ROOT / ".browser-profile"

CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Users\llc\AppData\Local\Google\Chrome\Application\chrome.exe",
]


def find_chrome_executable() -> str:
    for path in CHROME_PATHS:
        if Path(path).exists():
            return path
    raise FileNotFoundError("Chrome 未找到，请确认安装路径")


def is_chrome_running(port: int = 9222) -> bool:
    try:
        resp = requests.get(f"http://localhost:{port}/json/version", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def launch_chrome(port: int = 9222, caido_port: int = 8181) -> subprocess.Popen:
    chrome = find_chrome_executable()
    BROWSER_PROFILE.mkdir(exist_ok=True)
    cmd = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--proxy-server=http://127.0.0.1:{caido_port}",
        f"--user-data-dir={BROWSER_PROFILE}",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--lang=zh-CN",
        "--window-position=1400,0",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_chrome(port: int = 9222, timeout: int = 15) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_chrome_running(port):
            return f"http://localhost:{port}"
        time.sleep(0.5)
    raise TimeoutError(f"Chrome 未在 {timeout}s 内就绪（port={port}）")


def find_db(target: str) -> str | None:
    matches = sorted(DBS_DIR.glob(f"{target}_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    return str(matches[0]) if matches else None


def write_cdp_url_to_db(db_path: str, cdp_url: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("UPDATE scan_state SET cdp_url=? WHERE id=1", (cdp_url,))
    conn.commit()
    conn.close()


def ensure_chrome(target: str, port: int = 9222, caido_port: int = 8181) -> str:
    """确保 Chrome 在线，返回 cdp_url。"""
    if is_chrome_running(port):
        cdp_url = f"http://localhost:{port}"
        print(f"[chrome] 已在线: {cdp_url}", file=sys.stderr)
    else:
        print(f"[chrome] 启动中（port={port}, proxy=8181)...", file=sys.stderr)
        launch_chrome(port, caido_port)
        cdp_url = wait_for_chrome(port)
        print(f"[chrome] 就绪: {cdp_url}", file=sys.stderr)

    db_path = find_db(target)
    if db_path:
        write_cdp_url_to_db(db_path, cdp_url)

    return cdp_url


def main() -> None:
    parser = argparse.ArgumentParser(description="Chrome 单实例管理")
    parser.add_argument("--target", required=True, help="目标名")
    parser.add_argument("--port", type=int, default=9222, help="CDP 端口（默认 9222）")
    parser.add_argument("--caido-port", type=int, default=int(os.environ.get("CAIDO_PORT", "8181")))
    args = parser.parse_args()

    try:
        cdp_url = ensure_chrome(args.target, args.port, args.caido_port)
        print(cdp_url)  # stdout 供调用方读取
    except (FileNotFoundError, TimeoutError) as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 创建 tests/__init__.py 和 TOOLS/__init__.py**

```bash
touch "e:/SRC挖掘/SRC/tests/__init__.py"
touch "e:/SRC挖掘/SRC/TOOLS/__init__.py"
```

- [ ] **Step 5: 运行测试确认通过**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_chrome_manager.py -v
```

预期：`5 passed`

- [ ] **Step 6: Commit**

```bash
git add TOOLS/chrome_manager.py TOOLS/__init__.py tests/test_chrome_manager.py tests/__init__.py
git commit -m "feat: add chrome_manager — single Chrome instance via CDP"
```

---

## Task 3: TOOLS/feishu_notify.py

**Files:**
- Create: `TOOLS/feishu_notify.py`
- Create: `tests/test_feishu_notify.py`

> ⚠️ lark-cli 命令语法需对照 https://github.com/larksuite/cli/blob/main/README.zh.md 确认。
> 下面的子命令 `im message create` / `im message list` 遵循 Feishu OpenAPI 路径约定，
> 若实际命令不同，只需修改 `_lark_send_text` / `_lark_get_messages` 两个函数。

- [ ] **Step 1: 写失败测试**

创建 `tests/test_feishu_notify.py`：

```python
"""Tests for feishu_notify.py"""
import json
import time
from unittest.mock import MagicMock, call, patch

import pytest


def test_poll_for_reply_returns_text_when_new_message_appears():
    baseline = [{"message_id": "msg_001", "body": {"content": json.dumps({"text": "old"})}}]
    new_msg = [
        {"message_id": "msg_001", "body": {"content": json.dumps({"text": "old"})}},
        {"message_id": "msg_002", "body": {"content": json.dumps({"text": "1a2b"})}},
    ]
    with patch("TOOLS.feishu_notify._lark_get_messages", side_effect=[baseline, new_msg]):
        with patch("time.sleep"):
            with patch("time.time", side_effect=[0, 1, 2, 200]):
                from TOOLS.feishu_notify import _poll_for_reply
                result = _poll_for_reply("chat_abc", timeout=180)
                assert result == "1a2b"


def test_poll_for_reply_returns_none_on_timeout():
    baseline = [{"message_id": "msg_001", "body": {"content": json.dumps({"text": "old"})}}]
    with patch("TOOLS.feishu_notify._lark_get_messages", return_value=baseline):
        with patch("time.sleep"):
            # time.time: start=0, then 181 immediately
            with patch("time.time", side_effect=[0, 181, 182]):
                from TOOLS.feishu_notify import _poll_for_reply
                result = _poll_for_reply("chat_abc", timeout=180)
                assert result is None


def test_send_text_wait_reply_calls_send_then_polls():
    with patch("TOOLS.feishu_notify._lark_send_text") as mock_send:
        with patch("TOOLS.feishu_notify._poll_for_reply", return_value="1234") as mock_poll:
            from TOOLS.feishu_notify import send_text_wait_reply
            result = send_text_wait_reply("chat_abc", "请回复验证码", timeout=60)
            mock_send.assert_called_once_with("chat_abc", "请回复验证码")
            mock_poll.assert_called_once_with("chat_abc", 60)
            assert result == "1234"


def test_send_image_calls_lark_send_image():
    with patch("TOOLS.feishu_notify._lark_send_image") as mock_send:
        from TOOLS.feishu_notify import send_image
        send_image("chat_abc", "/tmp/qr.png", "请扫码登录")
        mock_send.assert_called_once_with("chat_abc", "/tmp/qr.png", "请扫码登录")
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_feishu_notify.py -v 2>&1 | head -20
```

预期：`ModuleNotFoundError: No module named 'TOOLS.feishu_notify'`

- [ ] **Step 3: 创建 TOOLS/feishu_notify.py**

```python
"""飞书通知 + 回复轮询：lark-cli 封装。

用法（Python import）:
  from TOOLS.feishu_notify import send_image, send_image_wait_reply, send_text_wait_reply

  send_image(chat_id, "/tmp/qr.png", "请扫码登录")
  answer = send_image_wait_reply(chat_id, "/tmp/cap.png", "请回复验证码内容")
  otp = send_text_wait_reply(chat_id, "短信已发，请回复验证码")

CLI 用法（直接调用）:
  python3 TOOLS/feishu_notify.py send-image --chat-id xxx --img /tmp/qr.png --msg "请扫码"
  python3 TOOLS/feishu_notify.py send-image-wait-reply --chat-id xxx --img /tmp/cap.png --msg "请回复验证码"
  python3 TOOLS/feishu_notify.py send-text-wait-reply --chat-id xxx --msg "短信已发"

环境变量:
  FEISHU_CHAT_ID   默认 chat_id（可被 --chat-id 覆盖）

⚠️ lark-cli 子命令语法对照 https://github.com/larksuite/cli/blob/main/README.zh.md
"""

import argparse
import json
import os
import subprocess
import sys
import time

POLL_INTERVAL = 3   # seconds
POLL_TIMEOUT = 180  # seconds (3 minutes)


def _run_lark(args: list[str]) -> str:
    result = subprocess.run(
        ["lark"] + args,
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _lark_send_text(chat_id: str, text: str) -> None:
    # ⚠️ 验证命令语法，参照 lark-cli README
    _run_lark([
        "im", "message", "create",
        "--receive-id-type", "chat_id",
        "--receive-id", chat_id,
        "--msg-type", "text",
        "--content", json.dumps({"text": text}),
    ])


def _lark_send_image(chat_id: str, image_path: str, text: str) -> None:
    # Step 1: 上传图片获取 image_key
    # ⚠️ 验证命令语法，参照 lark-cli README
    upload_out = _run_lark([
        "im", "image", "create",
        "--image-type", "message",
        "--image", image_path,
    ])
    image_key = json.loads(upload_out).get("image_key", "")

    # Step 2: 发送图片消息
    _run_lark([
        "im", "message", "create",
        "--receive-id-type", "chat_id",
        "--receive-id", chat_id,
        "--msg-type", "image",
        "--content", json.dumps({"image_key": image_key}),
    ])

    # Step 3: 发送说明文字
    if text:
        _lark_send_text(chat_id, text)


def _lark_get_messages(chat_id: str) -> list[dict]:
    # ⚠️ 验证命令语法，参照 lark-cli README
    out = _run_lark([
        "im", "message", "list",
        "--container-id-type", "chat",
        "--container-id", chat_id,
        "--sort-type", "ByCreateTimeDesc",
        "--page-size", "10",
    ])
    data = json.loads(out) if out else {}
    return data.get("items", [])


def _poll_for_reply(chat_id: str, timeout: int = POLL_TIMEOUT) -> str | None:
    """轮询 chat 消息，直到出现新消息，返回消息文本。超时返回 None。"""
    baseline = _lark_get_messages(chat_id)
    baseline_ids = {m.get("message_id") for m in baseline}

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        msgs = _lark_get_messages(chat_id)
        for m in msgs:
            if m.get("message_id") not in baseline_ids:
                try:
                    content = json.loads(m.get("body", {}).get("content", "{}"))
                    return content.get("text", "").strip()
                except (json.JSONDecodeError, AttributeError):
                    return str(m.get("body", {}).get("content", "")).strip()
    return None


def send_image(chat_id: str, image_path: str, msg: str) -> None:
    """发图片通知，不等回复（QR 码场景）。"""
    _lark_send_image(chat_id, image_path, msg)


def send_image_wait_reply(chat_id: str, image_path: str, msg: str, timeout: int = POLL_TIMEOUT) -> str | None:
    """发图片，等待操作员回复（验证码场景）。"""
    _lark_send_image(chat_id, image_path, msg)
    return _poll_for_reply(chat_id, timeout)


def send_text_wait_reply(chat_id: str, msg: str, timeout: int = POLL_TIMEOUT) -> str | None:
    """发文字，等待操作员回复（OTP 场景）。"""
    _lark_send_text(chat_id, msg)
    return _poll_for_reply(chat_id, timeout)


def main() -> None:
    chat_id_default = os.environ.get("FEISHU_CHAT_ID", "")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    for mode in ("send-image", "send-image-wait-reply"):
        p = sub.add_parser(mode)
        p.add_argument("--chat-id", default=chat_id_default, required=not chat_id_default)
        p.add_argument("--img", required=True)
        p.add_argument("--msg", default="")

    p3 = sub.add_parser("send-text-wait-reply")
    p3.add_argument("--chat-id", default=chat_id_default, required=not chat_id_default)
    p3.add_argument("--msg", required=True)

    args = parser.parse_args()

    if args.mode == "send-image":
        send_image(args.chat_id, args.img, args.msg)
    elif args.mode == "send-image-wait-reply":
        reply = send_image_wait_reply(args.chat_id, args.img, args.msg)
        if reply:
            print(reply)
        else:
            print("[timeout]", file=sys.stderr)
            sys.exit(1)
    elif args.mode == "send-text-wait-reply":
        reply = send_text_wait_reply(args.chat_id, args.msg)
        if reply:
            print(reply)
        else:
            print("[timeout]", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_feishu_notify.py -v
```

预期：`4 passed`

- [ ] **Step 5: Commit**

```bash
git add TOOLS/feishu_notify.py tests/test_feishu_notify.py
git commit -m "feat: add feishu_notify — lark-cli wrapper with reply polling"
```

---

## Task 4: TOOLS/browser_auth.py

**Files:**
- Create: `TOOLS/browser_auth.py`
- Create: `tests/test_browser_auth.py`

- [ ] **Step 1: 写失败测试**

创建 `tests/test_browser_auth.py`：

```python
"""Tests for browser_auth.py"""
import json
import sqlite3
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_parse_surface_urls_filters_same_domain():
    from TOOLS.browser_auth import parse_surface_urls
    raw = [
        {"url": "https://example.com/dashboard", "title": "Dashboard"},
        {"url": "https://example.com/settings", "title": "Settings"},
        {"url": "https://other.com/evil", "title": "External"},
        {"url": "https://sub.example.com/api", "title": "API"},
    ]
    result = parse_surface_urls(raw, base_domain="example.com")
    urls = [r["url"] for r in result]
    assert "https://example.com/dashboard" in urls
    assert "https://example.com/settings" in urls
    assert "https://sub.example.com/api" in urls
    assert "https://other.com/evil" not in urls


def test_parse_surface_urls_filters_static_assets():
    from TOOLS.browser_auth import parse_surface_urls
    raw = [
        {"url": "https://example.com/page", "title": "Page"},
        {"url": "https://example.com/style.css", "title": ""},
        {"url": "https://example.com/logo.png", "title": ""},
        {"url": "https://example.com/app.js", "title": ""},
    ]
    result = parse_surface_urls(raw, base_domain="example.com")
    urls = [r["url"] for r in result]
    assert "https://example.com/page" in urls
    assert "https://example.com/style.css" not in urls
    assert "https://example.com/logo.png" not in urls
    # JS files are NOT filtered — they may contain API endpoints worth crawling
    assert "https://example.com/app.js" in urls


def test_write_surface_urls_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        depth INTEGER,
        status TEXT,
        source TEXT
    )""")
    conn.commit()
    conn.close()

    from TOOLS.browser_auth import write_surface_urls_to_db
    urls = [
        {"url": "https://example.com/dashboard", "title": "Dashboard"},
        {"url": "https://example.com/admin", "title": "Admin"},
    ]
    count = write_surface_urls_to_db(db_path, urls)
    assert count == 2

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT url, source FROM pages").fetchall()
    conn.close()
    assert len(rows) == 2
    assert all(r[1] == "browser_use" for r in rows)


def test_write_cookies_to_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE auth_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_type TEXT,
        token_name TEXT,
        token_value TEXT,
        domain TEXT,
        path TEXT,
        is_active INTEGER DEFAULT 1,
        cookie_source TEXT DEFAULT 'manual'
    )""")
    conn.commit()
    conn.close()

    from TOOLS.browser_auth import write_cookies_to_db
    cookies = [
        {"name": "session", "value": "abc123", "domain": "example.com", "path": "/"},
        {"name": "csrf", "value": "xyz", "domain": "example.com", "path": "/"},
    ]
    write_cookies_to_db(db_path, cookies)

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT token_name, cookie_source FROM auth_sessions").fetchall()
    conn.close()
    assert len(rows) == 2
    assert all(r[1] == "browser_use" for r in rows)
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_browser_auth.py -v 2>&1 | head -20
```

预期：`ModuleNotFoundError: No module named 'TOOLS.browser_auth'`

- [ ] **Step 3: 创建 TOOLS/browser_auth.py**

```python
"""browser-use agent：登录 + surface discovery + 写 DB。

用法:
  python3 TOOLS/browser_auth.py --target "目标名" --url "https://example.com/login"

输出:
  - auth_sessions 表写入 cookies（cookie_source='browser_use'）
  - pages 表写入认证后发现的 URL（source='browser_use', status='queued'）
  - scan_state.phase 更新为 'auth_ready'（成功）或 'auth_timeout'（超时）

环境变量:
  ANTHROPIC_API_KEY   Claude Haiku API key（必填）
  FEISHU_CHAT_ID      飞书 chat_id（必填）
  CAIDO_PORT          Caido 代理端口（默认 8181）
"""

import argparse
import asyncio
import json
import os
import re
import sqlite3
import sys
from datetime import datetime
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
    """过滤：同域 + 排除纯静态资源（CSS/图片/字体）。"""
    result = []
    for item in raw:
        url = item.get("url", "")
        if not url.startswith("http"):
            continue
        # domain check
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc
            base = base_domain.lstrip("www.")
            if not (host == base_domain or host == f"www.{base}" or host.endswith(f".{base}")):
                continue
        except Exception:
            continue
        # skip static-only extensions
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
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
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
    """
    browser-use agent 登录 + surface discovery。
    成功返回 True，失败/超时返回 False。
    """
    from browser_use import Agent, BrowserConfig
    from browser_use.browser.context import BrowserContext
    from langchain_anthropic import ChatAnthropic

    chat_id = os.environ.get("FEISHU_CHAT_ID", "")
    if not chat_id:
        print("[error] 环境变量 FEISHU_CHAT_ID 未设置", file=sys.stderr)
        return False

    llm = ChatAnthropic(
        model="claude-haiku-4-5-20251001",
        api_key=os.environ["ANTHROPIC_API_KEY"],
        timeout=60,
    )
    browser_config = BrowserConfig(cdp_url=cdp_url, headless=False)

    # Custom action：阻塞等待操作员通过飞书回复
    from browser_use import Controller
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
最大步骤：20。
"""

    try:
        agent = Agent(
            task=task,
            llm=llm,
            browser_config=browser_config,
            controller=controller,
            max_steps=20,
        )
        result = await asyncio.wait_for(agent.run(), timeout=300)

        # 提取最终输出的 JSON
        output_text = str(result)
        json_match = re.search(r'\{"urls":\s*\[.*?\]\}', output_text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            raw_urls = data.get("urls", [])
            filtered = parse_surface_urls(raw_urls, base_domain)
            added = write_surface_urls_to_db(db_path, filtered)
            print(f"[browser_auth] surface discovery: {len(raw_urls)} 原始 → {added} 条写入 pages", file=sys.stderr)

        # 提取 cookies（通过 patchright CDP）
        from patchright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.connect_over_cdp(cdp_url)
            context = browser.contexts[0] if browser.contexts else None
            if context:
                cookies = await context.cookies()
                write_cookies_to_db(db_path, cookies)
                print(f"[browser_auth] 写入 {len(cookies)} 条 cookies", file=sys.stderr)

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

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("[error] 请设置环境变量 ANTHROPIC_API_KEY")
    if not os.environ.get("FEISHU_CHAT_ID"):
        sys.exit("[error] 请设置环境变量 FEISHU_CHAT_ID")

    db_path = find_db(args.target)
    if not db_path:
        sys.exit(f"[error] 找不到目标 DB: {args.target}")

    # 从 DB 读取 cdp_url
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT cdp_url FROM scan_state WHERE id=1").fetchone()
    conn.close()
    cdp_url = row[0] if row and row[0] else "http://localhost:9222"

    TMP_DIR.mkdir(exist_ok=True)

    success = asyncio.run(run_browser_auth(args.target, args.url, cdp_url, db_path))

    if success:
        set_phase(db_path, "auth_ready")
        print(f"[browser_auth] 登录成功，phase → auth_ready", file=sys.stderr)
    else:
        set_phase(db_path, "auth_timeout")
        print(f"[browser_auth] 登录失败，phase → auth_timeout", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -m pytest tests/test_browser_auth.py -v
```

预期：`4 passed`

- [ ] **Step 5: Commit**

```bash
git add TOOLS/browser_auth.py tests/test_browser_auth.py
git commit -m "feat: add browser_auth — browser-use login agent with Feishu interaction"
```

---

## Task 5: 修改 TOOLS/bfs_crawl.py

**Files:**
- Modify: `TOOLS/bfs_crawl.py:160-190`（main 函数）

- [ ] **Step 1: 在 main() 首行添加 chrome_manager 调用**

找到 `bfs_crawl.py` 的 `main()` 函数（第 160 行），在 `db_path = find_db(args.target)` 之前插入：

```python
def main() -> None:
    parser = argparse.ArgumentParser(description="katana BFS 批量爬取")
    parser.add_argument("--target", required=True, help="目标名 (从 dbs/ 查找 DB)")
    parser.add_argument("--url", help="覆盖种子 URL（默认从 DB 读取）")
    parser.add_argument("--depth", type=int, default=3, help="爬取深度 (默认 3)")
    parser.add_argument("--max-pages", type=int, default=500, help="最大页面数 (默认 500)")
    parser.add_argument("--no-chrome", action="store_true", help="跳过 Chrome 启动（无需浏览器的目标）")
    args = parser.parse_args()

    # ── 启动/确认 Chrome 单实例 ──────────────────────────────────────────
    if not args.no_chrome:
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).parent / "chrome_manager.py"), "--target", args.target],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                print(f"[warn] chrome_manager 失败，继续不带 CDP: {result.stderr.strip()}")
            else:
                print(f"[chrome] {result.stdout.strip()}", file=sys.stderr)
        except Exception as e:
            print(f"[warn] chrome_manager 异常: {e}")
    # ────────────────────────────────────────────────────────────────────

    db_path = find_db(args.target)
    conn = connect(db_path)
    # ... 以下不变
```

同时在文件顶部 import 区块末尾加入（如果尚未有）：

```python
from pathlib import Path
```

（`bfs_crawl.py` 已有此 import，确认不重复）

- [ ] **Step 2: 验证语法**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -c "import ast; ast.parse(open('TOOLS/bfs_crawl.py').read()); print('syntax ok')"
```

预期：`syntax ok`

- [ ] **Step 3: Commit**

```bash
git add TOOLS/bfs_crawl.py
git commit -m "feat: bfs_crawl calls chrome_manager at startup"
```

---

## Task 6: 修改 TOOLS/init_scan.py

**Files:**
- Modify: `TOOLS/init_scan.py:144-194`（update_target + main 函数）

- [ ] **Step 1: 在 update_target() 添加 auth 检测，在 main() 调用 browser_auth**

修改 `update_target()` 函数，新增返回值以携带 auth 检测结果：

```python
AUTH_STATUS_CODES = {302, 401, 403}
AUTH_KEYWORDS = re.compile(
    r"(login|signin|sign-in|auth|passport|sso|oauth|账号|登录|验证|portal|请先登录|会话过期)",
    re.IGNORECASE,
)


def update_target(conn: sqlite3.Connection, result: dict) -> dict:
    """更新 targets 表，返回 {'url': ..., 'needs_auth': bool}。"""
    url = result.get("url", result.get("input", ""))
    status_code = result.get("status_code", 0)
    title = result.get("title", "")
    ip = result.get("host", "")
    tech_list: list = result.get("tech", []) or []
    tech_stack = ", ".join(tech_list) if tech_list else ""

    hostname = _strip_scheme(url)
    rows_updated = conn.execute(
        "UPDATE targets SET tech_stack=?, ip=? WHERE domain=? OR domain=?",
        (tech_stack, ip, url, hostname),
    ).rowcount
    conn.commit()

    if rows_updated == 0:
        print(f"  [warn] targets 中未找到匹配域名: {hostname}（跳过更新）")

    needs_auth = (
        status_code in AUTH_STATUS_CODES
        or bool(AUTH_KEYWORDS.search(title or ""))
        or bool(AUTH_KEYWORDS.search(url or ""))
    )
    if needs_auth:
        print(f"  [!] 疑似需要认证: {url} (HTTP {status_code}) — {title}")

    if status_code in (200, 301, 302, 403):
        conn.execute(
            "INSERT INTO pages (url, depth, status) VALUES (?, 0, 'queued') ON CONFLICT(url) DO NOTHING",
            (url,),
        )
        conn.commit()

    return {"url": url, "needs_auth": needs_auth, "status_code": status_code}
```

修改 `main()` 末尾，在打印摘要前检查并触发 auth：

```python
def main() -> None:
    # ... 解析参数不变 ...

    results = run_httpx(urls)

    auth_targets: list[dict] = []
    if args.target:
        db_path = find_db(args.target)
        conn = connect(db_path)
        for r in results:
            info = update_target(conn, r)
            if info["needs_auth"]:
                auth_targets.append(info)
        conn.close()
        print(f"[db] 已更新 targets 表，DB: {db_path.name}")

    print_summary(results)

    # ── auth 检测：触发 browser_auth ────────────────────────────────────
    if auth_targets and args.target:
        db_path_str = str(find_db(args.target))
        # 写 auth_pending
        conn = sqlite3.connect(db_path_str)
        conn.execute("UPDATE scan_state SET phase='auth_pending' WHERE id=1")
        conn.commit()
        conn.close()

        login_url = auth_targets[0]["url"]
        print(f"\n[auth] 检测到认证壁垒，启动 browser_auth: {login_url}")

        # 先确保 Chrome 在线
        subprocess.run(
            [sys.executable, str(Path(__file__).parent / "chrome_manager.py"), "--target", args.target],
            timeout=20,
        )

        # 调用 browser_auth
        ret = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "browser_auth.py"),
             "--target", args.target, "--url", login_url],
            timeout=360,
        )
        if ret.returncode != 0:
            print("[auth] browser_auth 失败，请检查飞书通知或手动登录")
    # ────────────────────────────────────────────────────────────────────
```

在文件顶部补充 import（若缺少）：

```python
import subprocess
from pathlib import Path
```

- [ ] **Step 2: 验证语法**

```bash
cd "e:/SRC挖掘/SRC"
.venv/Scripts/python -c "import ast; ast.parse(open('TOOLS/init_scan.py').read()); print('syntax ok')"
```

预期：`syntax ok`

- [ ] **Step 3: Commit**

```bash
git add TOOLS/init_scan.py
git commit -m "feat: init_scan detects auth barriers and invokes browser_auth"
```

---

## Task 7: 更新 .mcp.json + 删除 .mcp-browser.json

**Files:**
- Modify: `.mcp.json`
- Delete: `.mcp-browser.json`

- [ ] **Step 1: 更新 .mcp.json**

将 `.mcp.json` 修改为（移除 stealth-browser，新增 caido 占位）：

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp",
      "env": {
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost"
      }
    },
    "sqlite": {
      "command": "python",
      "args": [
        "E:\\SRC挖掘\\SRC\\TOOLS\\sqlite-mcp-server.py",
        "E:\\SRC挖掘\\SRC\\.claude\\skills\\stealth-scanner\\scanner.db"
      ],
      "env": {
        "NO_PROXY": "registry.npmjs.org,unpkg.com,*.npmjs.org,github.com,*.github.com"
      }
    },
    "MiniMax": {
      "command": "uvx",
      "args": [
        "minimax-coding-plan-mcp",
        "-y"
      ],
      "env": {
        "MINIMAX_API_KEY": "sk-cp-ECfFbjNgBCOjnL2I4IQuiLGbx5Ix6FJwp0KQgEdXQjsvVG1WqVyCnuP0pVez5SEf-J2QTWUxxYnXO518zo0hbIyXgmWn57VMWeZOXyzIeT9_I0kO-x5rsDQ",
        "MINIMAX_API_HOST": "https://api.minimaxi.com"
      }
    },
    "scrapling": {
      "command": "E:\\SRC挖掘\\SRC\\.venv\\Scripts\\scrapling.exe",
      "args": [
        "mcp"
      ]
    },
    "caido": {
      "type": "http",
      "url": "TODO_CAIDO_MCP_URL_AFTER_INSTALL"
    }
  }
}
```

- [ ] **Step 2: 删除 .mcp-browser.json**

```bash
rm "e:/SRC挖掘/SRC/.mcp-browser.json"
```

- [ ] **Step 3: Commit**

```bash
git add .mcp.json
git rm .mcp-browser.json
git commit -m "chore: remove stealth-browser MCP, add caido placeholder in .mcp.json"
```

---

## Task 8: 更新 stealth-scanner SKILL.md（via skill-editor）

**Files:**
- Modify: `.claude/skills/stealth-scanner/SKILL.md`

> ⚠️ **必须使用 `skill-editor` skill** 来修改此文件，不能直接 Edit。

- [ ] **Step 1: 调用 skill-editor**

```
Skill(skill="skill-editor", args="目标文件: .claude/skills/stealth-scanner/SKILL.md")
```

- [ ] **Step 2: 通过 skill-editor 指令更新以下内容**

**2a. 工具速查表新增三行：**

```markdown
| 启动/确认 Chrome | `python3 TOOLS/chrome_manager.py --target "{目标}"` |
| 触发 auth 流程 | `python3 TOOLS/browser_auth.py --target "{目标}" --url "{登录页URL}"` |
| 飞书发图等回复 | `python3 TOOLS/feishu_notify.py send-image-wait-reply --chat-id $FEISHU_CHAT_ID --img tmp/cap.png --msg "请回复验证码"` |
```

**2b. allowed-tools 行：**

将 `mcp__stealth_browser__*` 替换为 `mcp__caido__*`

**2c. Phase 2.5 会话过期检测 内容替换为：**

```markdown
### 2.5 会话过期检测

响应 302/401 或内容含登录页特征 →

1. 写 `scan_state.phase = 'auth_pending'`
2. 调用 chrome_manager 确保 Chrome 在线
3. 调用 browser_auth.py 触发自动登录流程（飞书通知 + 操作员手机响应）
4. 成功后 phase → `auth_ready`，继续 BFS
5. 失败/超时后 phase → `auth_timeout`，跳过该目标

```bash
python3 TOOLS/chrome_manager.py --target "{目标}"
python3 TOOLS/browser_auth.py --target "{目标}" --url "{302跳转目标URL}"
```
```

**2d. 状态机新增两个状态：**

```markdown
| `auth_timeout` | 飞书超时，跳过目标 | — |
| `chrome_error` | Chrome 启动失败，通知操作员 | — |
```

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/stealth-scanner/SKILL.md
git commit -m "feat: update stealth-scanner skill — browser_auth flow, remove stealth-browser"
```

---

## Task 9: 设置环境变量

- [ ] **Step 1: 在 Windows 用户环境变量中设置（PowerShell）**

```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...<your-new-key>", "User")
[System.Environment]::SetEnvironmentVariable("FEISHU_CHAT_ID", "<your-feishu-chat-id>", "User")
[System.Environment]::SetEnvironmentVariable("CAIDO_PORT", "8181", "User")
```

- [ ] **Step 2: 重启 Claude Code session，验证变量可读**

```bash
echo $ANTHROPIC_API_KEY | cut -c1-20
echo $FEISHU_CHAT_ID
echo $CAIDO_PORT
```

预期：显示 key 前 20 位、chat_id、`8181`

- [ ] **Step 3: 冒烟测试 chrome_manager（无需目标 DB）**

```bash
cd "e:/SRC挖掘/SRC"
python3 TOOLS/chrome_manager.py --target "人民教育出版社"
```

预期：`http://localhost:9222`（Chrome 窗口应在副屏出现）

- [ ] **Step 4: 最终 commit**

```bash
git add tests/
git commit -m "test: add unit tests for chrome_manager, feishu_notify, browser_auth"
```

---

## Self-Review

**Spec coverage check:**

| 设计需求 | 对应 Task |
|---------|----------|
| chrome_manager.py — 单 Chrome 实例 | Task 2 ✅ |
| feishu_notify.py — lark-cli 封装 | Task 3 ✅ |
| browser_auth.py — browser-use agent | Task 4 ✅ |
| bfs_crawl.py — 调 chrome_manager | Task 5 ✅ |
| init_scan.py — 检测 401/302 → auth | Task 6 ✅ |
| migrations/008_browser_auth.sql | Task 1 ✅ |
| .mcp.json 移除 stealth-browser | Task 7 ✅ |
| 删除 .mcp-browser.json | Task 7 ✅ |
| stealth-scanner SKILL.md 更新 | Task 8 ✅ |
| 环境变量设置 | Task 9 ✅ |
| skill-editor 用于 SKILL.md 修改 | Task 8 ✅（明确要求） |
| lark-cli 语法验证提示 | Task 3 ✅（⚠️ 注释） |
| CAIDO_PORT=8181 | Task 2/9 ✅ |
| Caido MCP URL = TODO | Task 7 ✅ |

**Placeholder 检查：** 无 TBD/TODO（除 Caido MCP URL 是设计决定的 TODO）。

**类型一致性：** `write_surface_urls_to_db(db_path: str, urls: list[dict])` 在 Task 4 定义，Task 4 内部调用一致。`write_cookies_to_db(db_path: str, cookies: list[dict])` 同。
