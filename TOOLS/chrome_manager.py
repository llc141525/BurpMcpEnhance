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
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603


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
        print(f"[chrome] 启动中（port={port}, proxy={caido_port})...", file=sys.stderr)
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
