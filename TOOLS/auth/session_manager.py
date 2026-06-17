"""共享 Session 续期工具 — 任意 skill 均可调用。

用法:
  python TOOLS/auth/session_manager.py --target "台州学院"
  python TOOLS/auth/session_manager.py --target "台州学院" --login-url "https://sso.tzc.edu.cn/login?..."

退出码:
  0  session 有效（或续期成功）
  1  session 无效且无法续期（需操作员手动登录）
  2  目标 DB 未找到
"""

import argparse
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = Path(__file__).resolve().parent.parent
_venv_python = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON = str(_venv_python) if _venv_python.exists() else sys.executable

sys.path.insert(0, str(TOOLS_DIR))
from auth.auth_state import capture_to_db  # noqa: E402
from db.db_utils import find_db  # noqa: E402


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def sessions_valid(conn: sqlite3.Connection, role: str = "primary") -> bool:
    """True 表示存在至少一个 is_active=1 且未过期的 session。"""
    rows = conn.execute(
        "SELECT is_active, expires_at FROM auth_sessions WHERE is_active=1 AND COALESCE(role, 'primary')=?",
        (role,),
    ).fetchall()
    if not rows:
        return False
    now = datetime.now()
    for r in rows:
        exp = r["expires_at"]
        if not exp:
            return True  # 无过期时间视为永久有效
        try:
            if datetime.strptime(exp, "%Y-%m-%d %H:%M:%S") > now:
                return True
        except ValueError:
            return True
    return False


def get_credentials(conn: sqlite3.Connection, account_label: str = "primary") -> tuple[str, str, str | None] | None:
    """返回 (username, password, login_url) 或 None。

    优先从 auth_credentials 拿（含 login_url），fallback 到 auth_sessions。
    """
    # auth_credentials 表（migration 010 添加）
    try:
        row = conn.execute(
            """SELECT username, password, login_url FROM auth_credentials
               WHERE username IS NOT NULL AND account_label=?
               ORDER BY id DESC LIMIT 1""",
            (account_label,),
        ).fetchone()
        if row and row["username"]:
            return row["username"], row["password"], row["login_url"]
    except sqlite3.OperationalError:
        pass

    # fallback：auth_sessions 里任意 source 存有凭据的行
    row = conn.execute(
        """SELECT username, password FROM auth_sessions
           WHERE username IS NOT NULL AND COALESCE(role, 'primary')=?
           ORDER BY id DESC LIMIT 1""",
        (account_label,),
    ).fetchone()
    if row and row["username"]:
        return row["username"], row["password"], None

    return None


def run_relogin(target: str, login_url: str, username: str, password: str, role: str = "primary") -> bool:
    result = subprocess.run(  # noqa: S603
        [
            PYTHON,
            str(TOOLS_DIR / "auth" / "browser_auth.py"),
            "--target",
            target,
            "--url",
            login_url,
            "--username",
            username,
            "--password",
            password,
            "--role",
            role,
            "--account-label",
            role,
        ],
        timeout=360,
        check=False,
    )
    return result.returncode == 0


def try_cdp_capture(target: str, db_path: str, role: str = "primary") -> bool:
    """尝试从现有 CDP 浏览器捕获认证态。"""
    try:
        counts = capture_to_db(target, db_path, role=role)
        print(
            f"[session_manager] CDP 捕获认证态: cookies={counts.get('cookies', 0)} "
            f"storage_tokens={counts.get('storage_tokens', 0)}",
            file=sys.stderr,
        )
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[session_manager] CDP 捕获失败: {e}", file=sys.stderr)
        return False


def ensure_session(target: str, login_url_override: str | None = None, role: str = "primary") -> bool:
    """检查 session；过期则自动续期。返回 True 表示可继续。"""
    db_path = find_db(target)
    if not db_path:
        print(f"[session_manager] 未找到目标 DB: {target}", file=sys.stderr)
        return False

    conn = connect(db_path)

    # 先用 auth_check.py 更新 is_active 标志
    subprocess.run(  # noqa: S603
        [PYTHON, str(TOOLS_DIR / "db" / "auth_check.py"), "--target", target, "--update"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    conn.close()
    conn = connect(db_path)  # 重连读最新状态

    if sessions_valid(conn, role=role):
        print(f"[session_manager] {role} Session 有效", file=sys.stderr)
        conn.close()
        return True

    print(f"[session_manager] {role} Session 已过期", file=sys.stderr)
    conn.close()

    if role == "primary":
        print("[session_manager] 尝试从现有 Chrome 捕获 primary 认证态...", file=sys.stderr)
        if try_cdp_capture(target, db_path, role=role):
            conn = connect(db_path)
            if sessions_valid(conn, role=role):
                print(f"[session_manager] CDP {role} 认证态可用", file=sys.stderr)
                conn.close()
                return True
            conn.close()
    else:
        print("[session_manager] 跳过 secondary 的 CDP 快速捕获，避免误标当前 primary 浏览器态", file=sys.stderr)

    print(f"[session_manager] 尝试使用 {role} 凭据通过 browser-use 续期...", file=sys.stderr)

    conn = connect(db_path)
    creds = get_credentials(conn, account_label=role)
    conn.close()

    if not creds:
        print("[session_manager] 未找到存储凭据，需手动登录", file=sys.stderr)
        return False

    username, password, stored_login_url = creds
    login_url = login_url_override or stored_login_url

    if not login_url:
        print("[session_manager] 未找到 login_url，请用 --login-url 参数指定", file=sys.stderr)
        return False

    print(f"[session_manager] 使用 {role} 凭据 {username} 重新登录: {login_url}", file=sys.stderr)
    success = run_relogin(target, login_url, username, password, role=role)

    if success:
        print("[session_manager] 续期成功", file=sys.stderr)
    else:
        print("[session_manager] 续期失败，需手动登录", file=sys.stderr)

    return success


def main() -> None:
    parser = argparse.ArgumentParser(description="Session 续期工具")
    parser.add_argument("--target", required=True)
    parser.add_argument("--login-url", default=None, help="登录页 URL（覆盖 DB 中存储的值）")
    parser.add_argument("--role", default="primary", choices=["primary", "secondary"], help="检查/续期的账号角色")
    args = parser.parse_args()

    ok = ensure_session(args.target, args.login_url, role=args.role)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
