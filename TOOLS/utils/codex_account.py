#!/usr/bin/env python3
"""
Codex multi-account auth switcher.

Only auth.json is saved/switched. Codex history, sessions, memories, and
config stay in the shared ~/.codex directory.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path


ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_SHARED_HOME") or Path.home() / ".codex")


def auth_store() -> Path:
    return Path(os.environ.get("CODEX_AUTH_STORE") or Path.home() / ".codex-auths")


def auth_path() -> Path:
    return codex_home() / "auth.json"


def banner() -> str:
    return f"""
============================================================
 Codex 多账号额度轮换工具
============================================================

目标:
  多个账号轮流用额度，但共用同一份 Codex 上下文、历史、配置。

共享上下文目录:
  {codex_home()}

账号凭据保存目录:
  {auth_store()}

这个脚本只会保存/切换:
  {auth_path()}

不会动这些上下文文件:
  {codex_home() / "sessions"}
  {codex_home() / "session_index.jsonl"}
  {codex_home() / "config.toml"}
  {codex_home() / "memories_1.sqlite"}

常用命令:
  python TOOLS/utils/codex_account.py save llc141525
  python TOOLS/utils/codex_account.py use  llc141525
  python TOOLS/utils/codex_account.py list

第一次保存账号:
  1. 先在 Codex 里登录账号 A
  2. python TOOLS/utils/codex_account.py save acc-a
  3. 再在 Codex 里登录账号 B
  4. python TOOLS/utils/codex_account.py save acc-b

额度用完切换:
  python TOOLS/utils/codex_account.py use acc-b

注意:
  auth.json 等同登录令牌，不要发给别人，不要提交 Git。
  切换后如果 Codex app 还显示旧账号，请重启 Codex app 或新开会话。
============================================================
""".strip()


def validate_name(name: str) -> None:
    if not ACCOUNT_RE.match(name):
        raise SystemExit("账号名只能包含字母、数字、点、下划线和短横线。")


def ensure_file_auth_config() -> None:
    config_path = codex_home() / "config.toml"
    if not config_path.exists():
        codex_home().mkdir(parents=True, exist_ok=True)
        config_path.write_text('cli_auth_credentials_store = "file"\n', encoding="utf-8")
        return

    text = config_path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"(?m)^cli_auth_credentials_store\s*=", text):
        text = re.sub(
            r'(?m)^cli_auth_credentials_store\s*=.*$',
            'cli_auth_credentials_store = "file"',
            text,
            count=1,
        )
    else:
        text = 'cli_auth_credentials_store = "file"\n\n' + text

    config_path.write_text(text, encoding="utf-8")


def save_account(name: str) -> None:
    validate_name(name)
    ensure_file_auth_config()

    src = auth_path()
    if not src.exists():
        raise SystemExit(
            f"没有找到当前登录凭据: {src}\n"
            f"请先在 Codex 里登录这个账号，然后再运行: python TOOLS/utils/codex_account.py save {name}"
        )

    account_dir = auth_store() / name
    account_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, account_dir / "auth.json")

    meta = {
        "name": name,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "codex_home": str(codex_home()),
        "source": str(src),
    }
    (account_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print_success(
        f"账号已保存: {name}",
        [
            f"保存位置: {account_dir / 'auth.json'}",
            f"共享上下文仍然是: {codex_home()}",
        ],
    )


def use_account(name: str, no_backup: bool = False) -> None:
    validate_name(name)
    ensure_file_auth_config()

    src = auth_store() / name / "auth.json"
    dst = auth_path()
    if not src.exists():
        raise SystemExit(
            f"没有保存过账号: {name}\n"
            f"先登录这个账号，然后运行: python TOOLS/utils/codex_account.py save {name}"
        )

    codex_home().mkdir(parents=True, exist_ok=True)
    if dst.exists() and not no_backup:
        backup_dir = codex_home() / "auth-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(dst, backup_dir / f"auth.before-switch.{stamp}.json")

    shutil.copy2(src, dst)
    (codex_home() / "active_account").write_text(name + "\n", encoding="utf-8")

    print_success(
        f"已切换到账号: {name}",
        [
            f"当前 auth.json: {dst}",
            f"共享上下文目录: {codex_home()}",
            "如果 Codex app 还显示旧账号，请重启 Codex app 或新开会话。",
        ],
    )


def list_accounts() -> None:
    store = auth_store()
    print(banner())
    print()

    if not store.exists():
        print(f"还没有保存任何账号。账号保存目录将会是: {store}")
        return

    rows = []
    active = ""
    active_path = codex_home() / "active_account"
    if active_path.exists():
        active = active_path.read_text(encoding="utf-8", errors="replace").strip()

    for item in sorted(store.iterdir()):
        if not item.is_dir():
            continue
        meta_path = item / "meta.json"
        saved_at = ""
        if meta_path.exists():
            try:
                saved_at = json.loads(meta_path.read_text(encoding="utf-8")).get("saved_at", "")
            except json.JSONDecodeError:
                saved_at = ""
        mark = "*" if item.name == active else " "
        rows.append((mark, item.name, saved_at, str(item)))

    if not rows:
        print(f"还没有保存任何账号。账号保存目录: {store}")
        return

    print("已保存账号:")
    for mark, name, saved_at, path in rows:
        suffix = f"  saved_at={saved_at}" if saved_at else ""
        print(f"  {mark} {name}{suffix}")
        print(f"      {path}")

    print()
    print("* 表示上次通过本工具切换到的账号。")


def print_success(title: str, lines: list[str]) -> None:
    print()
    print("============================================================")
    print(f"成功: {title}")
    print("============================================================")
    for line in lines:
        print(f"- {line}")
    print("============================================================")
    print()


def normalize_legacy_args(argv: list[str]) -> list[str]:
    if not argv:
        return argv

    first = argv[0].lower()
    mapping = {
        "save-codexaccount": "save",
        "save_codexaccount": "save",
        "savecodexaccount": "save",
        "use-codexaccount": "use",
        "use_codexaccount": "use",
        "usecodexaccount": "use",
        "list-codexaccounts": "list",
        "list_codexaccounts": "list",
        "listcodexaccounts": "list",
    }
    if first in mapping:
        return [mapping[first], *argv[1:]]
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex_account.py",
        description="Save and switch Codex auth.json while keeping one shared Codex context.",
    )
    sub = parser.add_subparsers(dest="command")

    save = sub.add_parser("save", help="保存当前已登录账号")
    save.add_argument("name", help="账号别名，例如 llc141525")

    use = sub.add_parser("use", aliases=["switch"], help="切换到已保存账号")
    use.add_argument("name", help="账号别名")
    use.add_argument("--no-backup", action="store_true", help="切换前不备份当前 auth.json")

    sub.add_parser("list", aliases=["ls"], help="列出已保存账号")
    sub.add_parser("help", help="显示详细使用说明")

    return parser


def main(argv: list[str]) -> int:
    argv = normalize_legacy_args(argv)

    if not argv:
        print(banner())
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "save":
        save_account(args.name)
    elif args.command in {"use", "switch"}:
        use_account(args.name, no_backup=args.no_backup)
    elif args.command in {"list", "ls"}:
        list_accounts()
    elif args.command == "help":
        print(banner())
    else:
        print(banner())

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
