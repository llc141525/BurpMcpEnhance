"""SQLite DB 安全备份，支持 WAL 模式。

用法:
  python3 TOOLS/db_backup.py --all                           # 备份所有目标 DB
  python3 TOOLS/db_backup.py --target "货讯通科技"            # 备份指定目标
  python3 TOOLS/db_backup.py --all --keep 3                   # 每 DB 保留最近 3 份
  python3 TOOLS/db_backup.py --list                           # 列出已有备份
  python3 TOOLS/db_backup.py --list --target "货讯通科技"     # 列出指定目标的备份
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # db/ → TOOLS/ → SRC/
DBS_DIR = PROJECT_ROOT / "dbs"
DEFAULT_BACKUP_DIR = DBS_DIR / ".backups"


def find_all_dbs() -> list[Path]:
    return sorted(DBS_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)


def find_target_db(target: str) -> Path | None:
    matches = sorted(
        DBS_DIR.glob(f"{target}_*.db"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return matches[0] if matches else None


def sqlite3_backup(src: Path, dst: Path) -> bool:
    """使用 sqlite3 .backup 命令安全备份 WAL 模式 DB。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["sqlite3", str(src), f".backup '{dst}'"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return _copy_backup(src, dst)


def _copy_backup(src: Path, dst: Path) -> bool:
    """降级方案: 文件拷贝（WAL 模式下可能不一致）。"""
    try:
        shutil.copy2(src, dst)

        for suffix in ("-wal", "-shm"):
            wal = Path(str(src) + suffix)
            if wal.exists():
                shutil.copy2(wal, Path(str(dst) + suffix))

        return True
    except OSError:
        return False


def list_backups(backup_dir: Path, target: str | None = None) -> list[dict]:
    if not backup_dir.exists():
        return []

    backups = []
    for f in sorted(backup_dir.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        name = f.stem
        if target and not name.startswith(target):
            continue
        stat = f.stat()
        backups.append(
            {
                "file": str(f.relative_to(PROJECT_ROOT)),
                "size_kb": round(stat.st_size / 1024, 1),
                "time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    return backups


def rotate_backups(backup_dir: Path, target: str, keep: int) -> int:
    """保留最近 keep 份，删除旧的。返回删除数量。"""
    existing = sorted(backup_dir.glob(f"{target}_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for f in existing[keep:]:
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def backup_one(db_path: Path, backup_dir: Path, keep: int) -> dict:
    target_name = db_path.stem.rsplit("_", 1)[0]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = backup_dir / f"{target_name}_{ts}.db"

    ok = sqlite3_backup(db_path, dst)
    if not ok:
        return {"db": str(db_path.name), "status": "failed", "reason": "备份写入失败"}

    stat = dst.stat()
    removed = rotate_backups(backup_dir, target_name, keep)

    return {
        "db": str(db_path.name),
        "status": "ok",
        "backup": str(dst.relative_to(PROJECT_ROOT)),
        "size_kb": round(stat.st_size / 1024, 1),
        "rotated": removed,
    }


def main():
    parser = argparse.ArgumentParser(description="SQLite DB 备份")
    parser.add_argument("--target", help="目标名称（不指定则 --all）")
    parser.add_argument("--all", action="store_true", help="备份所有目标 DB")
    parser.add_argument("--list", action="store_true", help="列出已有备份")
    parser.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR), help="备份目录")
    parser.add_argument("--keep", type=int, default=5, help="每 DB 保留最近 N 份备份 (默认 5)")
    args = parser.parse_args()

    backup_dir = Path(args.backup_dir)
    if not backup_dir.is_absolute():
        backup_dir = PROJECT_ROOT / backup_dir

    if args.list:
        backups = list_backups(backup_dir, args.target)
        if not backups:
            print(json.dumps({"msg": "无备份记录"}, ensure_ascii=False))
        else:
            print(json.dumps({"backups": backups}, ensure_ascii=False, indent=2))
        return

    if args.target:
        db_path = find_target_db(args.target)
        if db_path is None:
            print(json.dumps({"error": f"未找到目标 DB: {args.target}"}, ensure_ascii=False))
            sys.exit(1)
        dbs = [db_path]
    elif args.all:
        dbs = find_all_dbs()
        if not dbs:
            print(json.dumps({"msg": "dbs/ 目录无 DB 文件"}, ensure_ascii=False))
            return
    else:
        parser.print_help()
        sys.exit(1)

    results = []
    for db_path in dbs:
        result = backup_one(db_path, backup_dir, args.keep)
        results.append(result)
        status = "OK" if result["status"] == "ok" else "FAIL"
        print(f"[{status}] {result['db']} → {result.get('backup', result.get('reason', ''))}", file=sys.stderr)

    ok_count = sum(1 for r in results if r["status"] == "ok")
    summary = {
        "backed_up": ok_count,
        "failed": len(results) - ok_count,
        "backup_dir": str(backup_dir),
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
