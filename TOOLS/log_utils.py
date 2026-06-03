"""结构化活动日志 helper。所有 TOOLS 脚本 opt-in 导入，追加 .session-log.jsonl。

用法:
  from log_utils import log_event, log_start, log_error, log_done
  log_start("brutescan", "货讯通科技", url="https://t.com", limit=200)
  log_error("scrapling_fetch", "台州学院", error="connection refused", url="https://...")
  log_done("brutescan", "货讯通科技", elapsed=45.2, found=12)
  log_event("waf_rotate", "货讯通科技", "waf_blocked", url="https://...", detail="403 → HK-01")
"""

import json
import os
import threading
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".session-log.jsonl")
_lock = threading.Lock()


def _write(entry: dict) -> None:
    entry["ts"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass


def log_event(tool: str, target: str, event: str, **kwargs) -> None:
    entry = {"tool": tool, "target": target, "event": event}
    entry.update(kwargs)
    _write(entry)


def log_start(tool: str, target: str, **kwargs) -> None:
    log_event(tool, target, "start", **kwargs)


def log_error(tool: str, target: str, error: str, **kwargs) -> None:
    log_event(tool, target, "error", error=error, **kwargs)


def log_done(tool: str, target: str, elapsed: float, **kwargs) -> None:
    log_event(tool, target, "done", elapsed=elapsed, **kwargs)
