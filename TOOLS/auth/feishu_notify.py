"""飞书通知 + 回复轮询：lark-cli 封装。

发送: bot 身份（手机会收到推送）
轮询回复: user 身份（有权限读群消息）

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
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

POLL_INTERVAL = 3  # seconds
POLL_TIMEOUT = 180  # seconds (3 minutes)

# Windows npm 安装的 CLI 是 .cmd 文件
_LARK_BIN = "lark-cli.cmd" if sys.platform == "win32" else "lark-cli"


def _run_lark(args: list[str], cwd: str | None = None) -> dict:
    """调用 lark-cli，返回解析后的 JSON dict。失败返回 {}。"""
    result = subprocess.run(  # noqa: S603
        [_LARK_BIN] + args,
        capture_output=True,
        encoding="utf-8",
        cwd=cwd,
    )
    raw = result.stdout.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def _lark_send_text(chat_id: str, text: str) -> None:
    """用 bot 身份发文字消息（手机有推送）。"""
    _run_lark(["im", "+messages-send", "--chat-id", chat_id, "--text", text, "--as", "bot"])


def _lark_send_image(chat_id: str, image_path: str, text: str) -> None:
    """用 bot 身份发图片，再发文字说明。"""
    image_abs = Path(image_path).resolve()
    _run_lark(
        ["im", "+messages-send", "--chat-id", chat_id, "--image", image_abs.name, "--as", "bot"],
        cwd=str(image_abs.parent),
    )
    if text:
        _lark_send_text(chat_id, text)


def _lark_get_messages(chat_id: str) -> list[dict]:
    """用 user 身份拉群消息列表（bot 无读权限）。"""
    data = _run_lark(["im", "+chat-messages-list", "--chat-id", chat_id])
    return data.get("data", {}).get("messages", [])


def _poll_for_reply(chat_id: str, timeout: int = POLL_TIMEOUT) -> str | None:
    """轮询直到出现新消息，返回消息文本。超时返回 None。"""
    baseline_ids = {m.get("message_id") for m in _lark_get_messages(chat_id)}

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        for m in _lark_get_messages(chat_id):
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
