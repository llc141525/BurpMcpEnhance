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

POLL_INTERVAL = 3  # seconds
POLL_TIMEOUT = 180  # seconds (3 minutes)


def _run_lark(args: list[str]) -> str:
    result = subprocess.run(  # noqa: S603
        ["lark"] + args, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _lark_send_text(chat_id: str, text: str) -> None:
    # ⚠️ 验证命令语法，参照 lark-cli README
    _run_lark(
        [
            "im",
            "message",
            "create",
            "--receive-id-type",
            "chat_id",
            "--receive-id",
            chat_id,
            "--msg-type",
            "text",
            "--content",
            json.dumps({"text": text}),
        ]
    )


def _lark_send_image(chat_id: str, image_path: str, text: str) -> None:
    # Step 1: 上传图片获取 image_key
    # ⚠️ 验证命令语法，参照 lark-cli README
    upload_out = _run_lark(
        [
            "im",
            "image",
            "create",
            "--image-type",
            "message",
            "--image",
            image_path,
        ]
    )
    image_key = json.loads(upload_out).get("image_key", "")

    # Step 2: 发送图片消息
    _run_lark(
        [
            "im",
            "message",
            "create",
            "--receive-id-type",
            "chat_id",
            "--receive-id",
            chat_id,
            "--msg-type",
            "image",
            "--content",
            json.dumps({"image_key": image_key}),
        ]
    )

    # Step 3: 发送说明文字
    if text:
        _lark_send_text(chat_id, text)


def _lark_get_messages(chat_id: str) -> list[dict]:
    # ⚠️ 验证命令语法，参照 lark-cli README
    out = _run_lark(
        [
            "im",
            "message",
            "list",
            "--container-id-type",
            "chat",
            "--container-id",
            chat_id,
            "--sort-type",
            "ByCreateTimeDesc",
            "--page-size",
            "10",
        ]
    )
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
