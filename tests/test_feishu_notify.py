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
    with patch("TOOLS.auth.feishu_notify._lark_get_messages", side_effect=[baseline, new_msg]):
        with patch("time.sleep"):
            with patch("time.time", side_effect=[0, 1, 2, 200]):
                from TOOLS.auth.feishu_notify import _poll_for_reply
                result = _poll_for_reply("chat_abc", timeout=180)
                assert result == "1a2b"


def test_poll_for_reply_returns_none_on_timeout():
    baseline = [{"message_id": "msg_001", "body": {"content": json.dumps({"text": "old"})}}]
    with patch("TOOLS.auth.feishu_notify._lark_get_messages", return_value=baseline):
        with patch("time.sleep"):
            with patch("time.time", side_effect=[0, 181, 182]):
                from TOOLS.auth.feishu_notify import _poll_for_reply
                result = _poll_for_reply("chat_abc", timeout=180)
                assert result is None


def test_send_text_wait_reply_calls_send_then_polls():
    with patch("TOOLS.auth.feishu_notify._lark_send_text") as mock_send:
        with patch("TOOLS.auth.feishu_notify._poll_for_reply", return_value="1234") as mock_poll:
            from TOOLS.auth.feishu_notify import send_text_wait_reply
            result = send_text_wait_reply("chat_abc", "请回复验证码", timeout=60)
            mock_send.assert_called_once_with("chat_abc", "请回复验证码")
            mock_poll.assert_called_once_with("chat_abc", 60)
            assert result == "1234"


def test_send_image_calls_lark_send_image():
    with patch("TOOLS.auth.feishu_notify._lark_send_image") as mock_send:
        from TOOLS.auth.feishu_notify import send_image
        send_image("chat_abc", "/tmp/qr.png", "请扫码登录")
        mock_send.assert_called_once_with("chat_abc", "/tmp/qr.png", "请扫码登录")
