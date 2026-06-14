"""三层重放响应比对：判定 confirmed / low_confidence / false_positive。

用法:
  python TOOLS/utils/compare.py --test-type idor \\
    --a-status 200 --a-body '{"user":"alice"}' \\
    --b-status 200 --b-body '{"user":"alice"}'

  python TOOLS/utils/compare.py --test-type unauth \\
    --a-status 200 --a-body '...' \\
    --unauth-status 200 --unauth-body '...'

输出 JSON: {"verdict": "confirmed|low_confidence|false_positive", "evidence": "..."}
"""

import argparse
import json
import re

try:
    from utils.signal_filter import classify_endpoint, has_sensitive_response_signal, response_sensitive_markers
except ModuleNotFoundError:  # direct script execution from TOOLS/utils
    from signal_filter import classify_endpoint, has_sensitive_response_signal, response_sensitive_markers

_LOGIN_RE = re.compile(r"login|登录|未登录|401|unauthorized", re.I)
_SUCCESS_RE = re.compile(r"success|\"code\":0|\"code\":200|\"ok\":true|\"status\":1", re.I)
_EXPIRED_RE = re.compile(r"expired|used|invalid|失效|已使用|验证码错误", re.I)
_FAIL_RE = re.compile(r"不存在|invalid|not.found|error|fail", re.I)

_PHONE_RE = re.compile(r"1[3-9]\d{9}")
_IDCARD_RE = re.compile(r"\d{17}[\dXx]")
_EMAIL_RE = re.compile(r"[\w.\-]+@[\w.\-]+\.\w{2,}")

LOGIC_PARAMS = {
    "status",
    "role",
    "type",
    "level",
    "is_admin",
    "admin",
    "group",
    "permission",
    "state",
    "enabled",
    "verified",
}


def _sim(a: str, b: str) -> float:
    from difflib import SequenceMatcher  # noqa: PLC0415

    return SequenceMatcher(None, a, b).ratio()


def compare_idor(a_body: str, b_body: str, a_status: int, b_status: int) -> tuple[str, str]:
    if a_status == 200 and b_status == 200:
        s = _sim(a_body, b_body)
        evidence = f"A {len(a_body)}B vs B {len(b_body)}B, sim={s:.2f}"
        if s > 0.85:
            return "confirmed", evidence
        if s > 0.5:
            return "low_confidence", evidence
    return "false_positive", f"a_status={a_status} b_status={b_status}"


def compare_unauth(
    a_body: str,
    unauth_body: str,
    a_status: int,
    unauth_status: int,
    url: str = "",
    auth_mode: str = "",
) -> tuple[str, str]:
    if a_status == 200 and unauth_status == 200 and len(unauth_body) > 100:
        if _LOGIN_RE.search(unauth_body):
            return "false_positive", "unauth response contains login keywords"
        s = _sim(a_body, unauth_body)
        signal = classify_endpoint(url) if url else None
        markers = response_sensitive_markers(unauth_body)
        marker_text = " ".join(f"{k}={v}" for k, v in markers.items())
        evidence = f"unauth 200 sim={s:.2f} auth_mode={auth_mode or 'unknown'} {marker_text}".strip()
        if signal and signal.value in ("low_value", "ignore"):
            return "false_positive", f"{evidence} endpoint_value={signal.value}"
        if auth_mode and "bearer" not in auth_mode:
            if s > 0.85 and has_sensitive_response_signal(unauth_body):
                return "low_confidence", f"{evidence} no_bearer"
            return "false_positive", f"{evidence} no_bearer"
        if s > 0.85 and has_sensitive_response_signal(unauth_body):
            return "confirmed", evidence
        if has_sensitive_response_signal(unauth_body):
            return "low_confidence", evidence
        if s > 0.85:
            return "low_confidence", f"{evidence} no_sensitive_signal"
        return "false_positive", evidence
    return "false_positive", f"unauth_status={unauth_status}"


def compare_info_leak(a_body: str, a_status: int) -> tuple[str, str]:
    if a_status != 200:
        return "false_positive", f"status={a_status}"
    phones = _PHONE_RE.findall(a_body)
    idcards = _IDCARD_RE.findall(a_body)
    emails = _EMAIL_RE.findall(a_body)
    total = len(phones) + len(idcards) + len(emails)
    evidence = f"phones={len(phones)} idcards={len(idcards)} emails={len(emails)}"
    if total > 3:
        return "confirmed", evidence
    if total > 0:
        return "low_confidence", evidence
    return "false_positive", "no sensitive data"


def compare_param_logic(a_body: str, a_status: int, target_param: str) -> tuple[str, str]:
    if a_status == 200 and _SUCCESS_RE.search(a_body):
        return "confirmed", f"param={target_param} logic substitution succeeded"
    if a_status == 200:
        return "low_confidence", "status=200 but no success keyword"
    return "false_positive", f"status={a_status}"


def compare_user_enum(a_body: str, b_body: str, a_status: int, b_status: int) -> tuple[str, str]:
    if a_status != b_status:
        return "confirmed", f"status diff: {a_status} vs {b_status}"
    ratio = abs(len(a_body) - len(b_body)) / max(len(a_body), 1)
    if ratio > 0.2:
        return "confirmed", f"length diff ratio={ratio:.2f} ({len(a_body)} vs {len(b_body)})"
    return "low_confidence", "subtle response difference"


def compare_captcha_reuse(a_body: str, b_body: str, a_status: int, b_status: int) -> tuple[str, str]:
    if a_status == 200 and b_status == 200:
        if _SUCCESS_RE.search(b_body):
            return "confirmed", "captcha accepted on second use"
        if not _EXPIRED_RE.search(b_body):
            return "low_confidence", "second use 200, no expiry/used message"
    return "false_positive", f"second_use_status={b_status}"


def compare_password_reset(a_body: str, a_status: int) -> tuple[str, str]:
    if a_status == 200:
        if not _FAIL_RE.search(a_body):
            return "confirmed", "reset with replaced target field succeeded"
        return "low_confidence", "200 but ambiguous response"
    return "false_positive", f"status={a_status}"


def compare_vertical_priv_esc(
    a_status: int,
    a_body: str,
    b_status: int,
    b_body: str,
) -> tuple[str, str]:
    """a=primary（普通用户），b=teacher/admin（高权限，b_status=0 表示无会话）。

    Returns (verdict, evidence):
      "confirmed"             — 垂直越权确认
      "false_positive"        — 权限合理或接口公开
      "needs_teacher_account" — primary 返回 403 但无高权限 session 可验证；
                                调用方应写入 suspicious_points 并提示操作员提供账号。
    """
    if a_status == 500:
        return "confirmed", f"a_status=500 missing require_login; response={a_body[:120]}"
    if a_status == 200:
        return "false_positive", "primary can access, likely public endpoint"
    if a_status in (403, 401):
        if b_status == 0:
            return "needs_teacher_account", "primary returns 403 but no teacher/admin session to verify"
        if b_status == 200:
            return "confirmed", f"primary={a_status} teacher=200 body={b_body[:200]}"
        return "false_positive", f"both primary={a_status} and teacher={b_status}"
    return "false_positive", f"a_status={a_status}"


def compare_batch_idor(
    a_status: int,
    a_body: str,
    b_status: int,
    b_body: str,
    unauth_status: int,
    unauth_body: str,
) -> tuple[str, str]:
    """a=variant①(A+[A_id]基线), b=variant②(B+[A_id]), unauth=variant③(A+[A_id,B_id])。"""
    if a_status != 200:
        return "false_positive", f"baseline variant① a_status={a_status}, not a batch endpoint"
    # >20 bytes filters out empty/error stubs; >50 would exclude compact API responses (~35 bytes).
    if b_status == 200 and len(b_body) > 20:
        s = _sim(a_body, b_body)
        if s > 0.7:
            return "confirmed", f"variant② B+[A_id] succeeded sim={s:.2f}, cross-account operation"
    # >20 bytes filters out empty/error stubs; >50 would exclude compact API responses (~35 bytes).
    if unauth_status == 200 and len(unauth_body) > 20:
        s3 = _sim(a_body, unauth_body)
        if s3 > 0.7:
            return "confirmed", f"variant③ A+[A_id,B_id] succeeded sim={s3:.2f}, batch IDOR"
    if b_status == 200 or unauth_status == 200:
        return (
            "low_confidence",
            f"variant② b_status={b_status} variant③ unauth_status={unauth_status} but body too short",
        )
    return "false_positive", f"variant② b_status={b_status} variant③ unauth_status={unauth_status}"


_HANDLERS = {
    "idor": lambda a: compare_idor(a.a_body, a.b_body, a.a_status, a.b_status),
    "unauth": lambda a: compare_unauth(a.a_body, a.unauth_body, a.a_status, a.unauth_status, a.url, a.auth_mode),
    "info_leak": lambda a: compare_info_leak(a.a_body, a.a_status),
    "param_logic": lambda a: compare_param_logic(a.a_body, a.a_status, a.target_param),
    "user_enum": lambda a: compare_user_enum(a.a_body, a.b_body, a.a_status, a.b_status),
    "captcha_reuse": lambda a: compare_captcha_reuse(a.a_body, a.b_body, a.a_status, a.b_status),
    "password_reset_takeover": lambda a: compare_password_reset(a.a_body, a.a_status),
    "vertical_priv_esc": lambda a: compare_vertical_priv_esc(a.a_status, a.a_body, a.b_status, a.b_body),
    "batch_idor": lambda a: compare_batch_idor(
        a.a_status, a.a_body, a.b_status, a.b_body, a.unauth_status, a.unauth_body
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser(description="三层重放响应比对")
    parser.add_argument("--test-type", required=True, choices=list(_HANDLERS))
    parser.add_argument("--a-status", type=int, default=200)
    parser.add_argument("--a-body", default="")
    parser.add_argument("--b-status", type=int, default=0)
    parser.add_argument("--b-body", default="")
    parser.add_argument("--unauth-status", type=int, default=0)
    parser.add_argument("--unauth-body", default="")
    parser.add_argument("--target-param", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--auth-mode", default="")
    args = parser.parse_args()

    verdict, evidence = _HANDLERS[args.test_type](args)
    print(json.dumps({"verdict": verdict, "evidence": evidence}, ensure_ascii=False))


if __name__ == "__main__":
    main()
