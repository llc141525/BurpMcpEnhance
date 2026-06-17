"""Shared signal/noise filters for SRC endpoint triage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

EndpointValue = Literal["high_value", "medium_value", "low_value", "ignore"]
AuthSurfaceType = Literal[
    "auth_required",
    "public_api",
    "noise_counter",
    "unauth_candidate",
    "idor_candidate",
    "info_leak_candidate",
]

NOISE_QUERY_PARAMS = {
    "_",
    "t",
    "ts",
    "timestamp",
    "time",
    "cache",
    "random",
    "random_number",
    "r",
    "page",
    "pageno",
    "pagenum",
    "pageindex",
    "pagesize",
    "limit",
    "offset",
}

BUSINESS_QUERY_PARAMS = {
    "id",
    "uid",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "orgid",
    "org_id",
    "roleid",
    "role_id",
    "fileid",
    "file_id",
    "studentid",
    "student_id",
    "code",
    "key",
    "token",
    "type",
    "status",
}

HIGH_VALUE_PATTERNS = (
    "me",
    "profile",
    "personal",
    "user",
    "student",
    "message",
    "schedule",
    "task",
    "role",
    "permission",
    "portrait",
    "file",
    "download",
)

MEDIUM_VALUE_PATTERNS = (
    "service",
    "calendar",
    "organization",
    "org",
    "notice",
    "workflow",
)

LOW_VALUE_PATTERNS = (
    "cms",
    "content",
    "column",
    "theme",
    "menu",
    "dict",
    "dictionary",
    "config",
    "conf",
    "recommend",
    "banner",
    "news",
    "stat",
    "track",
    "log",
)

AUTH_REQUIRED_MARKERS = (
    "unauthorized",
    "access denied",
    "forbidden",
    "login",
    "没有访问权限",
    "无权限",
    "未登录",
    "token信息不存在",
    "invalid request",
)

PUBLIC_PATH_PATTERNS = (
    "/cms/",
    "/theme/",
    "/column/",
    "/config/system",
    "/public/",
    "/assets/",
    "/i18n/",
    "/domain.json",
    "/login",
)

NOISE_PATH_PATTERNS = (
    "/calendar/getcurrentweekmap.jsp",
    "/click/addclicktimes.jsp",
    "/pagecounterdwr.",
    "/dwr/call/",
)

IGNORE_EXT_RE = re.compile(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|map)(\?.*)?$", re.I)
ID_VALUE_RE = re.compile(r"^\d{2,}$")
PHONE_RE = re.compile(r"1[3-9]\d{9}")
IDCARD_RE = re.compile(r"\d{17}[\dXx]")
EMAIL_RE = re.compile(r"[\w.\-]+@[\w.\-]+\.\w{2,}")
USER_FIELD_RE = re.compile(
    r"user(Name|Id|No)|account(Name|Id)|student(Id|No|Name)|姓名|学号|工号|手机号|phone|mobile|email|mail|portrait|avatar|role|permission",
    re.I,
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
TOKEN_FIELD_RE = re.compile(r"token|jwt|authorization|accessToken|idToken|secret|appSecret|api[_-]?key", re.I)


@dataclass(frozen=True)
class EndpointSignal:
    value: EndpointValue
    reason: str
    canonical_url: str
    business_params: tuple[str, ...]

    @property
    def is_candidate(self) -> bool:
        return self.value in ("high_value", "medium_value")


def canonicalize_url(url: str) -> str:
    parsed = urlparse(url)
    kept = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in NOISE_QUERY_PARAMS:
            continue
        kept.append((key, value))
    kept.sort(key=lambda item: (item[0].lower(), item[1]))
    query = urlencode(kept, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", query, ""))


def canonical_query_string(url: str) -> str:
    return urlparse(canonicalize_url(url)).query


def endpoint_fingerprint(
    url: str,
    method: str = "GET",
    params: list[str] | tuple[str, ...] | None = None,
) -> str:
    parsed = urlparse(canonicalize_url(url))
    names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    for param in params or []:
        key = (param or "").lower()
        if key and key not in NOISE_QUERY_PARAMS:
            names.add(key)
    return "|".join(
        [
            method.upper(),
            parsed.netloc.lower(),
            parsed.path or "/",
            ",".join(sorted(names)),
        ]
    )


def business_params_from_url(url: str, params: list[str] | tuple[str, ...] | None = None) -> tuple[str, ...]:
    names = {name.lower() for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
    names.update((p or "").lower() for p in (params or []))
    return tuple(sorted(name for name in names if name in BUSINESS_QUERY_PARAMS))


def classify_endpoint(url: str, method: str = "GET", params: list[str] | tuple[str, ...] | None = None) -> EndpointSignal:
    canonical = canonicalize_url(url)
    parsed = urlparse(canonical)
    path_text = parsed.path.lower()
    full_text = f"{path_text}?{parsed.query.lower()}"
    business_params = business_params_from_url(url, params)

    if IGNORE_EXT_RE.search(url):
        return EndpointSignal("ignore", "static_resource", canonical, business_params)
    if any(_matches_high_value_pattern(path_text, pattern) for pattern in HIGH_VALUE_PATTERNS) or business_params:
        return EndpointSignal("high_value", "business_identity_signal", canonical, business_params)
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return EndpointSignal("medium_value", "state_changing_method", canonical, business_params)
    if any(pattern in full_text for pattern in MEDIUM_VALUE_PATTERNS):
        return EndpointSignal("medium_value", "medium_business_signal", canonical, business_params)
    if any(pattern in full_text for pattern in LOW_VALUE_PATTERNS):
        return EndpointSignal("low_value", "public_or_configuration_signal", canonical, business_params)
    return EndpointSignal("low_value", "no_business_signal", canonical, business_params)


def summarize_response(status: int | None, content_type: str = "", body_text: str = "") -> dict:
    body = body_text or ""
    summary = {
        "status": int(status or 0),
        "content_type": content_type.split(";")[0].strip().lower(),
        "body_len": len(body),
        "json_keys": [],
        "data_shape": "unknown",
        "auth_required_hint": False,
        "sensitive_markers": response_sensitive_markers(body),
    }
    lowered = body.lower()
    summary["auth_required_hint"] = (summary["status"] in (401, 403)) or any(
        marker.lower() in lowered for marker in AUTH_REQUIRED_MARKERS
    )
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            summary["json_keys"] = sorted(str(key) for key in parsed.keys())[:20]
            data = parsed.get("data")
            if data == []:
                summary["data_shape"] = "array_empty"
            elif data == {}:
                summary["data_shape"] = "object_empty"
            elif data is None:
                summary["data_shape"] = "null"
            elif isinstance(data, list):
                summary["data_shape"] = "array"
            elif isinstance(data, dict):
                summary["data_shape"] = "object"
            else:
                summary["data_shape"] = type(data).__name__
        elif isinstance(parsed, list):
            summary["data_shape"] = "array_empty" if not parsed else "array"
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return summary


def classify_auth_surface(
    url: str,
    method: str = "GET",
    params: list[str] | tuple[str, ...] | None = None,
    response_summary: dict | None = None,
    has_body: bool = False,
) -> tuple[AuthSurfaceType, int, str]:
    signal = classify_endpoint(url, method, params)
    parsed = urlparse(signal.canonical_url)
    path = (parsed.path or "/").lower()
    query = parsed.query.lower()
    text = f"{path}?{query}"
    response_summary = response_summary or {}
    sensitive_total = sum((response_summary.get("sensitive_markers") or {}).values())
    risk_score = 0

    if response_summary.get("auth_required_hint"):
        return "auth_required", 0, "auth_required_response"
    if any(pattern in text for pattern in NOISE_PATH_PATTERNS) or IGNORE_EXT_RE.search(url):
        return "noise_counter", 0, "noise_or_static_path"
    if any(pattern in text for pattern in PUBLIC_PATH_PATTERNS):
        if sensitive_total:
            return "info_leak_candidate", 55, "public_path_with_sensitive_marker"
        return "public_api", 0, "public_or_login_path"
    if sensitive_total or TOKEN_FIELD_RE.search(text) or JWT_RE.search(url):
        return "info_leak_candidate", 70, "sensitive_marker"
    if signal.business_params or any(pattern in text for pattern in ("user", "role", "message", "record", "file", "path")):
        return "idor_candidate", 60, "identity_or_object_signal"
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        if not has_body:
            return "auth_required", 0, "state_changing_without_body"
        return "unauth_candidate", 45, "state_changing_method"
    if signal.value == "high_value":
        return "unauth_candidate", 45, signal.reason
    if signal.value == "medium_value":
        risk_score = 30
        return "auth_required", risk_score, "medium_signal_below_review_threshold"
    return "public_api", 0, signal.reason


def _matches_high_value_pattern(path_text: str, pattern: str) -> bool:
    if pattern == "me":
        return "me" in [part for part in re.split(r"[^a-z0-9]+", path_text) if part]
    return pattern in path_text


def classify_mmx_fallback(req: dict) -> dict | None:
    signal = classify_endpoint(req.get("url", ""), req.get("method", "GET"), req.get("params", []))
    if not signal.is_candidate:
        return None
    endpoint_type = "business_api"
    return {
        **req,
        "url": signal.canonical_url,
        "endpoint_type": endpoint_type,
        "business_intent": f"本地启发式识别: {signal.reason}",
        "risk_hint": "High" if signal.value == "high_value" else "Medium",
    }


def response_sensitive_markers(body: str) -> dict[str, int]:
    text = body or ""
    field_hits = len(USER_FIELD_RE.findall(text))
    try:
        parsed = json.loads(text)
        field_hits += _count_sensitive_json_fields(parsed)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return {
        "phones": len(PHONE_RE.findall(text)),
        "idcards": len(IDCARD_RE.findall(text)),
        "emails": len(EMAIL_RE.findall(text)),
        "jwts": len(JWT_RE.findall(text)),
        "fields": field_hits,
        "token_fields": len(TOKEN_FIELD_RE.findall(text)),
    }


def has_sensitive_response_signal(body: str) -> bool:
    markers = response_sensitive_markers(body)
    return sum(markers.values()) > 0


def _count_sensitive_json_fields(value) -> int:
    if isinstance(value, dict):
        count = sum(1 for key in value if USER_FIELD_RE.search(str(key)))
        return count + sum(_count_sensitive_json_fields(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_sensitive_json_fields(item) for item in value[:50])
    if isinstance(value, str):
        return 1 if USER_FIELD_RE.search(value) else 0
    return 0
