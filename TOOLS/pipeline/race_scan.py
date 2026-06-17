"""竞态条件（Race Condition）扫描器。

从 hunt_queue 中识别竞态风险端点（支付/优惠券/积分/注册等），
用 HTTP/2 多路复用或 gate 同步发送并发请求，检测并记录竞态漏洞。

用法:
  uv run python TOOLS/pipeline/race_scan.py --target "目标名"

写入:
  - findings (type='race_condition', risk='High') — 确认漏洞
  - suspicious_points (test_type='race_condition', risk='Medium') — 低置信度
"""

import argparse
import asyncio
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db.cookie_helper import get_auth_cookie_header  # noqa: E402
from db.db_utils import connect, find_db  # noqa: E402

PROXY = "http://127.0.0.1:8080"
RACE_N = 15
REQUEST_DELAY = 1.5

RACE_KEYWORDS = frozenset(
    {
        "coupon",
        "redeem",
        "use",
        "apply",
        "voucher",
        "discount",
        "order",
        "pay",
        "deduct",
        "consume",
        "transfer",
        "withdraw",
        "register",
        "signup",
        "verify",
        "otp",
        "stock",
        "inventory",
        "limit",
        "quota",
        "balance",
        "point",
        "ticket",
        "charge",
        "refund",
        "exchange",
        "prize",
        "reward",
        "gift",
    }
)

SUCCESS_SIGNALS = frozenset(
    {
        '"code":0',
        '"code": 0',
        '"status":"ok"',
        '"status": "ok"',
        '"result":true',
        '"result": true',
        '"success":true',
        '"success": true',
        '"msg":"success"',
        '"msg": "success"',
        '"message":"ok"',
    }
)

ERROR_SIGNALS = frozenset(
    {
        '"error"',
        '"fail"',
        '"failed"',
        '"invalid"',
        '"expired"',
        '"already',
        '"duplicate"',
        "already used",
        '"consumed"',
    }
)


def _url_kw_cond(kw: str) -> str:
    """生成 URL 路径段精确匹配条件（防止 /use 误匹配 /user）。"""
    # 匹配：/kw/ 或 /kw? 或 /kw 结尾
    return f"(LOWER(url) LIKE '%/{kw}/%' OR LOWER(url) LIKE '%/{kw}?%' OR LOWER(url) LIKE '%/{kw}')"


def find_race_candidates(conn: sqlite3.Connection) -> list[dict]:
    """从 hunt_queue 找竞态风险端点。"""
    # business_intent: simple LIKE match (free-text field)
    # url: path-segment match to avoid e.g. "use" matching "user"
    intent_conds = " OR ".join(f"LOWER(business_intent) LIKE '%{kw}%'" for kw in sorted(RACE_KEYWORDS))
    url_conds = " OR ".join(_url_kw_cond(kw) for kw in sorted(RACE_KEYWORDS))
    # Keywords are hardcoded constants, not user input — S608 false positive
    where_clause = f"({intent_conds} OR {url_conds})"
    sql = (
        "SELECT method, url, query_string, body, content_type,"  # noqa: S608
        " business_intent, notes, target_id FROM hunt_queue"
        f" WHERE status = 'queued' AND {where_clause} LIMIT 10"
    )
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def is_race_detected(responses: list) -> tuple[bool, str]:
    """分析并发响应，判断是否存在竞态条件。"""
    successes = 0
    total = len(responses)
    for r in responses:
        if isinstance(r, Exception):
            continue
        if r.status_code not in (200, 201, 204):
            continue
        body_sample = r.text[:500]
        body_lower = body_sample.lower()
        has_success = any(sig.lower() in body_lower for sig in SUCCESS_SIGNALS)
        has_error = any(sig.lower() in body_lower for sig in ERROR_SIGNALS)
        if has_success and not has_error:
            successes += 1
        elif r.status_code in (200, 201) and not has_error and not has_success:
            successes += 1
    if successes >= 2:
        return True, f"{successes}/{total} 并发请求均返回成功响应（预期仅 1 次成功）"
    return False, f"仅 {successes}/{total} 请求成功，未检测到竞态"


async def http2_race(
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    n: int = RACE_N,
) -> list:
    """HTTP/2 多路复用并发 — 同一连接发送 N 个请求。"""
    proxies = {"http://": PROXY, "https://": PROXY}
    try:
        async with httpx.AsyncClient(http2=True, verify=False, proxies=proxies, timeout=15.0) as client:  # noqa: S501
            tasks = [client.request(method, url, headers=headers, content=body) for _ in range(n)]
            return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        return [exc] * n


async def gate_race(
    url: str,
    method: str,
    headers: dict,
    body: bytes | None,
    n: int = RACE_N,
) -> list:
    """Gate/last-byte sync — 所有连接同时释放。"""
    gate = asyncio.Event()
    proxies = {"http://": PROXY, "https://": PROXY}

    async def _one() -> httpx.Response:
        await gate.wait()
        async with httpx.AsyncClient(http2=False, verify=False, proxies=proxies, timeout=15.0) as client:  # noqa: S501
            return await client.request(method, url, headers=headers, content=body)

    tasks = [asyncio.create_task(_one()) for _ in range(n)]
    await asyncio.sleep(0.05)
    gate.set()
    return await asyncio.gather(*tasks, return_exceptions=True)


def write_race_finding(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    method: str,
    evidence: str,
    n_success: int,
) -> bool:
    """写入 findings 表，去重返回 False。"""
    existing = conn.execute("SELECT id FROM findings WHERE url=? AND type='race_condition'", (url,)).fetchone()
    if existing:
        return False
    finding_id = f"F-RACE-{uuid.uuid4().hex[:8]}"
    conn.execute(
        """INSERT INTO findings
           (id, target_id, type, url, method, payload, evidence, risk, cvss, remediation, confirmed_at)
           VALUES (?, ?, 'race_condition', ?, ?, ?, ?, 'High',
                   'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N',
                   '使用幂等令牌（idempotency key）或数据库唯一约束防止重复操作',
                   datetime('now','localtime'))""",
        (finding_id, target_id, url, method, f"race_n_success={n_success}", evidence),
    )
    conn.commit()
    return True


def write_race_sp(
    conn: sqlite3.Connection,
    target_id: int,
    url: str,
    method: str,
    evidence: str,
) -> bool:
    """写入 suspicious_points，去重返回 False。"""
    existing = conn.execute(
        "SELECT id FROM suspicious_points WHERE url=? AND param=? AND test_type=?",
        (url, method, "race_condition"),
    ).fetchone()
    if existing:
        return False
    sp_id = f"SP-RACE-{uuid.uuid4().hex[:8]}"
    conn.execute(
        """INSERT INTO suspicious_points
           (id, url, param, method, test_type, evidence, source, risk, test_status, created_at)
           VALUES (?, ?, ?, ?, 'race_condition', ?, 'race_scan', 'Medium', 'untested',
                   datetime('now','localtime'))""",
        (sp_id, url, method, method, evidence),
    )
    conn.commit()
    return True


def _build_headers(candidate: dict, cookie_header: str | None) -> dict:
    headers: dict[str, str] = {"User-Agent": "Mozilla/5.0"}
    if candidate.get("content_type"):
        headers["Content-Type"] = candidate["content_type"]
    if cookie_header:
        headers["Cookie"] = cookie_header
    return headers


def _build_body(candidate: dict) -> bytes | None:
    raw = candidate.get("body") or ""
    return raw.encode() if raw else None


def main() -> None:
    parser = argparse.ArgumentParser(description="竞态条件扫描器")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    db_path = find_db(args.target)
    conn = connect(db_path)

    seed_row = conn.execute("SELECT seed_url FROM scan_state WHERE id=1").fetchone()
    seed_domain = seed_row[0] if seed_row and seed_row[0] else ""
    cookie_header = get_auth_cookie_header(str(db_path), seed_domain, role="primary")

    target_row = conn.execute("SELECT id FROM targets WHERE target_name=?", (args.target,)).fetchone()
    target_id = target_row[0] if target_row else 1

    candidates = find_race_candidates(conn)
    print(f"[race_scan] 找到 {len(candidates)} 个竞态候选端点")

    found_findings = 0
    found_sp = 0

    for cand in candidates:
        url = cand["url"]
        method = cand["method"]
        headers = _build_headers(cand, cookie_header)
        body = _build_body(cand)

        print(f"  [*] 测试 {method} {url}")
        try:
            responses = asyncio.run(http2_race(url, method, headers, body))
            # 检查 HTTP/2 是否真正生效（若全部异常则降级）
            real_resps = [r for r in responses if not isinstance(r, Exception)]
            if len(real_resps) < RACE_N // 2:
                print("    [!] HTTP/2 失败率高，降级为 gate sync")
                responses = asyncio.run(gate_race(url, method, headers, body))
        except Exception as exc:
            print(f"    [!] 请求异常: {exc}")
            time.sleep(REQUEST_DELAY)
            continue

        detected, evidence = is_race_detected(responses)
        success_count = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code in (200, 201, 204))

        if detected:
            ok = write_race_finding(conn, target_id, url, method, evidence, success_count)
            if ok:
                found_findings += 1
                print(f"    [+] RACE CONFIRMED: {evidence}")
        elif success_count >= 1:
            ok = write_race_sp(conn, target_id, url, method, evidence)
            if ok:
                found_sp += 1
                print(f"    [?] SP: {evidence}")

        time.sleep(REQUEST_DELAY)

    conn.close()
    print(f"\n[RACE_SCAN] candidates={len(candidates)} findings={found_findings} sp={found_sp}")


if __name__ == "__main__":
    main()
