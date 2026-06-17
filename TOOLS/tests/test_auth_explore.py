# TOOLS/tests/test_auth_explore.py
from auth.auth_explore import (
    CandidateQueue,
    extract_inline_route_literals,
    extract_response_candidates,
    filter_api_requests,
    is_unsafe_label,
    normalize_candidate_url,
    parse_request_params,
    write_explore_results_to_db,
    write_hunt_queue,
)
import sqlite3


class TestFilterApiRequests:
    def _make_req(self, url, resource_type="xhr"):
        return {"url": url, "resource_type": resource_type, "method": "GET"}

    def test_keeps_xhr_same_domain(self):
        reqs = [self._make_req("https://example.com/api/v1")]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_keeps_fetch_same_domain(self):
        reqs = [{"url": "https://example.com/api", "resource_type": "fetch", "method": "POST"}]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_excludes_stylesheet(self):
        reqs = [self._make_req("https://example.com/style.css", "stylesheet")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_excludes_image(self):
        reqs = [self._make_req("https://example.com/logo.png", "image")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_excludes_different_domain(self):
        reqs = [self._make_req("https://cdn.other.com/api")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_keeps_subdomain(self):
        reqs = [self._make_req("https://api.example.com/v1")]
        result = filter_api_requests(reqs, "example.com")
        assert len(result) == 1

    def test_keeps_peer_subdomain_for_portal_seed(self):
        reqs = [self._make_req("https://jwglxt.tzc.edu.cn/api/menu")]
        result = filter_api_requests(reqs, "portal.tzc.edu.cn")
        assert len(result) == 1

    def test_excludes_static_extension(self):
        reqs = [self._make_req("https://example.com/fonts/icon.woff2")]
        assert filter_api_requests(reqs, "example.com") == []

    def test_empty_list(self):
        assert filter_api_requests([], "example.com") == []


class TestParseRequestParams:
    def test_query_string_params(self):
        params = parse_request_params("https://example.com/api?id=1&type=user", None)
        assert set(params) == {"id", "type"}

    def test_json_post_body(self):
        params = parse_request_params("https://example.com/api", '{"userId": 1, "action": "read"}')
        assert set(params) == {"userId", "action"}

    def test_form_post_body(self):
        params = parse_request_params("https://example.com/api", "username=foo&password=bar")
        assert set(params) == {"username", "password"}

    def test_no_params(self):
        params = parse_request_params("https://example.com/api", None)
        assert params == []

    def test_combined_query_and_body(self):
        params = parse_request_params(
            "https://example.com/api?page=1",
            '{"filter": "active"}',
        )
        assert set(params) == {"page", "filter"}


class TestNavigationCandidateExtraction:
    def test_normalizes_hash_route_against_seed_url(self):
        url = normalize_candidate_url("#/Dashboard", "https://portal.example.edu/main.html#/IndexView")
        assert url == "https://portal.example.edu/main.html#/Dashboard"

    def test_rejects_unsafe_labels(self):
        assert is_unsafe_label("退出登录")
        assert is_unsafe_label("Delete user")
        assert not is_unsafe_label("成绩查询")

    def test_extracts_nested_response_routes(self):
        payload = {
            "menus": [
                {"name": "一卡通", "appUrl": "https://ecard.example.edu/home"},
                {"title": "成绩", "children": [{"route": "/grade/index"}]},
                {"label": "iframe app", "iframeUrl": "https://portal.example.edu/app/frame"},
            ]
        }
        candidates = extract_response_candidates(
            payload,
            seed_url="https://portal.example.edu/main.html#/IndexView",
            source_url="https://portal.example.edu/api/menu",
        )

        values = {c["value"] for c in candidates}
        labels = {c["label"] for c in candidates}
        assert "https://ecard.example.edu/home" in values
        assert "https://portal.example.edu/grade/index" in values
        assert "https://portal.example.edu/app/frame" in values
        assert {"一卡通", "成绩", "iframe app"} <= labels

    def test_excludes_external_response_routes(self):
        payload = {"menus": [{"name": "外部系统", "appUrl": "https://evil.example.net/home"}]}

        candidates = extract_response_candidates(
            payload,
            seed_url="https://portal.example.edu/main.html#/IndexView",
            source_url="https://portal.example.edu/api/menu",
        )

        assert candidates == []

    def test_extracts_inline_script_routes(self):
        script = """
        window.open('https://oa.example.edu/home');
        location.href = '/portal/news';
        router.push({ path: '/student/profile' });
        navigate('/library/search');
        """
        routes = extract_inline_route_literals(script)

        assert "https://oa.example.edu/home" in routes
        assert "/portal/news" in routes
        assert "/student/profile" in routes
        assert "/library/search" in routes


class TestCandidateQueue:
    def test_preserves_breadth_with_per_prefix_cap(self):
        queue = CandidateQueue(per_prefix_cap=2, per_host_cap=10)
        for idx in range(5):
            queue.add(
                {
                    "kind": "url",
                    "value": f"https://jwglxt.example.edu/jwglxt/page/{idx}",
                    "label": f"教务{idx}",
                    "source": "test",
                }
            )
        queue.add(
            {
                "kind": "url",
                "value": "https://ecard.example.edu/home",
                "label": "一卡通",
                "source": "test",
            }
        )

        values = [c["value"] for c in queue.items()]
        assert len([v for v in values if "jwglxt.example.edu/jwglxt" in v]) == 2
        assert "https://ecard.example.edu/home" in values


class TestExploreDbWrites:
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE suspicious_points (
                id TEXT PRIMARY KEY,
                url TEXT,
                param TEXT,
                method TEXT,
                test_type TEXT,
                evidence TEXT,
                source TEXT,
                reasoning TEXT,
                risk TEXT,
                test_status TEXT,
                created_at TEXT,
                endpoint_fingerprint TEXT,
                response_summary TEXT,
                risk_score INTEGER DEFAULT 0
            );
            CREATE UNIQUE INDEX idx_suspicious_points_auth_fingerprint
                ON suspicious_points(source, endpoint_fingerprint, test_type)
                WHERE endpoint_fingerprint IS NOT NULL;
            CREATE TABLE pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                depth INTEGER,
                status TEXT
            );
            CREATE TABLE hunt_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                query_string TEXT,
                body TEXT,
                content_type TEXT,
                endpoint_type TEXT,
                business_intent TEXT,
                risk_hint TEXT,
                source TEXT,
                status TEXT,
                created_at TEXT,
                UNIQUE(method, url, query_string)
            );
            """
        )
        return conn

    def test_low_value_xhr_does_not_write_suspicious_point(self):
        conn = self._conn()

        counts = write_explore_results_to_db(
            conn,
            [
                {
                    "url": "https://portal.example.edu/portal-api/v2/theme/themeInfo?random_number=1",
                    "method": "GET",
                    "params": ["random_number"],
                    "nav_context": "首页",
                },
                {
                    "url": "https://portal.example.edu/api/user/profile?random_number=1",
                    "method": "GET",
                    "params": ["random_number"],
                    "nav_context": "个人中心",
                    "response_summary": {
                        "status": 200,
                        "sensitive_markers": {"fields": 1, "phones": 0, "idcards": 0, "emails": 0, "jwts": 0, "token_fields": 0},
                    },
                },
            ],
            [],
        )

        rows = conn.execute("SELECT url, test_type, risk_score FROM suspicious_points").fetchall()
        conn.close()
        assert counts["sp"] == 1
        assert rows[0]["url"] == "https://portal.example.edu/api/user/profile"
        assert rows[0]["test_type"] == "info_leak_candidate"
        assert rows[0]["risk_score"] >= 60

    def test_dedupes_suspicious_points_by_endpoint_fingerprint(self):
        conn = self._conn()

        counts = write_explore_results_to_db(
            conn,
            [
                {
                    "url": "https://portal.example.edu/api/user/profile?random_number=1&uid=42&pageSize=10",
                    "method": "GET",
                    "params": ["random_number", "uid", "pageSize"],
                    "nav_context": "个人中心",
                },
                {
                    "url": "https://portal.example.edu/api/user/profile?random_number=2&uid=42&pageSize=20",
                    "method": "GET",
                    "params": ["random_number", "uid", "pageSize"],
                    "nav_context": "个人中心",
                },
            ],
            [],
        )

        rows = conn.execute("SELECT endpoint_fingerprint, test_type FROM suspicious_points").fetchall()
        conn.close()
        assert counts["sp"] == 1
        assert len(rows) == 1
        assert rows[0]["endpoint_fingerprint"] == "GET|portal.example.edu|/api/user/profile|uid"
        assert rows[0]["test_type"] == "idor_candidate"

    def test_hunt_queue_dedupes_canonical_random_params(self):
        conn = self._conn()

        count = write_hunt_queue(
            conn,
            [
                {
                    "url": "https://portal.example.edu/api/user/profile?random_number=1&uid=42",
                    "method": "GET",
                    "post_data": "",
                    "endpoint_type": "business_api",
                    "business_intent": "profile",
                    "risk_hint": "High",
                },
                {
                    "url": "https://portal.example.edu/api/user/profile?random_number=2&uid=42",
                    "method": "GET",
                    "post_data": "",
                    "endpoint_type": "business_api",
                    "business_intent": "profile",
                    "risk_hint": "High",
                },
            ],
            1,
        )

        rows = conn.execute("SELECT url, query_string FROM hunt_queue").fetchall()
        conn.close()
        assert count == 1
        assert rows[0]["url"] == "https://portal.example.edu/api/user/profile"
        assert rows[0]["query_string"] == "uid=42"
