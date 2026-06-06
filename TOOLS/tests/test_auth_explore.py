# TOOLS/tests/test_auth_explore.py
from auth.auth_explore import filter_api_requests, parse_request_params


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
