# TOOLS/tests/test_js_analyzer.py
from js_analyzer import parse_mmx_output, score_js_url


class TestScoreJsUrl:
    def test_cdn_skipped(self):
        assert score_js_url("https://cdnjs.cloudflare.com/jquery.min.js") == 0

    def test_vendor_skipped(self):
        assert score_js_url("https://example.com/vendor.bundle.js") == 0

    def test_jquery_skipped(self):
        assert score_js_url("https://example.com/jquery.min.js") == 0

    def test_high_priority_api(self):
        assert score_js_url("https://example.com/api.js") == 2

    def test_high_priority_auth(self):
        assert score_js_url("https://example.com/auth-service.js") == 2

    def test_high_priority_config(self):
        assert score_js_url("https://example.com/config.js") == 2

    def test_chunk_medium_priority(self):
        # webpack/vite hash chunk
        assert score_js_url("https://example.com/main.abc123ef.js") == 1

    def test_generic_medium_priority(self):
        assert score_js_url("https://example.com/dashboard.js") == 1


class TestParseMmxOutput:
    def test_valid_json(self):
        raw = (
            '{"api_endpoints": [{"path": "/api/v1", "method": "GET", "params": ["id"]}],'
            ' "hardcoded_secrets": [], "internal_routes": [], "auth_patterns": []}'
        )
        result = parse_mmx_output(raw)
        assert result is not None
        assert len(result["api_endpoints"]) == 1

    def test_json_in_markdown_fence(self):
        raw = '```json\n{"api_endpoints": [], "hardcoded_secrets": [], "internal_routes": [], "auth_patterns": []}\n```'
        result = parse_mmx_output(raw)
        assert result is not None
        assert result["api_endpoints"] == []

    def test_json_with_preamble(self):
        raw = (
            "Here is the analysis:\n"
            '{"api_endpoints": [], "hardcoded_secrets": [{"type": "apikey", "name": "API_KEY",'
            ' "value": "secret123"}], "internal_routes": [], "auth_patterns": []}'
        )
        result = parse_mmx_output(raw)
        assert result is not None
        assert len(result["hardcoded_secrets"]) == 1

    def test_invalid_returns_none(self):
        assert parse_mmx_output("not json at all") is None

    def test_empty_returns_none(self):
        assert parse_mmx_output("") is None

    def test_list_returns_none(self):
        assert parse_mmx_output("[1, 2, 3]") is None
