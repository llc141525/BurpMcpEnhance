"""sqli_scan.py 纯函数单元测试。"""

import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_TOOLS))

from pipeline.sqli_scan import build_sqlmap_cmd, is_waf_blocked_line, parse_sqlmap_log


class TestBuildSqlmapCmd:
    def test_basic_get_request(self):
        cmd = build_sqlmap_cmd(
            url="http://example.com/api?id=1",
            proxy="http://127.0.0.1:9870",
            output_dir="/tmp/sqlmap",  # noqa: S108
        )
        assert "sqlmap" in cmd[0]
        assert "-u" in cmd
        assert "http://example.com/api?id=1" in cmd
        assert "--proxy" in cmd
        assert "http://127.0.0.1:9870" in cmd
        assert "--batch" in cmd
        assert "--output-dir" in cmd

    def test_includes_cookie_when_provided(self):
        cmd = build_sqlmap_cmd(
            url="http://example.com/",
            proxy="http://127.0.0.1:9870",
            output_dir="/tmp",  # noqa: S108
            cookie="session=abc123",
        )
        assert "--cookie" in cmd
        assert "session=abc123" in cmd

    def test_post_method_includes_data(self):
        cmd = build_sqlmap_cmd(
            url="http://example.com/login",
            proxy="http://127.0.0.1:9870",
            output_dir="/tmp",  # noqa: S108
            method="POST",
            data="username=admin&password=test",
        )
        assert "--method=POST" in cmd
        assert "--data" in cmd
        assert "username=admin&password=test" in cmd

    def test_no_cookie_when_none(self):
        cmd = build_sqlmap_cmd(
            url="http://example.com/",
            proxy="http://127.0.0.1:9870",
            output_dir="/tmp",  # noqa: S108
            cookie=None,
        )
        assert "--cookie" not in cmd

    def test_default_level_and_risk(self):
        cmd = build_sqlmap_cmd(
            url="http://example.com/",
            proxy="http://127.0.0.1:9870",
            output_dir="/tmp",  # noqa: S108
        )
        assert "--level=2" in cmd
        assert "--risk=1" in cmd


class TestIsWafBlockedLine:
    def test_waf_keyword(self):
        assert is_waf_blocked_line("[WARNING] the web server responded with an HTTP error code (403)") is True

    def test_rate_limit(self):
        assert is_waf_blocked_line("too many requests detected") is True

    def test_blocked_keyword(self):
        assert is_waf_blocked_line("CRITICAL: access blocked by WAF") is True

    def test_normal_line(self):
        assert is_waf_blocked_line("[INFO] testing parameter 'id'") is False

    def test_empty_line(self):
        assert is_waf_blocked_line("") is False


class TestParseSqlmapLog:
    def test_returns_empty_for_missing_file(self):
        result = parse_sqlmap_log(Path("/nonexistent/path/log"))
        assert result == []

    def test_parses_injection_point(self, tmp_path):
        log_content = """
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1-- uaFr

Parameter: name (POST)
    Type: time-based blind
    Payload: name=test' AND SLEEP(5)-- abc
---
"""
        log_file = tmp_path / "log"
        log_file.write_text(log_content)
        results = parse_sqlmap_log(log_file)
        assert len(results) >= 1
        assert any(r["param"] == "id" for r in results)

    def test_returns_empty_for_no_injection(self, tmp_path):
        log_file = tmp_path / "log"
        log_file.write_text("[INFO] no injection detected\n")
        assert parse_sqlmap_log(log_file) == []
