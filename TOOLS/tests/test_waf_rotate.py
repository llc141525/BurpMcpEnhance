# TOOLS/tests/test_waf_rotate.py
from utils.waf_rotate import is_waf_blocked


class TestIsWafBlocked:
    # ── 状态码触发 ───────────────────────────────────────
    def test_403_blocked(self):
        assert is_waf_blocked(403, "")

    def test_429_blocked(self):
        assert is_waf_blocked(429, "rate limit exceeded")

    def test_503_blocked(self):
        assert is_waf_blocked(503, "")

    def test_200_no_keywords_not_blocked(self):
        assert not is_waf_blocked(200, "welcome to the portal")

    # ── 关键词触发 ───────────────────────────────────────
    def test_waf_keyword(self):
        assert is_waf_blocked(200, "waf protection activated")

    def test_modsecurity_keyword(self):
        assert is_waf_blocked(403, "modsecurity blocked your request")

    def test_security_intercept_zh(self):
        assert is_waf_blocked(200, "安全拦截，您的访问已被限制")

    def test_cloudflare_ray_id(self):
        assert is_waf_blocked(403, "Cloudflare Ray ID: 7abc123def")

    def test_too_many_requests(self):
        assert is_waf_blocked(200, "too many requests from your IP")

    # ── 修复后：不再误判 ─────────────────────────────────
    def test_verify_email_not_blocked(self):
        assert not is_waf_blocked(200, "Please verify your email address to continue")

    def test_normal_404_not_blocked(self):
        assert not is_waf_blocked(404, "您访问的页面不存在，请检查您输入的网址")

    def test_ddos_article_not_blocked(self):
        assert not is_waf_blocked(200, "本文介绍DDoS攻击的原理与防御方法")

    def test_ddos_protection_page_blocked(self):
        assert is_waf_blocked(200, "ddos protection is active for your IP")

    def test_2fa_page_not_blocked(self):
        assert not is_waf_blocked(200, "Enter your verification code for two-factor authentication")

    def test_empty_body(self):
        assert not is_waf_blocked(200, "")

    def test_none_body(self):
        assert not is_waf_blocked(200, None)
