from utils.signal_filter import (
    canonical_query_string,
    canonicalize_url,
    classify_auth_surface,
    classify_endpoint,
    endpoint_fingerprint,
    has_sensitive_response_signal,
    response_sensitive_markers,
    summarize_response,
)


class TestCanonicalUrl:
    def test_removes_noise_params_and_sorts_remaining(self):
        url = "https://portal.example.edu/api/item?random_number=1&page=2&uid=42&type=a"

        assert canonicalize_url(url) == "https://portal.example.edu/api/item?type=a&uid=42"
        assert canonical_query_string(url) == "type=a&uid=42"

    def test_preserves_business_key_param(self):
        url = "https://portal.example.edu/api/getValueByKey?key=abc&ts=123"

        assert canonicalize_url(url) == "https://portal.example.edu/api/getValueByKey?key=abc"

    def test_endpoint_fingerprint_ignores_noise_params(self):
        one = endpoint_fingerprint(
            "https://portal.example.edu/api/user/profile?random_number=1&pageSize=10&uid=42",
            "GET",
            ["random_number", "uid"],
        )
        two = endpoint_fingerprint(
            "https://portal.example.edu/api/user/profile?random_number=2&pageSize=20&uid=42",
            "GET",
            ["uid"],
        )

        assert one == two
        assert one == "GET|portal.example.edu|/api/user/profile|uid"


class TestEndpointClassification:
    def test_public_theme_is_low_value(self):
        signal = classify_endpoint("https://portal.example.edu/portal-api/v2/theme/themeInfo")

        assert signal.value == "low_value"

    def test_user_profile_is_high_value(self):
        signal = classify_endpoint("https://portal.example.edu/api/user/profile")

        assert signal.value == "high_value"

    def test_message_endpoint_is_high_value(self):
        signal = classify_endpoint("https://message.example.edu/api/listMessageRecordIsReadCount?readed=0")

        assert signal.value == "high_value"

    def test_post_without_identity_is_medium_value(self):
        signal = classify_endpoint("https://portal.example.edu/api/search", "POST")

        assert signal.value == "medium_value"

    def test_noise_counter_path_is_not_review_candidate(self):
        kind, score, reason = classify_auth_surface(
            "https://zzb.example.edu/system/resource/calendar/getCurrentWeekMap.jsp",
            "POST",
            ["sdate", "edate"],
        )

        assert kind == "noise_counter"
        assert score == 0
        assert reason == "noise_or_static_path"

    def test_identity_param_becomes_idor_candidate(self):
        summary = summarize_response(200, "application/json", '{"code":0,"data":{"name":"x"}}')
        kind, score, _ = classify_auth_surface(
            "https://portal.example.edu/api/order/detail?userId=42",
            "GET",
            ["userId"],
            summary,
        )

        assert kind == "idor_candidate"
        assert score >= 60


class TestResponseSignals:
    def test_response_summary_detects_auth_required(self):
        summary = summarize_response(403, "application/json", '{"message":"Access Denied"}')

        assert summary["auth_required_hint"]
        assert summary["status"] == 403

    def test_detects_phone_and_user_fields(self):
        body = '{"userName":"张三","mobile":"13800138000"}'

        markers = response_sensitive_markers(body)

        assert markers["phones"] == 1
        assert markers["fields"] >= 1
        assert has_sensitive_response_signal(body)

    def test_response_summary_detects_jwt_and_token_fields(self):
        body = '{"accessToken":"eyJaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccc"}'

        markers = response_sensitive_markers(body)

        assert markers["jwts"] == 1
        assert markers["token_fields"] >= 1

    def test_ignores_plain_public_json(self):
        assert not has_sensitive_response_signal('{"code":0,"theme":"blue"}')
