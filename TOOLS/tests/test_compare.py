from utils.compare import compare_unauth


class TestCompareUnauth:
    def test_public_config_similar_response_is_false_positive(self):
        body = '{"code":0,"theme":"blue","data":{"layout":"default","items":["a","b","c"],"text":"' + "x" * 120 + '"}}'

        verdict, evidence = compare_unauth(
            body,
            body,
            200,
            200,
            "https://portal.example.edu/portal-api/v2/theme/themeInfo",
            "cookie+bearer",
        )

        assert verdict == "false_positive"
        assert "endpoint_value=low_value" in evidence

    def test_sensitive_response_with_bearer_is_confirmed(self):
        body = '{"code":0,"data":{"userName":"张三","mobile":"13800138000","desc":"' + "x" * 120 + '"}}'

        verdict, evidence = compare_unauth(
            body,
            body,
            200,
            200,
            "https://portal.example.edu/api/user/profile",
            "cookie+bearer",
        )

        assert verdict == "confirmed"
        assert "phones=1" in evidence

    def test_sensitive_response_without_bearer_is_low_confidence(self):
        body = '{"code":0,"data":{"userName":"张三","mobile":"13800138000","desc":"' + "x" * 120 + '"}}'

        verdict, evidence = compare_unauth(
            body,
            body,
            200,
            200,
            "https://portal.example.edu/api/user/profile",
            "cookie_only",
        )

        assert verdict == "low_confidence"
        assert "no_bearer" in evidence


from utils.compare import compare_batch_idor, compare_vertical_priv_esc


class TestCompareVerticalPrivEsc:
    def test_primary_403_teacher_200_is_confirmed(self):
        verdict, evidence = compare_vertical_priv_esc(
            403,
            '{"code":403,"message":"权限不足"}',
            200,
            '{"code":0,"data":{"users":[{"id":1,"name":"学生甲"}]}}',
        )
        assert verdict == "confirmed"
        assert "teacher=200" in evidence

    def test_primary_500_missing_auth_is_confirmed(self):
        verdict, evidence = compare_vertical_priv_esc(
            500,
            '{"error":"undefined method for nil:NilClass"}',
            0,
            "",
        )
        assert verdict == "confirmed"
        assert "500" in evidence

    def test_both_403_is_false_positive(self):
        verdict, evidence = compare_vertical_priv_esc(
            403,
            '{"code":403}',
            403,
            '{"code":403}',
        )
        assert verdict == "false_positive"
        assert "teacher=403" in evidence

    def test_no_teacher_session_is_needs_teacher_account(self):
        verdict, evidence = compare_vertical_priv_esc(
            403,
            '{"code":403}',
            0,
            "",
        )
        assert verdict == "needs_teacher_account"

    def test_primary_200_is_false_positive_public_endpoint(self):
        verdict, evidence = compare_vertical_priv_esc(
            200,
            '{"code":0,"data":{}}',
            0,
            "",
        )
        assert verdict == "false_positive"
        assert "public endpoint" in evidence


class TestCompareBatchIdor:
    def test_variant2_b_with_a_id_succeeds_is_confirmed(self):
        baseline = '{"code":0,"data":{"items":[{"id":101,"score":95}]}}'
        b_cross = '{"code":0,"data":{"items":[{"id":101,"score":95}]}}'
        verdict, evidence = compare_batch_idor(
            200,
            baseline,  # ① A + [A_id]
            200,
            b_cross,  # ② B + [A_id]
            0,
            "",  # ③ 未执行
        )
        assert verdict == "confirmed"
        assert "variant②" in evidence

    def test_variant3_mixed_ids_is_confirmed(self):
        baseline = '{"code":0,"data":{"ids":[101]}}'
        mixed = '{"code":0,"data":{"ids":[101,202]}}'
        verdict, evidence = compare_batch_idor(
            200,
            baseline,
            403,
            '{"code":403}',  # ② 拒绝
            200,
            mixed,  # ③ A + [A_id, B_id]
        )
        assert verdict == "confirmed"
        assert "variant③" in evidence

    def test_variant2_403_is_false_positive(self):
        baseline = '{"code":0,"data":{"ids":[101]}}'
        verdict, evidence = compare_batch_idor(
            200,
            baseline,
            403,
            '{"code":403}',
            403,
            '{"code":403}',
        )
        assert verdict == "false_positive"

    def test_baseline_fail_is_false_positive(self):
        verdict, evidence = compare_batch_idor(
            404,
            "",
            0,
            "",
            0,
            "",
        )
        assert verdict == "false_positive"
        assert "baseline" in evidence
