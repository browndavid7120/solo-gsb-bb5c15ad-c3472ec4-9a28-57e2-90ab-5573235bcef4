import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_auth_results  # noqa: E402
from mailtrace.parsing.sample import (  # noqa: E402
    SAMPLE_HEADERS_AUTHRES,
    SAMPLE_TRUSTED_HOSTS,
)

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def _received(frm, by, ip=None, date="Thu, 24 Sep 2026 03:00:00 +0000"):
    """构造单条 Received（书写顺序即最终接收方在顶部）。"""
    head = f"Received: from {frm}"
    if ip:
        head += f" ({frm} [{ip}])"
    head += f"\n\tby {by} with ESMTP id X"
    if date:
        head += f"; {date}"
    return head


HOSTS = ["edge.org", "gw2.org"]

# 可信前缀为 edge.org / gw2.org 两跳、第 3 跳为边界的基础链路
BASE_RECEIVED = "\n".join(
    [
        _received("gw2.org", "edge.org", "10.0.0.2"),
        _received("partner.example", "gw2.org", "203.0.113.55"),
        _received("relay.out", "relay.out", "198.51.100.9"),
        "Subject: hi\n",
    ]
)


class AuthResultsAttributionTests(unittest.TestCase):
    def test_own_claim_extracts_methods_in_order_with_duplicates(self):
        raw = (
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=x.example;\n"
            "\tdkim=pass header.d=x.example; dkim=fail header.d=y.example;\n"
            "\tdmarc=pass header.from=x.example\n"
            + BASE_RECEIVED
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["ar_count"], 1)
        self.assertEqual(result["own_count"], 1)
        self.assertFalse(result["no_org_claims"])
        self.assertIsNone(result["no_org_reason"])
        entry = result["results"][0]
        self.assertEqual(entry["status"], "own")
        self.assertEqual(entry["status_label"], "本组织声明")
        self.assertEqual(entry["authserv_id"], "edge.org")
        self.assertEqual(entry["hop_top_index"], 1)
        self.assertEqual(entry["hop_by_host"], "edge.org")
        # 按原文顺序保留重复声明（dkim 出现两次）
        self.assertEqual(
            [(m["method"], m["result"]) for m in entry["methods"]],
            [("spf", "pass"), ("dkim", "pass"), ("dkim", "fail"), ("dmarc", "pass")],
        )
        self.assertEqual(
            [(m["method"], m["result"]) for m in result["auth_summary"]],
            [(m["method"], m["result"]) for m in entry["methods"]],
        )

    def test_own_claim_requires_immediately_following_received(self):
        # AR 与其归属的 Received 之间隔了另一条 Received：归属到紧邻的下一条
        raw = (
            "Authentication-Results: gw2.org; spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\n"
            + _received("partner.example", "gw2.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        # 紧邻的下一条是第 1 跳（by edge.org），authserv-id 不一致 → 身份不符
        self.assertEqual(entry["hop_top_index"], 1)
        self.assertEqual(entry["status"], "identity_mismatch")

    def test_ar_above_ar_attributes_both_to_same_hop(self):
        # 两条 AR 之间没有 Received：都归属到下方紧邻的同一跳
        raw = (
            "Authentication-Results: forged.example; spf=pass\n"
            "Authentication-Results: edge.org; spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        first, second = result["results"]
        self.assertEqual(first["hop_top_index"], 1)
        self.assertEqual(first["status"], "identity_mismatch")
        self.assertEqual(second["hop_top_index"], 1)
        self.assertEqual(second["status"], "own")
        self.assertEqual(result["own_count"], 1)

    def test_no_hop_when_no_received_after(self):
        raw = (
            _received("gw2.org", "edge.org")
            + "\nAuthentication-Results: edge.org; spf=pass\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertEqual(entry["status"], "no_hop")
        self.assertEqual(entry["status_label"], "无对应跳")
        self.assertIsNone(entry["hop_top_index"])
        self.assertEqual(result["own_count"], 0)
        self.assertTrue(result["no_org_claims"])
        self.assertEqual(result["no_org_reason"], "none_attributed")

    def test_beyond_boundary_hop(self):
        # AR 位于可信跳与边界跳之间：归属到边界跳（第 3 跳）
        raw = "\n".join(
            [
                _received("gw2.org", "edge.org"),
                _received("partner.example", "gw2.org"),
                "Authentication-Results: relay.out; spf=pass",
                _received("relay.out", "relay.out"),
                "Subject: hi\n",
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertEqual(entry["status"], "beyond_boundary")
        self.assertEqual(entry["status_label"], "越过边界")
        self.assertEqual(entry["hop_top_index"], 3)
        self.assertEqual(entry["hop_by_host"], "relay.out")
        self.assertEqual(entry["methods"], [])

    def test_beyond_boundary_even_when_authserv_matches_by(self):
        # 边界之后 by 再次命中名单的伪造 Received：authserv-id 一致也不接入
        raw = "\n".join(
            [
                _received("gw2.org", "edge.org"),
                _received("relay.out", "relay.out"),
                "Authentication-Results: gw2.org; spf=pass",
                _received("evil.example", "gw2.org"),
                "Subject: hi\n",
            ]
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertEqual(entry["hop_top_index"], 3)
        self.assertEqual(entry["status"], "beyond_boundary")

    def test_identity_mismatch_on_trusted_hop(self):
        raw = (
            "Authentication-Results: forged.example; spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertEqual(entry["status"], "identity_mismatch")
        self.assertEqual(entry["status_label"], "身份不符")
        self.assertEqual(entry["hop_top_index"], 1)

    def test_missing_authserv_id_is_identity_mismatch(self):
        raw = (
            "Authentication-Results: spf=pass smtp.mailfrom=x.example\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertIsNone(entry["authserv_id"])
        self.assertEqual(entry["status"], "identity_mismatch")

    def test_authserv_none_is_identity_mismatch(self):
        raw = (
            "Authentication-Results: none\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertIsNone(entry["authserv_id"])
        self.assertEqual(entry["status"], "identity_mismatch")

    def test_authserv_id_case_and_trailing_dot_ignored(self):
        raw = (
            "Authentication-Results: EDGE.Org.; spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["results"][0]["status"], "own")

    def test_authserv_id_with_comment(self):
        raw = (
            "Authentication-Results: edge.org (mx tier); spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        entry = result["results"][0]
        self.assertEqual(entry["authserv_id"], "edge.org")
        self.assertEqual(entry["status"], "own")

    def test_methods_ignore_props_and_comments(self):
        raw = (
            "Authentication-Results: edge.org;\n"
            "\tspf=softfail (domain of x.example does not designate) smtp.mailfrom=x.example;\n"
            "\tdkim=pass (1024-bit key) header.d=x.example; dmarc=none header.from=x.example\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        methods = result["results"][0]["methods"]
        self.assertEqual(
            [(m["method"], m["result"]) for m in methods],
            [("spf", "softfail"), ("dkim", "pass"), ("dmarc", "none")],
        )

    def test_no_trusted_prefix_marks_no_org_claims(self):
        raw = (
            "Authentication-Results: edge.org; spf=pass\n" + BASE_RECEIVED
        )
        result = analyze_auth_results(raw, ["only-other.org"])
        self.assertEqual(result["status"], "untrusted_top")
        self.assertEqual(result["trusted_count"], 0)
        self.assertTrue(result["no_org_claims"])
        self.assertEqual(result["no_org_reason"], "no_trusted_prefix")
        self.assertIn("无本组织声明", result["message"])
        # 对应跳存在但不在可信前缀内 → 越过边界
        self.assertEqual(result["results"][0]["status"], "beyond_boundary")

    def test_no_received_means_no_trusted_prefix(self):
        raw = "Authentication-Results: edge.org; spf=pass\nSubject: hi\n"
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["status"], "no_received")
        self.assertTrue(result["no_org_claims"])
        self.assertEqual(result["no_org_reason"], "no_trusted_prefix")
        self.assertIn("无本组织声明", result["message"])
        self.assertEqual(result["results"][0]["status"], "no_hop")

    def test_no_auth_results_fields(self):
        result = analyze_auth_results(BASE_RECEIVED, HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["ar_count"], 0)
        self.assertEqual(result["results"], [])
        self.assertTrue(result["no_org_claims"])
        self.assertEqual(result["no_org_reason"], "no_auth_results")
        self.assertIn("无本组织声明", result["message"])

    def test_empty_hostlist_is_input_error(self):
        result = analyze_auth_results(BASE_RECEIVED, "  \n, ")
        self.assertIn("error", result)
        self.assertNotIn("results", result)

    def test_arc_authentication_results_not_counted(self):
        # ARC-Authentication-Results 是另一字段名，不参与归属
        raw = (
            "ARC-Authentication-Results: i=1; edge.org; spf=pass\n"
            + _received("gw2.org", "edge.org")
            + "\nSubject: hi\n"
        )
        result = analyze_auth_results(raw, HOSTS)
        self.assertEqual(result["ar_count"], 0)
        self.assertEqual(result["no_org_reason"], "no_auth_results")

    def test_sample_headers_full_coverage(self):
        result = analyze_auth_results(SAMPLE_HEADERS_AUTHRES, SAMPLE_TRUSTED_HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["ar_count"], 6)
        self.assertEqual(result["own_count"], 2)
        self.assertFalse(result["no_org_claims"])
        self.assertEqual(
            [r["status"] for r in result["results"]],
            [
                "identity_mismatch",
                "own",
                "own",
                "beyond_boundary",
                "beyond_boundary",
                "no_hop",
            ],
        )
        # 汇总按原文顺序保留重复（dkim=pass 出现两次、dkim 共三条）
        self.assertEqual(
            [(m["method"], m["result"]) for m in result["auth_summary"]],
            [
                ("spf", "pass"),
                ("dkim", "pass"),
                ("dkim", "fail"),
                ("dmarc", "pass"),
                ("spf", "softfail"),
                ("dkim", "pass"),
                ("dmarc", "fail"),
            ],
        )
        self.assertEqual(
            [m["field_index"] for m in result["auth_summary"]],
            [2, 2, 2, 2, 3, 3, 3],
        )


@unittest.skipIf(create_app is None, "Flask 未安装")
class AuthResultsApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_json_own_claim(self):
        raw = (
            "Authentication-Results: edge.org; spf=pass; dkim=pass; dmarc=pass\n"
            + BASE_RECEIVED
        )
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": raw, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["own_count"], 1)
        self.assertEqual(data["results"][0]["status"], "own")
        self.assertEqual(len(data["auth_summary"]), 3)

    def test_api_empty_hostlist_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": BASE_RECEIVED, "trusted_hosts": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("名单不能为空", resp.get_json()["error"])

    def test_api_blank_headers_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": "   ", "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_headers_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": 5, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_trusted_hosts_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": BASE_RECEIVED, "trusted_hosts": [1, 2]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_trusted_hosts_wrong_scalar_type_400(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": BASE_RECEIVED, "trusted_hosts": 9},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_no_trusted_prefix_is_200(self):
        resp = self.client.post(
            "/api/analyze/auth-results",
            json={"headers": BASE_RECEIVED, "trusted_hosts": ["nope.org"]},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "untrusted_top")
        self.assertTrue(data["no_org_claims"])

    def test_api_form_encoded(self):
        raw = "Authentication-Results: edge.org; spf=pass\n" + BASE_RECEIVED
        resp = self.client.post(
            "/api/analyze/auth-results",
            data={"headers": raw, "trusted_hosts": "edge.org\ngw2.org"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["own_count"], 1)

    def test_page_form_renders(self):
        resp = self.client.post(
            "/auth-results",
            data={
                "headers_authres": SAMPLE_HEADERS_AUTHRES,
                "trusted_hosts_authres": SAMPLE_TRUSTED_HOSTS,
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("本组织声明", body)
        self.assertIn("越过边界", body)
        self.assertIn("身份不符", body)
        self.assertIn("无对应跳", body)
        self.assertIn("dkim=fail", body)

    def test_page_form_shows_no_org_claims(self):
        resp = self.client.post(
            "/auth-results",
            data={
                "headers_authres": "Authentication-Results: x.example; spf=pass\n"
                + BASE_RECEIVED,
                "trusted_hosts_authres": "only-other.org",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("无本组织声明", resp.get_data(as_text=True))

    def test_page_form_empty_hostlist_error_banner(self):
        resp = self.client.post(
            "/auth-results",
            data={"headers_authres": BASE_RECEIVED, "trusted_hosts_authres": "  "},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
