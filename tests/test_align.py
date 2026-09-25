import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import audit_sender_alignment  # noqa: E402
from mailtrace.parsing.sample import (  # noqa: E402
    SAMPLE_HEADERS_ALIGN,
    SAMPLE_ORG_DOMAIN,
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
ORG = "partner.example"

# 可信前缀为 edge.org / gw2.org 两跳、第 3 跳为边界的基础链路
BASE_CHAIN = "\n".join(
    [
        _received("gw2.org", "edge.org", "10.0.0.2"),
        _received("partner.example", "gw2.org", "203.0.113.55"),
        _received("relay.out", "relay.out", "198.51.100.9"),
    ]
)


def _headers(ar_lines, from_line="From: Sender <news@mail.partner.example>"):
    parts = list(ar_lines)
    parts.append(BASE_CHAIN)
    if from_line is not None:
        parts.append(from_line)
    parts.append("Subject: hi\n")
    return "\n".join(parts)


class SenderAlignmentTests(unittest.TestCase):
    def test_strict_aligned_exact_match(self):
        raw = _headers(
            [
                "Authentication-Results: edge.org;\n"
                "\tspf=pass smtp.mailfrom=news@mail.partner.example;\n"
                "\tdkim=pass header.d=mail.partner.example"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "aligned")
        self.assertEqual(result["status_label"], "有对齐证据")
        self.assertIsNone(result["reason"])
        self.assertEqual(result["mode"], "strict")
        self.assertEqual(result["from"]["status"], "ok")
        self.assertEqual(result["from"]["domain"], "mail.partner.example")
        self.assertEqual(result["aligned_count"], 2)
        self.assertEqual(result["usable_claim_count"], 2)
        first = result["claims"][0]
        self.assertEqual(first["method"], "spf")
        self.assertEqual(first["identity_prop"], "smtp.mailfrom")
        self.assertEqual(first["identity_domain"], "mail.partner.example")
        self.assertEqual(first["status"], "aligned")
        self.assertEqual(first["field_index"], 1)
        self.assertEqual(first["field_position"], 1)
        self.assertEqual(first["hop_top_index"], 1)
        self.assertEqual(first["hop_by_host"], "edge.org")

    def test_strict_subdomain_is_not_exact_match(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=partner.example"]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "not_aligned")
        self.assertEqual(result["status_label"], "未见对齐证据")
        self.assertEqual(result["usable_claim_count"], 1)
        self.assertEqual(result["aligned_count"], 0)
        self.assertEqual(result["claims"][0]["status"], "not_aligned")

    def test_relaxed_aligns_subdomains_on_label_boundary(self):
        raw = _headers(
            [
                "Authentication-Results: edge.org;\n"
                "\tspf=pass smtp.mailfrom=bounces.partner.example;\n"
                "\tdkim=pass header.d=partner.example"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(result["status"], "aligned")
        self.assertEqual(result["aligned_count"], 2)
        self.assertTrue(all(c["status"] == "aligned" for c in result["claims"]))

    def test_relaxed_rejects_label_boundary_tricks(self):
        # notexample.com / partner.example.evil.com 都不是组织域或其子域
        raw = _headers(
            [
                "Authentication-Results: edge.org;\n"
                "\tspf=pass smtp.mailfrom=notpartner.example;\n"
                "\tdkim=pass header.d=partner.example.evil.com"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(result["status"], "not_aligned")
        self.assertEqual(
            [c["status"] for c in result["claims"]],
            ["not_aligned", "not_aligned"],
        )

    def test_relaxed_requires_from_domain_in_org_tree(self):
        # From 域不在组织域树内时，即使身份域在树内也不对齐
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=partner.example"],
            from_line="From: Sender <news@other.example>",
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(result["status"], "not_aligned")
        self.assertIn("From 域", result["claims"][0]["detail"])

    def test_relaxed_requires_org_domain(self):
        result = audit_sender_alignment(
            _headers(["Authentication-Results: edge.org; spf=pass"]), HOSTS, "", "relaxed"
        )
        self.assertIn("error", result)
        self.assertIn("发件组织域", result["error"])

    def test_invalid_mode_is_input_error(self):
        result = audit_sender_alignment(
            _headers([]), HOSTS, ORG, "loose"
        )
        self.assertIn("error", result)
        self.assertIn("strict", result["error"])

    def test_invalid_org_domain_is_input_error(self):
        result = audit_sender_alignment(
            _headers([]), HOSTS, "not a domain", "relaxed"
        )
        self.assertIn("error", result)
        self.assertIn("不是合法域名", result["error"])

    def test_default_mode_is_strict(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=partner.example"]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG)
        self.assertEqual(result["mode"], "strict")
        self.assertEqual(result["status"], "not_aligned")

    def test_duplicate_from_fields_not_silently_picked(self):
        # 两个 From 字段：即使存在可对齐声明，也不得静默择一
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"],
            from_line=(
                "From: Sender <news@mail.partner.example>\n"
                "From: Impostor <other@evil.example>"
            ),
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["status_label"], "证据不足")
        self.assertEqual(result["reason"], "from_multiple_fields")
        self.assertEqual(result["from"]["status"], "multiple_fields")
        self.assertEqual(result["from"]["field_count"], 2)
        self.assertIsNone(result["from"]["domain"])
        # 声明仍逐条列出，但标记为无法比较
        self.assertEqual(result["claims"][0]["status"], "uncomparable")

    def test_missing_from_is_insufficient(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"],
            from_line=None,
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "from_missing")
        self.assertEqual(result["from"]["field_count"], 0)

    def test_multiple_addresses_in_single_from_not_picked(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"],
            from_line="From: a@mail.partner.example, b@evil.example",
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "from_multiple_addresses")
        self.assertEqual(result["from"]["status"], "multiple_addresses")
        self.assertIsNone(result["from"]["domain"])

    def test_from_display_name_with_comma_still_unique(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"],
            from_line="From: Doe, John <news@mail.partner.example>",
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["from"]["status"], "ok")
        self.assertEqual(result["status"], "aligned")

    def test_no_own_claims_is_insufficient(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"]
        )
        result = audit_sender_alignment(raw, ["other.org"], ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "no_own_claims")
        self.assertTrue(result["no_org_claims"])
        self.assertEqual(result["claims"], [])

    def test_no_pass_claims_is_insufficient(self):
        raw = _headers(
            [
                "Authentication-Results: edge.org;\n"
                "\tspf=fail smtp.mailfrom=mail.partner.example;\n"
                "\tdkim=temperror header.d=mail.partner.example"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "no_pass_claims")
        self.assertEqual(result["pass_claim_count"], 0)
        self.assertEqual(
            [c["status"] for c in result["claims"]], ["not_pass", "not_pass"]
        )

    def test_pass_without_identity_is_insufficient(self):
        raw = _headers(
            [
                "Authentication-Results: edge.org;\n"
                "\tspf=pass smtp.helo=mail.partner.example;\n"
                "\tdkim=pass header.i=@mail.partner.example"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "no_usable_claims")
        self.assertEqual(result["pass_claim_count"], 2)
        self.assertEqual(result["usable_claim_count"], 0)
        self.assertEqual(
            [c["status"] for c in result["claims"]],
            ["no_identity", "no_identity"],
        )

    def test_null_sender_mailfrom_has_no_identity(self):
        raw = _headers(
            ["Authentication-Results: edge.org; spf=pass smtp.mailfrom=<>"]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["claims"][0]["status"], "no_identity")
        self.assertEqual(result["reason"], "no_usable_claims")

    def test_only_own_claims_are_adopted(self):
        # 越过边界的 AR 里有可对齐的 dkim=pass，也不予采纳
        raw = "\n".join(
            [
                "Authentication-Results: edge.org; spf=fail smtp.mailfrom=x.example",
                _received("gw2.org", "edge.org", "10.0.0.2"),
                _received("partner.example", "gw2.org", "203.0.113.55"),
                "Authentication-Results: relay.out; dkim=pass header.d=mail.partner.example",
                _received("relay.out", "relay.out", "198.51.100.9"),
                "From: Sender <news@mail.partner.example>",
                "Subject: hi\n",
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["reason"], "no_pass_claims")
        self.assertEqual(result["own_count"], 1)
        # 只有本组织声明进入 claims（1 条 spf=fail）
        self.assertEqual(len(result["claims"]), 1)
        self.assertEqual(result["claims"][0]["method"], "spf")

    def test_domain_case_and_trailing_dot_ignored(self):
        raw = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=MAIL.partner.example."],
            from_line="From: Sender <news@Mail.Partner.Example>",
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["from"]["domain"], "mail.partner.example")
        self.assertEqual(result["claims"][0]["identity_domain"], "mail.partner.example")
        self.assertEqual(result["status"], "aligned")

    def test_comments_in_auth_results_ignored(self):
        raw = _headers(
            [
                "Authentication-Results: edge.org (mx tier);\n"
                "\tspf=pass (domain ok) smtp.mailfrom=mail.partner.example"
            ]
        )
        result = audit_sender_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "aligned")
        self.assertEqual(
            result["claims"][0]["identity_domain"], "mail.partner.example"
        )

    def test_empty_hostlist_is_input_error(self):
        result = audit_sender_alignment(_headers([]), "  \n, ", ORG, "strict")
        self.assertIn("error", result)
        self.assertNotIn("claims", result)

    def test_sample_headers_strict_and_relaxed(self):
        strict = audit_sender_alignment(
            SAMPLE_HEADERS_ALIGN, SAMPLE_TRUSTED_HOSTS, SAMPLE_ORG_DOMAIN, "strict"
        )
        self.assertEqual(strict["status"], "aligned")
        self.assertEqual(strict["from"]["domain"], "mail.partner.example")
        self.assertEqual(strict["claim_count"], 5)
        self.assertEqual(strict["pass_claim_count"], 4)
        self.assertEqual(strict["usable_claim_count"], 4)
        # 严格模式：仅与 From 子域完全相同的两条对齐
        self.assertEqual(strict["aligned_count"], 2)
        self.assertEqual(
            [c["status"] for c in strict["claims"]],
            ["aligned", "aligned", "not_pass", "not_aligned", "not_aligned"],
        )
        relaxed = audit_sender_alignment(
            SAMPLE_HEADERS_ALIGN, SAMPLE_TRUSTED_HOSTS, SAMPLE_ORG_DOMAIN, "relaxed"
        )
        self.assertEqual(relaxed["status"], "aligned")
        # 宽松模式：四条 pass 声明的身份域均在组织域树内
        self.assertEqual(relaxed["aligned_count"], 4)


@unittest.skipIf(create_app is None, "Flask 未安装")
class SenderAlignmentApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def _aligned_headers(self):
        return _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"]
        )

    def test_api_json_strict_aligned(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={
                "headers": self._aligned_headers(),
                "trusted_hosts": HOSTS,
                "org_domain": ORG,
                "mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "aligned")
        self.assertEqual(data["status_label"], "有对齐证据")
        self.assertEqual(data["aligned_count"], 1)
        self.assertEqual(data["claims"][0]["identity_domain"], "mail.partner.example")

    def test_api_relaxed_aligned(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={
                "headers": _headers(
                    ["Authentication-Results: edge.org; spf=pass smtp.mailfrom=partner.example"]
                ),
                "trusted_hosts": HOSTS,
                "org_domain": ORG,
                "mode": "relaxed",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "aligned")

    def test_api_relaxed_without_org_domain_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": HOSTS,
                  "mode": "relaxed"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("发件组织域", resp.get_json()["error"])

    def test_api_invalid_mode_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": HOSTS,
                  "mode": "loose"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_blank_headers_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": "   ", "trusted_hosts": HOSTS, "mode": "strict"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_headers_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": 5, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_trusted_hosts_type_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": [1, 2]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_org_domain_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": HOSTS,
                  "org_domain": 7},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_empty_hostlist_400(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("名单不能为空", resp.get_json()["error"])

    def test_api_default_mode_strict(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            json={"headers": self._aligned_headers(), "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["mode"], "strict")

    def test_api_form_encoded(self):
        resp = self.client.post(
            "/api/analyze/sender-alignment",
            data={
                "headers": self._aligned_headers(),
                "trusted_hosts": "edge.org\ngw2.org",
                "org_domain": ORG,
                "mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "aligned")

    def test_page_form_renders_aligned(self):
        resp = self.client.post(
            "/sender-alignment",
            data={
                "headers_align": SAMPLE_HEADERS_ALIGN,
                "trusted_hosts_align": SAMPLE_TRUSTED_HOSTS,
                "org_domain": SAMPLE_ORG_DOMAIN,
                "align_mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("有对齐证据", body)
        self.assertIn("mail.partner.example", body)
        self.assertIn("不对齐", body)  # 逐条比较中含严格模式下不对齐的行

    def test_page_form_relaxed_renders(self):
        resp = self.client.post(
            "/sender-alignment",
            data={
                "headers_align": SAMPLE_HEADERS_ALIGN,
                "trusted_hosts_align": SAMPLE_TRUSTED_HOSTS,
                "org_domain": SAMPLE_ORG_DOMAIN,
                "align_mode": "relaxed",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("有对齐证据", resp.get_data(as_text=True))

    def test_page_form_duplicate_from_shows_insufficient(self):
        headers = _headers(
            ["Authentication-Results: edge.org; dkim=pass header.d=mail.partner.example"],
            from_line="From: a@mail.partner.example\nFrom: b@evil.example",
        )
        resp = self.client.post(
            "/sender-alignment",
            data={
                "headers_align": headers,
                "trusted_hosts_align": "edge.org\ngw2.org",
                "org_domain": ORG,
                "align_mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("证据不足", body)
        self.assertIn("重复 From 字段", body)

    def test_page_form_empty_hostlist_error_banner(self):
        resp = self.client.post(
            "/sender-alignment",
            data={
                "headers_align": self._aligned_headers(),
                "trusted_hosts_align": "  ",
                "align_mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
