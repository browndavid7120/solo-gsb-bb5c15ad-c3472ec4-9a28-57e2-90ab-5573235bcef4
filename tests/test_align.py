import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_from_alignment  # noqa: E402
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

FROM_HEADER = "From: Partner News <news@mail.partner.example>"


def _msg(ar_lines, from_header=FROM_HEADER, chain=BASE_CHAIN):
    parts = []
    if ar_lines:
        parts.append(ar_lines)
    parts.append(chain)
    if from_header:
        parts.append(from_header)
    parts.append("Subject: hi\n")
    return "\n".join(parts)


class FromAlignmentTests(unittest.TestCase):
    def test_strict_aligned_exact_match(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example"
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "aligned")
        self.assertEqual(result["alignment_label"], "有对齐证据")
        self.assertIsNone(result["alignment_reason"])
        self.assertEqual(result["aligned_claim_count"], 1)
        claim = result["claims"][0]
        self.assertEqual(claim["method"], "spf")
        self.assertEqual(claim["identity_prop"], "smtp.mailfrom")
        self.assertEqual(claim["identity_domain"], "mail.partner.example")
        self.assertEqual(claim["hop_top_index"], 1)
        self.assertEqual(claim["field_index"], 1)
        self.assertTrue(claim["aligned"])
        self.assertEqual(claim["compare"], "aligned")

    def test_strict_subdomain_not_aligned_but_relaxed_aligned(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=partner.example; dkim=pass header.d=partner.example"
        )
        strict = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        # From 域为 mail.partner.example，身份域为 partner.example：严格模式不对齐
        self.assertEqual(strict["alignment"], "not_aligned")
        self.assertEqual(strict["alignment_label"], "未见对齐证据")
        self.assertEqual(strict["usable_claim_count"], 2)
        self.assertEqual(strict["aligned_claim_count"], 0)
        self.assertEqual(
            [c["compare"] for c in strict["claims"]],
            ["not_aligned", "not_aligned"],
        )
        # 宽松模式：两域均为组织域 partner.example 或其子域 → 对齐
        relaxed = analyze_from_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(relaxed["alignment"], "aligned")
        self.assertEqual(relaxed["aligned_claim_count"], 2)
        self.assertEqual(relaxed["mode_label"], "宽松模式")

    def test_relaxed_requires_both_domains_in_org(self):
        # From 域不在组织域内：即使身份域在组织域内也不对齐
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=partner.example",
            from_header="From: Someone <someone@other.example>",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(result["alignment"], "not_aligned")
        claim = result["claims"][0]
        self.assertFalse(claim["aligned"])
        self.assertIn("From 域 other.example 不在组织域", claim["detail"])

    def test_relaxed_label_boundary_not_suffix(self):
        # 标签边界：evil-partner.example / partner.example.evil.org 均不属于
        # 组织域 partner.example
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=evil-partner.example",
            from_header="From: Someone <someone@evil-partner.example>",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "relaxed")
        self.assertEqual(result["alignment"], "not_aligned")
        raw2 = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=partner.example.evil.org",
            from_header="From: Someone <someone@partner.example.evil.org>",
        )
        result2 = analyze_from_alignment(raw2, HOSTS, ORG, "relaxed")
        self.assertEqual(result2["alignment"], "not_aligned")

    def test_dkim_pass_uses_header_d(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tdkim=pass header.i=@mail.partner.example "
            "header.d=mail.partner.example"
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "aligned")
        claim = result["claims"][0]
        self.assertEqual(claim["method"], "dkim")
        self.assertEqual(claim["identity_prop"], "header.d")
        self.assertEqual(claim["identity_domain"], "mail.partner.example")

    def test_dkim_fail_not_a_pass_claim(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tdkim=fail header.d=mail.partner.example; spf=softfail "
            "smtp.mailfrom=mail.partner.example"
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_label"], "证据不足")
        self.assertEqual(result["alignment_reason"], "no_pass_claims")
        self.assertEqual(result["claim_count"], 0)

    def test_only_own_claims_adopted(self):
        # 边界之外的 AR 即使身份域完全对齐也不采纳
        chain = "\n".join(
            [
                _received("gw2.org", "edge.org"),
                "Authentication-Results: relay.out; dkim=pass "
                "header.d=mail.partner.example",
                _received("relay.out", "relay.out"),
            ]
        )
        raw = _msg(None, chain=chain)
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["own_count"], 0)
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "no_org_claims")
        self.assertEqual(result["claims"], [])

    def test_missing_identity_prop_is_not_usable(self):
        raw = _msg("Authentication-Results: edge.org; spf=pass")
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "no_identity_domain")
        self.assertEqual(result["claim_count"], 1)
        self.assertEqual(result["usable_claim_count"], 0)
        claim = result["claims"][0]
        self.assertIsNone(claim["identity_domain"])
        self.assertIsNone(claim["aligned"])
        self.assertEqual(claim["compare"], "no_identity")

    def test_empty_mailfrom_is_missing_identity(self):
        raw = _msg(
            "Authentication-Results: edge.org; spf=pass smtp.mailfrom="
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment_reason"], "no_identity_domain")
        self.assertIsNone(result["claims"][0]["identity_domain"])

    def test_duplicate_from_fields_not_silently_picked(self):
        # 两个 From 字段：其中一个域本可对齐，但不得静默择一
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example",
            from_header=(
                "From: Partner News <news@mail.partner.example>\n"
                "From: Forged <forged@attacker.example>"
            ),
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "from_multiple_fields")
        self.assertEqual(result["from"]["status"], "multiple_fields")
        self.assertEqual(result["from"]["field_count"], 2)
        self.assertIsNone(result["from"]["domain"])
        # 声明仍逐条列出，但因 From 域不可用而无法比较
        self.assertEqual(result["claims"][0]["compare"], "no_from")
        self.assertIsNone(result["claims"][0]["aligned"])

    def test_multiple_addresses_in_from_not_silently_picked(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example",
            from_header="From: news@mail.partner.example, other@other.example",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment_reason"], "from_multiple_addresses")
        self.assertEqual(result["from"]["status"], "multiple_addresses")

    def test_missing_from_field(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example",
            from_header=None,
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "from_missing_field")
        self.assertEqual(result["from"]["field_count"], 0)

    def test_from_address_without_domain(self):
        raw = _msg(
            "Authentication-Results: edge.org; spf=pass smtp.mailfrom=x.example",
            from_header="From: alice",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment_reason"], "from_missing_domain")
        self.assertEqual(result["from"]["status"], "missing_domain")

    def test_from_group_syntax_has_no_address(self):
        raw = _msg(
            "Authentication-Results: edge.org; spf=pass smtp.mailfrom=x.example",
            from_header="From: undisclosed-recipients:;",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment_reason"], "from_no_address")

    def test_case_and_trailing_dot_normalized(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tdkim=pass header.d=MAIL.Partner.Example.",
            from_header="From: News <news@mail.partner.example>",
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["alignment"], "aligned")
        self.assertEqual(
            result["claims"][0]["identity_domain"], "mail.partner.example"
        )

    def test_relaxed_requires_org_domain(self):
        raw = _msg("Authentication-Results: edge.org; spf=pass smtp.mailfrom=x.example")
        result = analyze_from_alignment(raw, HOSTS, "", "relaxed")
        self.assertIn("error", result)
        self.assertIn("组织域", result["error"])

    def test_strict_mode_works_without_org_domain(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example"
        )
        result = analyze_from_alignment(raw, HOSTS)
        self.assertEqual(result["alignment"], "aligned")
        self.assertEqual(result["mode"], "strict")
        self.assertIsNone(result["org_domain"])

    def test_invalid_mode_is_error(self):
        raw = _msg("Authentication-Results: edge.org; spf=pass smtp.mailfrom=x.example")
        result = analyze_from_alignment(raw, HOSTS, ORG, "bogus")
        self.assertIn("error", result)

    def test_empty_hostlist_is_input_error(self):
        result = analyze_from_alignment(BASE_CHAIN, "  \n, ", ORG, "strict")
        self.assertIn("error", result)
        self.assertNotIn("claims", result)

    def test_no_received_means_insufficient(self):
        raw = (
            "Authentication-Results: edge.org; spf=pass smtp.mailfrom=x.example\n"
            "From: a@x.example\nSubject: hi\n"
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["status"], "no_received")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "no_org_claims")

    def test_untrusted_top_means_insufficient(self):
        raw = _msg(
            "Authentication-Results: edge.org;\n"
            "\tspf=pass smtp.mailfrom=mail.partner.example"
        )
        result = analyze_from_alignment(raw, ["other.org"], ORG, "strict")
        self.assertEqual(result["status"], "untrusted_top")
        self.assertEqual(result["alignment"], "insufficient")
        self.assertEqual(result["alignment_reason"], "no_org_claims")

    def test_claims_keep_field_and_hop_positions(self):
        # 两条本组织声明分属第 1、2 跳，逐条携带字段位置与接收跳
        raw = (
            "Authentication-Results: edge.org; spf=pass smtp.mailfrom=a.example\n"
            + _received("gw2.org", "edge.org")
            + "\nAuthentication-Results: gw2.org; dkim=pass header.d=b.example\n"
            + _received("partner.example", "gw2.org")
            + "\n"
            + FROM_HEADER
            + "\nSubject: hi\n"
        )
        result = analyze_from_alignment(raw, HOSTS, ORG, "strict")
        self.assertEqual(result["claim_count"], 2)
        first, second = result["claims"]
        self.assertEqual((first["field_index"], first["hop_top_index"]), (1, 1))
        self.assertEqual((second["field_index"], second["hop_top_index"]), (2, 2))
        self.assertEqual(first["method"], "spf")
        self.assertEqual(second["method"], "dkim")
        self.assertGreater(second["field_position"], first["field_position"])

    def test_sample_strict_not_aligned_relaxed_aligned(self):
        strict = analyze_from_alignment(
            SAMPLE_HEADERS_ALIGN, SAMPLE_TRUSTED_HOSTS, SAMPLE_ORG_DOMAIN, "strict"
        )
        self.assertEqual(strict["status"], "established")
        self.assertEqual(strict["own_count"], 2)
        self.assertEqual(strict["from"]["domain"], "mail.partner.example")
        # 本组织通过声明 3 条（spf×2 + dkim×1；dkim=fail 不计）；
        # 边界之外那条完全对齐的 dkim=pass 不采纳
        self.assertEqual(strict["claim_count"], 3)
        self.assertEqual(strict["alignment"], "not_aligned")
        relaxed = analyze_from_alignment(
            SAMPLE_HEADERS_ALIGN, SAMPLE_TRUSTED_HOSTS, SAMPLE_ORG_DOMAIN, "relaxed"
        )
        self.assertEqual(relaxed["alignment"], "aligned")
        self.assertEqual(relaxed["aligned_claim_count"], 3)


@unittest.skipIf(create_app is None, "Flask 未安装")
class FromAlignmentApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def _payload(self, **overrides):
        payload = {
            "headers": _msg(
                "Authentication-Results: edge.org;\n"
                "\tspf=pass smtp.mailfrom=mail.partner.example"
            ),
            "trusted_hosts": HOSTS,
            "org_domain": ORG,
            "mode": "strict",
        }
        payload.update(overrides)
        return payload

    def test_api_json_aligned(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload()
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["alignment"], "aligned")
        self.assertEqual(data["alignment_label"], "有对齐证据")
        self.assertEqual(data["from"]["domain"], "mail.partner.example")
        self.assertEqual(data["claims"][0]["identity_domain"], "mail.partner.example")

    def test_api_json_relaxed(self):
        resp = self.client.post(
            "/api/analyze/from-alignment",
            json=self._payload(
                headers=_msg(
                    "Authentication-Results: edge.org;\n"
                    "\tspf=pass smtp.mailfrom=partner.example"
                ),
                mode="relaxed",
            ),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["alignment"], "aligned")

    def test_api_relaxed_without_org_domain_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment",
            json=self._payload(mode="relaxed", org_domain=""),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("组织域", resp.get_json()["error"])

    def test_api_invalid_mode_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(mode="loose")
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_empty_hostlist_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment",
            json=self._payload(trusted_hosts=[]),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("名单不能为空", resp.get_json()["error"])

    def test_api_blank_headers_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(headers="   ")
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_headers_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(headers=5)
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_trusted_hosts_type_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(trusted_hosts=[1, 2])
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_org_domain_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(org_domain=5)
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_mode_wrong_type_400(self):
        resp = self.client.post(
            "/api/analyze/from-alignment", json=self._payload(mode=1)
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_default_mode_is_strict(self):
        payload = self._payload()
        del payload["mode"]
        resp = self.client.post("/api/analyze/from-alignment", json=payload)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["mode"], "strict")

    def test_api_duplicate_from_is_200_insufficient(self):
        resp = self.client.post(
            "/api/analyze/from-alignment",
            json=self._payload(
                headers=_msg(
                    "Authentication-Results: edge.org;\n"
                    "\tspf=pass smtp.mailfrom=mail.partner.example",
                    from_header=(
                        "From: a@mail.partner.example\n"
                        "From: b@attacker.example"
                    ),
                )
            ),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["alignment"], "insufficient")
        self.assertEqual(data["alignment_reason"], "from_multiple_fields")

    def test_api_form_encoded(self):
        resp = self.client.post(
            "/api/analyze/from-alignment",
            data={
                "headers": _msg(
                    "Authentication-Results: edge.org;\n"
                    "\tspf=pass smtp.mailfrom=mail.partner.example"
                ),
                "trusted_hosts": "edge.org\ngw2.org",
                "org_domain": ORG,
                "mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["alignment"], "aligned")

    def test_page_form_renders_strict(self):
        resp = self.client.post(
            "/from-alignment",
            data={
                "headers_align": SAMPLE_HEADERS_ALIGN,
                "trusted_hosts_align": SAMPLE_TRUSTED_HOSTS,
                "org_domain": SAMPLE_ORG_DOMAIN,
                "align_mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("未见对齐证据", body)
        self.assertIn("mail.partner.example", body)
        self.assertIn("smtp.mailfrom", body)

    def test_page_form_renders_relaxed(self):
        resp = self.client.post(
            "/from-alignment",
            data={
                "headers_align": SAMPLE_HEADERS_ALIGN,
                "trusted_hosts_align": SAMPLE_TRUSTED_HOSTS,
                "org_domain": SAMPLE_ORG_DOMAIN,
                "align_mode": "relaxed",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("有对齐证据", resp.get_data(as_text=True))

    def test_page_form_empty_hostlist_error_banner(self):
        resp = self.client.post(
            "/from-alignment",
            data={
                "headers_align": SAMPLE_HEADERS_ALIGN,
                "trusted_hosts_align": "  ",
                "org_domain": SAMPLE_ORG_DOMAIN,
                "align_mode": "strict",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
