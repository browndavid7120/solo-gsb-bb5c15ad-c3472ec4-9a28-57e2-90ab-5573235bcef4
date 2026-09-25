import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import analyze_trust_boundary, parse_trusted_hosts  # noqa: E402
from mailtrace.parsing.sample import (  # noqa: E402
    SAMPLE_HEADERS_TRUST,
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


# 头部自上而下（书写顺序）：
#   edge.org -> gw2.org -> relay.out -> gw2.org(再次出现) -> sender.out
HEADERS = "\n".join(
    [
        _received("gw2.org", "edge.org", "10.0.0.2"),
        _received("partner.example", "gw2.org", "203.0.113.55"),
        _received("relay.out", "relay.out", "198.51.100.9"),
        _received("sender.out", "gw2.org", "198.51.100.8"),
        _received("sender.out", "sender.out", "192.0.2.5"),
        "Subject: hi\n",
    ]
)
HOSTS = ["edge.org", "gw2.org"]


class ParseHostsTests(unittest.TestCase):
    def test_string_splits_on_lines_commas_whitespace(self):
        ordered, hosts = parse_trusted_hosts(" a.org\nB.ORG, c.org  d.org")
        self.assertEqual(ordered, ["a.org", "b.org", "c.org", "d.org"])
        self.assertEqual(hosts, {"a.org", "b.org", "c.org", "d.org"})

    def test_case_and_trailing_dot_ignored_and_dedup(self):
        ordered, hosts = parse_trusted_hosts(["GW2.ORG.", "gw2.org", "Edge.Org"])
        self.assertEqual(ordered, ["gw2.org", "edge.org"])
        self.assertEqual(hosts, {"gw2.org", "edge.org"})

    def test_list_of_strings(self):
        ordered, hosts = parse_trusted_hosts(["edge.org", "gw2.org"])
        self.assertEqual(ordered, ["edge.org", "gw2.org"])

    def test_blank_tokens_ignored(self):
        ordered, hosts = parse_trusted_hosts("  \n ,  \t")
        self.assertEqual(ordered, [])
        self.assertEqual(hosts, set())

    def test_non_string_items_raise(self):
        with self.assertRaises(TypeError):
            parse_trusted_hosts(["ok.org", 5])
        with self.assertRaises(TypeError):
            parse_trusted_hosts(123)


class TrustBoundaryTests(unittest.TestCase):
    def test_empty_hostlist_is_input_error(self):
        result = analyze_trust_boundary(HEADERS, "  \n, ")
        self.assertIn("error", result)
        self.assertNotIn("hops", result)

    def test_consecutive_prefix_trusted_then_boundary(self):
        result = analyze_trust_boundary(HEADERS, HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["untrusted_count"], 3)
        hops = result["hops"]
        self.assertEqual([h["top_index"] for h in hops], [1, 2, 3, 4, 5])
        self.assertTrue(hops[0]["trusted"])
        self.assertTrue(hops[1]["trusted"])
        # 边界 = 第 3 跳
        self.assertEqual(result["boundary"]["top_index"], 3)
        self.assertEqual(result["boundary"]["reason"], "not_listed")
        self.assertTrue(hops[2]["is_boundary"])
        self.assertFalse(hops[2]["trusted"])

    def test_no_reentry_after_boundary(self):
        result = analyze_trust_boundary(HEADERS, HOSTS)
        hops = result["hops"]
        # 第 4 跳 by=gw2.org 再次命中名单，但已在边界之外
        hop4 = hops[3]
        self.assertTrue(hop4["by_listed"])
        self.assertTrue(hop4["beyond_boundary"])
        self.assertTrue(hop4["reentry_listed"])
        self.assertFalse(hop4["trusted"])
        # 第 5 跳
        self.assertFalse(hops[4]["trusted"])

    def test_last_trusted_hop_is_handoff_point(self):
        result = analyze_trust_boundary(HEADERS, HOSTS)
        handoff = result["last_trusted_hop"]
        self.assertEqual(handoff["top_index"], 2)
        self.assertEqual(handoff["by_host"], "gw2.org")
        self.assertEqual(handoff["from_host"], "partner.example")
        self.assertEqual(handoff["ip"], "203.0.113.55")

    def test_boundary_missing_by(self):
        raw = "\n".join(
            [
                _received("gw2.org", "edge.org", "10.0.0.2"),
                # 缺少 by 的 Received（解析器仍会列出该跳）
                "Received: from mystery.example; Thu, 24 Sep 2026 02:59:00 +0000",
                _received("x.out", "gw2.org"),
            ]
        )
        result = analyze_trust_boundary(raw, HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 1)
        self.assertEqual(result["boundary"]["top_index"], 2)
        self.assertEqual(result["boundary"]["reason"], "missing_by")
        self.assertTrue(result["hops"][1]["is_boundary"])
        # 第 3 跳即使 by=gw2.org 命中也不可信
        self.assertFalse(result["hops"][2]["trusted"])
        self.assertTrue(result["hops"][2]["reentry_listed"])

    def test_top_miss_is_untrusted_top(self):
        result = analyze_trust_boundary(HEADERS, ["only-other.org"])
        self.assertEqual(result["status"], "untrusted_top")
        self.assertEqual(result["trusted_count"], 0)
        self.assertIsNone(result["last_trusted_hop"])
        self.assertEqual(result["boundary"]["top_index"], 1)
        self.assertEqual(result["untrusted_count"], 5)
        for hop in result["hops"]:
            self.assertFalse(hop["trusted"])

    def test_top_missing_by_is_untrusted_top(self):
        raw = "Received: from mystery.example; Thu, 24 Sep 2026 02:59:00 +0000\n"
        result = analyze_trust_boundary(raw, HOSTS)
        self.assertEqual(result["status"], "untrusted_top")
        self.assertEqual(result["boundary"]["reason"], "missing_by")

    def test_no_received(self):
        result = analyze_trust_boundary("Subject: hi\nFrom: a@b\n", HOSTS)
        self.assertEqual(result["status"], "no_received")
        self.assertIsNone(result["boundary"])
        self.assertEqual(result["hops"], [])
        self.assertEqual(result["trusted_count"], 0)
        self.assertIn("未找到 Received", result["message"])

    def test_all_trusted_no_boundary(self):
        raw = "\n".join(
            [
                _received("gw2.org", "edge.org"),
                _received("mail.corp", "gw2.org"),
            ]
        )
        result = analyze_trust_boundary(raw, HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertIsNone(result["boundary"])
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["untrusted_count"], 0)
        # 全部可信时“最后可信跳”是最下方一跳
        self.assertEqual(result["last_trusted_hop"]["top_index"], 2)

    def test_hostname_case_and_trailing_dot(self):
        result = analyze_trust_boundary(HEADERS, "EDGE.ORG.\n Gw2.Org")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["trusted_hosts"], ["edge.org", "gw2.org"])

    def test_string_hostlist_with_commas(self):
        result = analyze_trust_boundary(HEADERS, "edge.org, gw2.org")
        self.assertEqual(result["trusted_count"], 2)

    def test_sample_headers_handoff(self):
        result = analyze_trust_boundary(SAMPLE_HEADERS_TRUST, SAMPLE_TRUSTED_HOSTS)
        self.assertEqual(result["status"], "established")
        self.assertEqual(result["trusted_count"], 2)
        self.assertEqual(result["boundary"]["top_index"], 3)
        handoff = result["last_trusted_hop"]
        self.assertEqual(handoff["from_host"], "gateway.partner.example")
        self.assertEqual(handoff["ip"], "203.0.113.55")
        # 第 4 跳 by 再次命中名单：明确不重新接入
        self.assertTrue(result["hops"][3]["reentry_listed"])
        self.assertFalse(result["hops"][3]["trusted"])

    def test_path_index_cross_reference(self):
        result = analyze_trust_boundary(HEADERS, HOSTS)
        # 头部第 1 跳 = 投递方向最后一跳
        self.assertEqual(result["hops"][0]["path_index"], 5)
        self.assertEqual(result["hops"][-1]["path_index"], 1)


@unittest.skipIf(create_app is None, "Flask 未安装")
class TrustApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_json_established(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": HEADERS, "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "established")
        self.assertEqual(data["boundary"]["top_index"], 3)

    def test_api_empty_hostlist_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": HEADERS, "trusted_hosts": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("名单不能为空", resp.get_json()["error"])

    def test_api_top_miss_is_200(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": HEADERS, "trusted_hosts": ["nope.org"]},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "untrusted_top")

    def test_api_no_received_is_200(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": "Subject: hi\n", "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "no_received")

    def test_api_blank_headers_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": "   ", "trusted_hosts": HOSTS},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_bad_trusted_hosts_type_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": HEADERS, "trusted_hosts": [1, 2]},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_trusted_hosts_wrong_scalar_type_400(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            json={"headers": HEADERS, "trusted_hosts": 9},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_form_encoded(self):
        resp = self.client.post(
            "/api/analyze/trust-boundary",
            data={"headers": HEADERS, "trusted_hosts": "edge.org\ngw2.org"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["trusted_count"], 2)

    def test_page_form_renders(self):
        resp = self.client.post(
            "/trust-boundary",
            data={"headers_trust": HEADERS, "trusted_hosts": "edge.org\ngw2.org"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("可信边界", body)
        self.assertIn("外部交接点", body)
        self.assertIn("203.0.113.55", body)

    def test_page_form_empty_hostlist_error_banner(self):
        resp = self.client.post(
            "/trust-boundary",
            data={"headers_trust": HEADERS, "trusted_hosts": "  "},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("名单不能为空", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
