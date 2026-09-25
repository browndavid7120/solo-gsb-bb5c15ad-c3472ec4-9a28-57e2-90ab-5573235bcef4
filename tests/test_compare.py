import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import compare_headers  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS, SAMPLE_HEADERS_B  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def _received(by, ip=None, date=None, frm="peer.example"):
    """构造单条 Received 字段。"""
    parts = [f"Received: from {frm}"]
    if ip:
        parts.append(f" ({frm} [{ip}])")
    parts.append(f"\n\tby {by} with ESMTP")
    if date:
        parts.append(f"; {date}")
    return "".join(parts)


def _kinds(result):
    return [row["kind"] for row in result["alignment"]["rows"]]


class AlignmentTests(unittest.TestCase):
    def test_identical_headers_all_common(self):
        headers = (
            _received("b.example", "198.51.100.1", "Wed, 23 Sep 2026 02:01:00 +0000")
            + "\n"
            + _received("a.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000")
            + "\n"
        )
        result = compare_headers(headers, headers)
        alignment = result["alignment"]
        self.assertEqual(alignment["common_count"], 2)
        self.assertEqual(alignment["added_count"], 0)
        self.assertEqual(alignment["missing_count"], 0)
        self.assertEqual(_kinds(result), ["common", "common"])

    def test_added_and_missing_nodes(self):
        # 路径顺序（发件方 -> 收件方）：
        # A: edge -> mid -> final；B: edge -> final（mid 缺失）
        headers_a = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:03:00 +0000")
            + "\n"
            + _received("mid.example", "198.51.100.1", "Wed, 23 Sep 2026 02:02:00 +0000")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:01:00 +0000")
            + "\n"
        )
        headers_b = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:03:00 +0000")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:01:00 +0000")
            + "\n"
        )
        result = compare_headers(headers_a, headers_b)
        alignment = result["alignment"]
        self.assertEqual(alignment["common_count"], 2)
        self.assertEqual(alignment["missing_count"], 1)
        self.assertEqual(alignment["added_count"], 0)
        self.assertEqual(_kinds(result), ["common", "missing", "common"])
        missing_row = result["alignment"]["rows"][1]
        self.assertEqual(missing_row["a"]["by_host"], "mid.example")
        self.assertIsNone(missing_row["b"])

    def test_repeated_same_name_nodes_use_order_preserving_alignment(self):
        # A 只有一个 smtp01 节点（对端 10.10.0.5）；B 有两个同名 smtp01 节点，
        # 全局对齐应把 A 的节点对齐到 B 中“靠后且 IP 相同”的那个，
        # 而不是首次命中靠前的（10.10.0.9）那个。
        headers_a = (
            _received(
                "out.example", "10.10.0.5", "Wed, 23 Sep 2026 02:01:00 +0000",
                frm="smtp01.corp.example",
            )
            + "\n"
            + _received(
                "smtp01.corp.example", "10.10.0.5",
                "Wed, 23 Sep 2026 02:00:10 +0000", frm="[10.10.0.5]",
            )
            + "\n"
        )
        headers_b = (
            _received(
                "out.example", "10.10.0.5", "Wed, 23 Sep 2026 02:01:00 +0000",
                frm="smtp01.corp.example",
            )
            + "\n"
            + _received(
                "smtp01.corp.example", "10.10.0.5",
                "Wed, 23 Sep 2026 02:00:12 +0000", frm="[10.10.0.5]",
            )
            + "\n"
            + _received(
                "smtp01.corp.example", "10.10.0.9",
                "Wed, 23 Sep 2026 02:00:05 +0000", frm="smtp00.corp.example",
            )
            + "\n"
        )
        result = compare_headers(headers_a, headers_b)
        rows = result["alignment"]["rows"]
        self.assertEqual(_kinds(result), ["added", "common", "common"])
        # 新增的是 B 侧最靠前、对端 IP 为 10.10.0.9 的同名节点
        self.assertEqual(rows[0]["b"]["ip"], "10.10.0.9")
        # 共有行配对的是 IP 相同的 smtp01 节点
        self.assertEqual(rows[1]["a"]["ip"], "10.10.0.5")
        self.assertEqual(rows[1]["b"]["ip"], "10.10.0.5")
        self.assertEqual(rows[1]["b"]["delay_seconds"], 7)

    def test_ip_conflict_prevents_match_even_with_same_by_host(self):
        headers_a = _received(
            "mx.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        headers_b = _received(
            "mx.example", "192.0.2.2", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        result = compare_headers(headers_a + "\n", headers_b + "\n")
        alignment = result["alignment"]
        self.assertEqual(alignment["common_count"], 0)
        self.assertEqual(alignment["missing_count"], 1)
        self.assertEqual(alignment["added_count"], 1)

    def test_case_and_trailing_dot_insensitive_host_match(self):
        headers_a = _received(
            "MX.Example.", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        headers_b = _received(
            "mx.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        result = compare_headers(headers_a + "\n", headers_b + "\n")
        self.assertEqual(result["alignment"]["common_count"], 1)

    def test_identity_less_nodes_never_match_by_time(self):
        # 两侧各有一个既无 by 也无对端 IP 的节点，且时间完全相同：
        # 没有身份的节点不允许仅凭时间配成同一跳。
        headers_a = "Received: (internal processing); Wed, 23 Sep 2026 02:00:00 +0000\n"
        headers_b = "Received: (queue run); Wed, 23 Sep 2026 02:00:00 +0000\n"
        result = compare_headers(headers_a, headers_b)
        alignment = result["alignment"]
        self.assertEqual(alignment["common_count"], 0)
        self.assertEqual(alignment["missing_count"], 1)
        self.assertEqual(alignment["added_count"], 1)

    def test_partial_identity_can_match(self):
        # A 侧只有 by 主机、B 侧 by 主机与 IP 都有：不冲突且 by 相同，可配对。
        headers_a = _received(
            "mx.example", None, "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        headers_b = _received(
            "mx.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        result = compare_headers(headers_a + "\n", headers_b + "\n")
        self.assertEqual(result["alignment"]["common_count"], 1)


class DelayCompareTests(unittest.TestCase):
    def test_common_nodes_show_both_delays_and_diff(self):
        headers_a = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:10:00 +0000")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000")
            + "\n"
        )
        headers_b = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:12:00 +0000")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000")
            + "\n"
        )
        result = compare_headers(headers_a, headers_b)
        rows = result["alignment"]["rows"]
        first, second = rows
        # 首跳：双方都无上游耗时
        self.assertEqual(first["diff_status"], "first_hop")
        self.assertIsNone(first["delay_diff_seconds"])
        # 第二跳：A 600 秒，B 720 秒，差值 +120 秒
        self.assertEqual(second["diff_status"], "ok")
        self.assertEqual(second["delay_a_seconds"], 600)
        self.assertEqual(second["delay_b_seconds"], 720)
        self.assertEqual(second["delay_diff_seconds"], 120)
        self.assertEqual(second["delay_diff_human"], "+2 分 0 秒")

    def test_invalid_time_on_either_side_is_incomparable_and_not_spliced(self):
        # A 侧中间节点时间无效：其后节点的相邻耗时不可计算，
        # 对照时不得跳过该中间节点去拼接首尾耗时。
        headers_a = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:10:00 +0000")
            + "\n"
            + _received("mid.example", "198.51.100.1", "totally-not-a-date")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000")
            + "\n"
        )
        headers_b = (
            _received("final.example", "203.0.113.1", "Wed, 23 Sep 2026 02:10:00 +0000")
            + "\n"
            + _received("mid.example", "198.51.100.1", "Wed, 23 Sep 2026 02:05:00 +0000")
            + "\n"
            + _received("edge.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000")
            + "\n"
        )
        result = compare_headers(headers_a, headers_b)
        rows = result["alignment"]["rows"]
        self.assertEqual(_kinds(result), ["common", "common", "common"])
        mid_row, final_row = rows[1], rows[2]
        # A 侧 mid 时间无效 -> 该共有节点不可比较
        self.assertIsNone(mid_row["delay_a_seconds"])
        self.assertEqual(mid_row["delay_b_seconds"], 300)
        self.assertEqual(mid_row["diff_status"], "incomparable")
        # A 侧 final 的相邻耗时同样因上游无效而不可计算（不拼接 edge->final 的 600 秒）
        self.assertIsNone(final_row["delay_a_seconds"])
        self.assertEqual(final_row["delay_b_seconds"], 300)
        self.assertEqual(final_row["diff_status"], "incomparable")
        self.assertIsNone(final_row["delay_diff_seconds"])


class ErrorTests(unittest.TestCase):
    def test_missing_received_on_one_side_is_clear_error(self):
        headers_a = _received(
            "mx.example", "192.0.2.1", "Wed, 23 Sep 2026 02:00:00 +0000"
        )
        result = compare_headers(headers_a, "Subject: no received here\n")
        self.assertIn("error", result)
        self.assertIn("B 侧", result["error"])
        self.assertEqual(result["side_errors"], {"b": "B 侧头部中未找到 Received 字段"})

    def test_missing_received_on_both_sides(self):
        result = compare_headers("Subject: x\n", "Subject: y\n")
        self.assertIn("error", result)
        self.assertEqual(set(result["side_errors"]), {"a", "b"})


class SampleCompareTests(unittest.TestCase):
    def test_sample_pair_alignment(self):
        result = compare_headers(SAMPLE_HEADERS, SAMPLE_HEADERS_B)
        alignment = result["alignment"]
        # 共有 6 跳；B 侧新增 smtp00->smtp01 一跳；A 侧 Dovecot LMTP 一跳缺失
        self.assertEqual(alignment["common_count"], 6)
        self.assertEqual(alignment["added_count"], 1)
        self.assertEqual(alignment["missing_count"], 1)
        rows = alignment["rows"]
        self.assertEqual(rows[0]["kind"], "added")
        self.assertEqual(rows[0]["b"]["ip"], "10.10.0.9")
        self.assertEqual(rows[-1]["kind"], "missing")
        self.assertEqual(rows[-1]["a"]["with_proto"], "LMTP")
        # 同名 smtp01 节点：A 侧唯一一跳对齐到 B 侧 IP 相同（10.10.0.5）的那跳
        smtp_common = rows[1]
        self.assertEqual(smtp_common["kind"], "common")
        self.assertEqual(smtp_common["a"]["by_host"], "smtp01.corp.example.net")
        self.assertEqual(smtp_common["b"]["ip"], "10.10.0.5")
        # A 侧该跳时间无效 -> 不可比较
        self.assertEqual(smtp_common["diff_status"], "incomparable")


@unittest.skipIf(create_app is None, "未安装 Flask，跳过 API 测试")
class CompareApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_compare_ok(self):
        resp = self.client.post(
            "/api/compare",
            json={"headers_a": SAMPLE_HEADERS, "headers_b": SAMPLE_HEADERS_B},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["alignment"]["common_count"], 6)
        self.assertEqual(data["alignment"]["added_count"], 1)
        self.assertEqual(data["alignment"]["missing_count"], 1)
        self.assertEqual(data["a"]["hop_count"], 7)
        self.assertEqual(data["b"]["hop_count"], 7)

    def test_api_compare_side_without_received_returns_400(self):
        resp = self.client.post(
            "/api/compare",
            json={"headers_a": SAMPLE_HEADERS, "headers_b": "Subject: none\n"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("B 侧", data["error"])
        self.assertEqual(data["side_errors"], {"b": "B 侧头部中未找到 Received 字段"})

    def test_api_compare_rejects_non_string(self):
        resp = self.client.post(
            "/api/compare", json={"headers_a": 123, "headers_b": "x"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_compare_empty_side_returns_400(self):
        resp = self.client.post(
            "/api/compare", json={"headers_a": SAMPLE_HEADERS, "headers_b": "  "}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_compare_form_page(self):
        resp = self.client.post(
            "/compare",
            data={"headers_a": SAMPLE_HEADERS, "headers_b": SAMPLE_HEADERS_B},
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("路径对照结果", html)
        self.assertIn("共有", html)
        self.assertIn("新增", html)
        self.assertIn("缺失", html)


if __name__ == "__main__":
    unittest.main()
