import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import batch_delay_analysis, split_batch_headers  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS_BATCH  # noqa: E402

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


def _path_3(d_edge, d_mid, d_final):
    """构造 edge -> mid -> final 三跳路径（书写顺序 final, mid, edge）。"""
    return (
        _received("final.example", "203.0.113.1", d_final, frm="mid.example")
        + "\n"
        + _received("mid.example", "198.51.100.10", d_mid, frm="edge.example")
        + "\n"
        + _received("edge.example", "192.0.2.10", d_edge, frm="sender.example")
        + "\n"
    )


T = "Wed, 23 Sep 2026 02:{mm:02d}:{ss:02d} +0000"


def _t(seconds_from_020000):
    total = 120 + seconds_from_020000  # 从 02:02:00 起，避免负数分钟
    return T.format(mm=total // 60, ss=total % 60)


class SplitTests(unittest.TestCase):
    def test_split_on_equals_delimiter(self):
        text = (
            "Received: by a.example; Wed, 23 Sep 2026 02:00:00 +0000\n"
            "===== 下一封邮件 =====\n"
            "Received: by b.example; Wed, 23 Sep 2026 03:00:00 +0000\n"
            "---\n"
            "Received: by c.example; Wed, 23 Sep 2026 04:00:00 +0000\n"
        )
        parts = split_batch_headers(text)
        self.assertEqual(len(parts), 3)
        self.assertIn("a.example", parts[0])
        self.assertIn("b.example", parts[1])
        self.assertIn("c.example", parts[2])

    def test_split_ignores_blank_segments_and_crlf(self):
        text = (
            "###\n\nReceived: by a.example; Wed, 23 Sep 2026 02:00:00 +0000\r\n"
            "***\r\n\r\n"
        )
        parts = split_batch_headers(text)
        self.assertEqual(len(parts), 1)
        self.assertIn("a.example", parts[0])

    def test_split_no_delimiter_returns_single(self):
        text = "Received: by a.example; Wed, 23 Sep 2026 02:00:00 +0000\n"
        parts = split_batch_headers(text)
        self.assertEqual(len(parts), 1)

    def test_split_empty(self):
        self.assertEqual(split_batch_headers(""), [])
        self.assertEqual(split_batch_headers("=====\n\n===="), [])

    def test_indented_separator_run_is_not_a_delimiter(self):
        # 以空白开头的 “---” 行是折行续行，不应被当作分隔符
        text = (
            "Received: by a.example with X\n"
            "\t--- weird folded value\n"
            "\t; Wed, 23 Sep 2026 02:00:00 +0000\n"
        )
        parts = split_batch_headers(text)
        self.assertEqual(len(parts), 1)


class AggregationTests(unittest.TestCase):
    def test_adjacent_segments_aggregated_with_median_max_and_order(self):
        # 邮件 1：edge->mid 60s，mid->final 300s
        m1 = _path_3(_t(0), _t(60), _t(360))
        # 邮件 2：edge->mid 120s，mid->final 600s
        m2 = _path_3(_t(0), _t(120), _t(720))
        # 邮件 3：edge->mid 30s，mid->final 150s
        m3 = _path_3(_t(0), _t(30), _t(180))
        result = batch_delay_analysis([m1, m2, m3])
        self.assertNotIn("error", result)
        self.assertEqual(result["message_count"], 3)
        self.assertEqual(result["analyzed_count"], 3)
        self.assertEqual(result["segment_count"], 2)
        self.assertEqual(result["sample_count"], 6)

        segments = result["segments"]
        # 从慢到快：mid->final（中位 300）排在 edge->mid（中位 60）前
        self.assertEqual(segments[0]["from"]["node"], "mid.example")
        self.assertEqual(segments[0]["to"]["node"], "final.example")
        self.assertEqual(segments[0]["sample_count"], 3)
        self.assertEqual(segments[0]["median_seconds"], 300)
        self.assertEqual(segments[0]["max_seconds"], 600)
        self.assertEqual(segments[0]["rank"], 1)
        self.assertEqual(segments[1]["from"]["node"], "edge.example")
        self.assertEqual(segments[1]["median_seconds"], 60)
        self.assertEqual(segments[1]["max_seconds"], 120)
        self.assertEqual(segments[1]["rank"], 2)

    def test_only_actual_adjacent_nodes_are_aggregated(self):
        # edge -> mid -> final：不产生 edge->final 段
        result = batch_delay_analysis([_path_3(_t(0), _t(60), _t(120))])
        keys = {(s["from"]["node"], s["to"]["node"]) for s in result["segments"]}
        self.assertEqual(keys, {("edge.example", "mid.example"),
                                ("mid.example", "final.example")})

    def test_invalid_time_and_backflow_excluded(self):
        # mid 时间无效：edge->mid 与 mid->final 均无法计算（2 个 invalid_time）
        m1 = _path_3(_t(0), "not-a-valid-date", _t(300))
        # 时间倒灌：final 早于 mid（edge->mid 60 有效；mid->final 为负，记 backflow）
        m2 = _path_3(_t(0), _t(60), _t(30))
        result = batch_delay_analysis([m1, m2])
        self.assertEqual(result["excluded"]["invalid_time"], 2)
        self.assertEqual(result["excluded"]["backflow"], 1)
        # 仅 edge->mid 段保留一个样本（60s）
        self.assertEqual(result["segment_count"], 1)
        seg = result["segments"][0]
        self.assertEqual((seg["from"]["node"], seg["to"]["node"]),
                         ("edge.example", "mid.example"))
        self.assertEqual(seg["sample_count"], 1)
        self.assertEqual(seg["median_seconds"], 60)

    def test_zero_delay_is_valid(self):
        m = _path_3(_t(0), _t(0), _t(0))
        result = batch_delay_analysis([m])
        self.assertEqual(result["excluded"]["backflow"], 0)
        self.assertEqual(result["sample_count"], 2)
        self.assertTrue(all(s["median_seconds"] == 0 for s in result["segments"]))

    def test_identity_full_known_fields_combo_is_key(self):
        # 同 by 主机、不同对端 IP：身份不同，不应合并
        headers_a = (
            _received("mx.example", "192.0.2.1", _t(300), frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9", _t(0), frm="sender.example")
            + "\n"
        )
        headers_b = (
            _received("mx.example", "192.0.2.2", _t(300), frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9", _t(0), frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([headers_a, headers_b])
        # 上游身份相同，但下游 (mx, IP) 不同 -> 两个不同的段
        self.assertEqual(result["segment_count"], 2)
        self.assertEqual(result["sample_count"], 2)
        for seg in result["segments"]:
            self.assertEqual(seg["sample_count"], 1)

    def test_identity_partial_fields_do_not_merge_with_full(self):
        # A 侧下游只有 by 无 IP；B 侧下游 by + IP：字段组合不同，不合并
        headers_a = (
            _received("mx.example", None, _t(300), frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9", _t(0), frm="sender.example")
            + "\n"
        )
        headers_b = (
            _received("mx.example", "192.0.2.1", _t(300), frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9", _t(0), frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([headers_a, headers_b])
        self.assertEqual(result["segment_count"], 2)

    def test_identity_less_segment_not_merged_but_counted(self):
        # 下游节点既无 by 也无 IP：整个区段不合并
        headers = (
            "Received: (internal queue run); Wed, 23 Sep 2026 02:05:00 +0000\n"
            + _received("edge.example", "192.0.2.10",
                        "Wed, 23 Sep 2026 02:00:00 +0000", frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([headers, headers])
        self.assertEqual(result["excluded"]["identity_less"], 2)
        self.assertEqual(result["segment_count"], 0)

    def test_same_key_repeated_within_one_mail_takes_max_nonnegative(self):
        # 退信后发件方从同一 IP 重新注入：edge->mid 同键区段出现两次
        # （30s、150s）；中间与重注入形成 mid->edge 回流段（60s）；
        # final 时间无效。
        # 投递顺序（见各 by 行）：
        # edge@(对端=sender IP) --30s--> mid --15s--> edge@(对端=mid IP)
        #   --60s--> edge@(对端=sender IP) --150s--> mid --×--> final(无时间)
        text = (
            # final（无时间，mid->final 段记 invalid_time）
            _received("final.example", "198.51.100.20", None, frm="mid.example")
            + "\n"
            # 第二次 edge->mid：150s
            + _received("mid.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:05:30 +0000", frm="edge.example")
            + "\n"
            # 重注入（延续回流段：上一跳 edge@midIP -> 本跳 edge@senderIP，60s）
            + _received("edge.example", "203.0.113.50",
                        "Wed, 23 Sep 2026 02:03:00 +0000", frm="sender.example")
            + "\n"
            # 退信回流：mid -> edge，15s（本跳 edge 的对端 IP 是 mid）
            + _received("edge.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:02:00 +0000", frm="mid.example")
            + "\n"
            # 第一次 edge->mid：30s
            + _received("mid.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:01:45 +0000", frm="edge.example")
            + "\n"
            # 首次注入（首跳，无上游段）
            + _received("edge.example", "203.0.113.50",
                        "Wed, 23 Sep 2026 02:01:15 +0000", frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([text])
        # 同键 edge@(sender IP) -> mid@(edge IP) 出现两次（30s 与 150s）
        self.assertEqual(result["duplicate_collapsed"], 1)
        self.assertEqual(result["excluded"]["invalid_time"], 1)
        edge_mid = next(
            s for s in result["segments"]
            if s["from"]["by_host"] == "edge.example"
            and s["from"]["ip"] == "203.0.113.50"
            and s["to"]["by_host"] == "mid.example"
            and s["to"]["ip"] == "198.51.100.10"
        )
        # 该邮件在该段的唯一样本取最大值 150s
        self.assertEqual(edge_mid["sample_count"], 1)
        self.assertEqual(edge_mid["median_seconds"], 150)
        # 回流段：mid -> edge@(对端=mid IP)，15s
        mid_edge = next(
            s for s in result["segments"]
            if s["from"]["by_host"] == "mid.example"
            and s["from"]["ip"] == "198.51.100.10"
            and s["to"]["by_host"] == "edge.example"
            and s["to"]["ip"] == "198.51.100.10"
        )
        self.assertEqual(mid_edge["sample_count"], 1)
        self.assertEqual(mid_edge["median_seconds"], 15)
        # 重注入过渡段：edge@(对端=mid IP) -> edge@(对端=sender IP)，60s
        edge_edge = next(
            s for s in result["segments"]
            if s["from"]["by_host"] == "edge.example"
            and s["from"]["ip"] == "198.51.100.10"
            and s["to"]["by_host"] == "edge.example"
            and s["to"]["ip"] == "203.0.113.50"
        )
        self.assertEqual(edge_edge["median_seconds"], 60)
        self.assertEqual(result["segment_count"], 3)

    def test_same_key_negative_then_positive_keeps_positive_and_counts_backflow(self):
        # 同一封内同键 edge->mid 先出现一次倒灌（-30s，排除），
        # 重新注入后再次出现且为正（150s，取作样本）。
        text = (
            _received("mid.example", "198.51.100.10",
                      "Wed, 23 Sep 2026 02:05:00 +0000", frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.50",
                        "Wed, 23 Sep 2026 02:02:30 +0000", frm="sender.example")
            + "\n"
            + _received("mid.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:01:30 +0000", frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.50",
                        "Wed, 23 Sep 2026 02:02:00 +0000", frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([text])
        self.assertEqual(result["excluded"]["backflow"], 1)
        edge_mid = next(
            s for s in result["segments"]
            if s["from"]["by_host"] == "edge.example"
            and s["to"]["by_host"] == "mid.example"
        )
        # 第一次 -30s 被排除，第二次 150s 成为该邮件唯一样本
        self.assertEqual(edge_mid["sample_count"], 1)
        self.assertEqual(edge_mid["median_seconds"], 150)
        self.assertEqual(result["duplicate_collapsed"], 0)

    def test_per_mail_sample_is_one_even_with_many_repeats(self):
        # m1（退信后从同一发件 IP 重新注入），投递顺序：
        # E(sender IP)@02:02:00 --50s--> M@02:02:50 --50s--> E(mid IP)@02:03:40
        #   --50s--> E(sender IP)@02:04:30 --100s--> M@02:06:10
        # 同键 (E@192.0.2.10 -> M) 出现两次（50s、100s），该邮件仅取 100s；
        # m2 同键样本为 40s。
        m1 = (
            _received("mid.example", "198.51.100.10",
                      "Wed, 23 Sep 2026 02:06:10 +0000", frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9",
                        "Wed, 23 Sep 2026 02:04:30 +0000", frm="sender.example")
            + "\n"
            + _received("edge.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:03:40 +0000", frm="mid.example")
            + "\n"
            + _received("mid.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:02:50 +0000", frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9",
                        "Wed, 23 Sep 2026 02:02:00 +0000", frm="sender.example")
            + "\n"
        )
        m2 = (
            _received("final.example", "203.0.113.1",
                      "Wed, 23 Sep 2026 02:15:40 +0000", frm="mid.example")
            + "\n"
            + _received("mid.example", "198.51.100.10",
                        "Wed, 23 Sep 2026 02:00:40 +0000", frm="edge.example")
            + "\n"
            + _received("edge.example", "203.0.113.9",
                        "Wed, 23 Sep 2026 02:00:00 +0000", frm="sender.example")
            + "\n"
        )
        result = batch_delay_analysis([m1, m2])
        edge_mid = next(
            s for s in result["segments"]
            if s["from"]["by_host"] == "edge.example"
            and s["from"]["ip"] == "203.0.113.9"
            and s["to"]["by_host"] == "mid.example"
        )
        # 每封邮件仅一个样本：m1 取 100（50/100 的最大），m2 为 40
        self.assertEqual(edge_mid["sample_count"], 2)
        self.assertEqual(edge_mid["median_seconds"], 70)
        self.assertEqual(edge_mid["max_seconds"], 100)
        self.assertEqual(result["duplicate_collapsed"], 1)

    def test_message_without_received_is_reported_but_others_analyzed(self):
        good = _path_3(_t(0), _t(60), _t(120))
        result = batch_delay_analysis([good, "Subject: no received\n"])
        self.assertNotIn("error", result)
        self.assertEqual(result["analyzed_count"], 1)
        self.assertEqual(result["message_count"], 2)
        self.assertEqual(result["message_errors"],
                         [{"index": 2, "error": "该头部中未找到 Received 字段"}])

    def test_all_messages_without_received_is_error(self):
        result = batch_delay_analysis(["Subject: x\n", "   ", "\n"])
        self.assertIn("error", result)
        self.assertEqual(result["analyzed_count"], 0)
        self.assertEqual(len(result["message_errors"]), 3)

    def test_empty_list_is_error(self):
        result = batch_delay_analysis([])
        self.assertIn("error", result)
        self.assertEqual(result["segment_count"], 0)


class SampleBatchTests(unittest.TestCase):
    def test_sample_batch_split_into_three(self):
        parts = split_batch_headers(SAMPLE_HEADERS_BATCH)
        self.assertEqual(len(parts), 3)

    def test_sample_batch_attribution(self):
        parts = split_batch_headers(SAMPLE_HEADERS_BATCH)
        result = batch_delay_analysis(parts)
        self.assertEqual(result["analyzed_count"], 3)
        self.assertNotIn("error", result)
        # 邮件 2 的 mid->final 倒灌 -20s；邮件 3 的 mid->final 时间无效
        self.assertEqual(result["excluded"]["backflow"], 1)
        self.assertEqual(result["excluded"]["invalid_time"], 1)
        # 邮件 3 退信重注入：edge->mid 同键两次（60s、150s），归并 1 个重复
        self.assertEqual(result["duplicate_collapsed"], 1)

        segments = result["segments"]
        # 共 3 个区段：edge->mid、mid->final（跨邮件共有），
        # 以及邮件 3 退信/重注入路径上的 mid->edge 回流段（60s）；
        # 重注入路径上两跳 by edge 的对端 IP 不同，故两个 edge 身份不同，
        # mid->edge 不构成同键重复，仅 edge->mid 归并 1 次。
        self.assertEqual(result["segment_count"], 3)
        # edge->mid：60（m1）、600（m2）、150（m3 取最大）→ 中位 150，最大 600
        edge_mid = next(
            s for s in segments
            if s["from"]["by_host"] == "edge.example"
            and s["to"]["by_host"] == "mid.example"
        )
        self.assertEqual(edge_mid["sample_count"], 3)
        self.assertEqual(edge_mid["median_seconds"], 150)
        self.assertEqual(edge_mid["max_seconds"], 600)
        # mid->final：仅 m1 的 150s 有效（m2 倒灌、m3 时间无效）
        mid_final = next(
            s for s in segments
            if s["from"]["by_host"] == "mid.example"
            and s["to"]["by_host"] == "final.example"
        )
        self.assertEqual(mid_final["sample_count"], 1)
        self.assertEqual(mid_final["median_seconds"], 150)
        # 从慢到快：edge->mid（中位 150、最大 600）以最大耗时平手领先
        self.assertEqual(segments[0]["from"]["by_host"], "edge.example")
        # 邮件 3 独有回流段 mid->edge（15s 与 60s 同键，取最大 60s）
        mid_edge = next(
            s for s in segments
            if s["from"]["by_host"] == "mid.example"
            and s["to"]["by_host"] == "edge.example"
        )
        self.assertEqual(mid_edge["sample_count"], 1)
        self.assertEqual(mid_edge["median_seconds"], 60)
        self.assertEqual(mid_edge["to"]["ip"], "203.0.113.50")


@unittest.skipIf(create_app is None, "未安装 Flask，跳过 API 测试")
class BatchApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_batch_ok(self):
        parts = split_batch_headers(SAMPLE_HEADERS_BATCH)
        resp = self.client.post("/api/batch-delays", json={"headers": parts})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["analyzed_count"], 3)
        self.assertEqual(data["segment_count"], 3)

    def test_api_batch_requires_json(self):
        resp = self.client.post(
            "/api/batch-delays",
            data={"headers": "x"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_batch_rejects_non_list(self):
        resp = self.client.post("/api/batch-delays", json={"headers": "not-a-list"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("字符串数组", resp.get_json()["error"])

    def test_api_batch_rejects_non_string_items(self):
        resp = self.client.post("/api/batch-delays", json={"headers": ["a", 123]})
        self.assertEqual(resp.status_code, 400)

    def test_api_batch_requires_at_least_two(self):
        resp = self.client.post("/api/batch-delays", json={"headers": ["Received: x"]})
        self.assertEqual(resp.status_code, 400)

    def test_api_batch_rejects_blank_items(self):
        resp = self.client.post(
            "/api/batch-delays", json={"headers": ["Received: x", "   "]}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_batch_all_without_received_is_400(self):
        resp = self.client.post(
            "/api/batch-delays", json={"headers": ["Subject: x", "Subject: y"]}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_batch_form_page(self):
        resp = self.client.post(
            "/batch-delays", data={"headers_batch": SAMPLE_HEADERS_BATCH}
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("慢段归因结果", html)
        self.assertIn("中位耗时", html)
        self.assertIn("时间倒灌", html)

    def test_batch_form_no_delimiter_single_header_still_analyzes(self):
        single = (
            "Received: by final.example; Wed, 23 Sep 2026 02:05:00 +0000\n"
            "Received: by edge.example; Wed, 23 Sep 2026 02:00:00 +0000\n"
        )
        resp = self.client.post("/batch-delays", data={"headers_batch": single})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("慢段归因结果", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
