import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing.parser import (  # noqa: E402
    analyze_headers,
    parse_header_blocks,
    parse_received_date,
)


HEADERS = """\
Received: by final.example with ESMTPS id AAA; Wed, 23 Sep 2026 10:05:00 +0800
Received: from mid.example (mid.example [203.0.113.10])
\tby final.example with ESMTP id BBB; Wed, 23 Sep 2026 10:04:00 +0800
Received: from edge.example (edge.example [198.51.100.2])
 by mid.example id CCC; Wed, 23 Sep 2026 02:03:30 +0000
Received: from no-time.example
 by edge.example with ESMTP
Received: from bad.example by edge.example id DDD; totally-not-a-date
Subject: hi
 there
Date: Wed, 23 Sep 2026 02:00:00 +0000
"""


class UnfoldingTests(unittest.TestCase):
    def test_folded_field_merges_continuation_lines(self):
        blocks = parse_header_blocks(HEADERS)
        subject = [b for b in blocks if b.name.lower() == "subject"][0]
        self.assertEqual(subject.value, "hi there")
        # 原始折行文本被保留
        self.assertIn("\n", subject.raw)

    def test_received_count_and_order_preserved(self):
        blocks = parse_header_blocks(HEADERS)
        received = [b for b in blocks if b.name.lower() == "received"]
        self.assertEqual(len(received), 5)
        self.assertTrue(received[0].value.startswith("by final.example"))

    def test_mbox_separator_and_body_ignored(self):
        raw = (
            "From sender@example.com Wed Sep 23 02:00:00 2026\n"
            "Received: by a.example id 1; Wed, 23 Sep 2026 02:00:00 +0000\n"
            "\n"
            "This is the body, not a header\n"
        )
        blocks = parse_header_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].name.lower(), "received")


class DateParseTests(unittest.TestCase):
    def test_rfc2822_with_offset(self):
        dt, naive = parse_received_date("Wed, 23 Sep 2026 10:04:00 +0800")
        self.assertIsNotNone(dt)
        self.assertFalse(naive)
        self.assertEqual(dt.utcoffset().total_seconds(), 0)
        self.assertEqual(dt.strftime("%H:%M:%S"), "02:04:00")

    def test_naive_date_assumed_utc(self):
        dt, naive = parse_received_date("23 Sep 2026 02:03:30")
        self.assertIsNotNone(dt)
        self.assertTrue(naive)

    def test_invalid_date(self):
        dt, naive = parse_received_date("totally-not-a-date")
        self.assertIsNone(dt)
        self.assertFalse(naive)

    def test_iso_format_with_z(self):
        dt, naive = parse_received_date("2026-09-23T02:03:30Z")
        self.assertIsNotNone(dt)
        self.assertFalse(naive)


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_headers(HEADERS)

    def test_path_is_reversed_and_timed_first(self):
        path = self.result["path"]
        self.assertEqual(self.result["hop_count"], 5)
        # 最早生成的（no-time / bad 两跳之一在最前），final.example 最后
        self.assertEqual(path[-1]["by_host"], "final.example")

    def test_delays_between_adjacent_timed_nodes(self):
        # 路径顺序：bad(无时间) -> no-time(无时间) -> edge 02:03:30
        #          -> final 入口 02:04:00 -> final 投递 02:05:00
        by_final_esmtp = [
            h for h in self.result["path"] if h["id"] == "BBB"
        ][0]
        self.assertEqual(by_final_esmtp["delay_seconds"], 30)
        final = [h for h in self.result["path"] if h["id"] == "AAA"][0]
        self.assertEqual(final["delay_seconds"], 60)
        self.assertEqual(self.result["total_span_seconds"], 90)

    def test_missing_time_node_still_listed_with_warn(self):
        no_time = [
            h for h in self.result["path"] if h["from_host"] == "no-time.example"
        ][0]
        self.assertIsNone(no_time["time_utc"])
        self.assertTrue(any("缺少时间" in a["message"] for a in no_time["anomalies"]))
        self.assertIsNone(no_time["delay_seconds"])

    def test_unparseable_time_is_error_and_raw_kept(self):
        bad = [h for h in self.result["path"] if h["from_host"] == "bad.example"][0]
        self.assertIsNone(bad["time_utc"])
        self.assertEqual(bad["date_raw"], "totally-not-a-date")
        self.assertTrue(any(a["level"] == "error" for a in bad["anomalies"]))
        self.assertIn("totally-not-a-date", bad["raw"])

    def test_counts(self):
        self.assertEqual(self.result["timed_count"], 3)
        self.assertEqual(self.result["missing_count"], 2)
        self.assertEqual(self.result["error_count"], 1)

    def test_summary_extracts_folded_subject(self):
        self.assertEqual(self.result["summary"]["Subject"], "hi there")

    def test_ip_extraction(self):
        mid = [h for h in self.result["path"] if h["id"] == "BBB"][0]
        self.assertEqual(mid["ip"], "203.0.113.10")
        edge = [h for h in self.result["path"] if h["id"] == "CCC"][0]
        self.assertEqual(edge["ip"], "198.51.100.2")


class ClockSkewTests(unittest.TestCase):
    def test_negative_delay_flags_warning(self):
        headers = (
            "Received: by b.example id 2; Wed, 23 Sep 2026 02:05:00 +0000\n"
            "Received: from a.example by b.example id 1; "
            "Wed, 23 Sep 2026 02:06:00 +0000\n"
        )
        result = analyze_headers(headers)
        final = result["path"][-1]
        self.assertEqual(final["delay_seconds"], -60)
        self.assertTrue(
            any("时钟偏移" in a["message"] for a in final["anomalies"])
        )


class IpAndTzTests(unittest.TestCase):
    def test_postfix_ipv6_prefix(self):
        headers = (
            "Received: from v6.example (v6.example [IPv6:2001:db8::1])\n"
            "\tby mx.example with ESMTP; Wed, 23 Sep 2026 02:00:00 +0000\n"
        )
        result = analyze_headers(headers)
        self.assertEqual(result["path"][0]["ip"], "2001:db8::1")

    def test_bare_ipv6_in_brackets(self):
        headers = (
            "Received: from h.example ([2001:db8::2]) by mx.example; "
            "Wed, 23 Sep 2026 02:00:00 +0000\n"
        )
        result = analyze_headers(headers)
        self.assertEqual(result["path"][0]["ip"], "2001:db8::2")

    def test_naive_timestamp_warns_but_still_timed(self):
        headers = (
            "Received: by mx.example; Wed, 23 Sep 2026 02:00:00\n"
        )
        result = analyze_headers(headers)
        hop = result["path"][0]
        self.assertIsNotNone(hop["time_utc"])
        self.assertTrue(hop["naive_assumed_utc"])
        self.assertEqual(result["timed_count"], 1)
        self.assertTrue(
            any("时区" in a["message"] for a in hop["anomalies"])
        )

    def test_extreme_year_rejected(self):
        headers = "Received: by mx.example; Wed, 23 Sep 9999 02:00:00 +0000\n"
        result = analyze_headers(headers)
        self.assertIsNone(result["path"][0]["time_utc"])
        self.assertEqual(result["error_count"], 1)


if __name__ == "__main__":
    unittest.main()
