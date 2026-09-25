import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import build_share_report  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def _received(frm, by, ip=None, date=None):
    """构造单条 Received 字段（by 在前的实际顺序无关，解析器会反转）。"""
    parts = [f"Received: from {frm}"]
    if ip:
        parts.append(f" ({frm} [{ip}])")
    parts.append(f"\n\tby {by} with ESMTP id SECRET-ID")
    if date:
        parts.append(f"; {date}")
    return "".join(parts)


# 投递顺序（Received 逆序书写）：edge(10.0.0.1) -> mid(10.0.0.2) -> final(10.0.0.3)
HEADERS = (
    _received("mid.example", "final.example", "10.0.0.2",
              "Wed, 23 Sep 2026 02:03:00 +0000")
    + "\n"
    + _received("edge.example", "mid.example", "10.0.0.1",
                "Wed, 23 Sep 2026 02:02:00 +0000")
    + "\n"
    + _received("client.example", "edge.example", "10.0.0.3",
                "Wed, 23 Sep 2026 02:01:00 +0000")
    + "\n"
    + "Subject: secret subject\nMessage-ID: <secret@example.com>\n"
)

ALLOWED_ROW_KEYS = {
    "path_index",
    "node",
    "from_host",
    "ip",
    "time_utc",
    "delay_from",
    "delay_seconds",
    "delay_human",
    "anomalies",
}
ALLOWED_TOP_KEYS = {"host_aliases", "ip_aliases", "path"}
ALLOWED_ANOMALY_KEYS = {"level", "message"}


class ShareReportTests(unittest.TestCase):
    def test_aliases_assigned_in_delivery_order(self):
        report = build_share_report(HEADERS)
        rows = report["path"]
        self.assertEqual([r["path_index"] for r in rows], [1, 2, 3])
        # 别名按投递顺序、每跳“先节点后来源”注册：
        # 首跳 node=edge=H1, from=client=H2；次跳 node=mid=H3；末跳 node=final=H4
        self.assertEqual(rows[0]["node"], "H1")          # edge
        self.assertEqual(rows[0]["from_host"], "H2")     # client
        self.assertEqual(rows[0]["ip"], "IP1")
        self.assertEqual(rows[1]["node"], "H3")          # mid
        self.assertEqual(rows[1]["from_host"], "H1")     # 来源即上一节点 edge
        self.assertEqual(rows[1]["ip"], "IP2")
        self.assertEqual(rows[2]["node"], "H4")          # final
        self.assertEqual(rows[2]["from_host"], "H3")
        self.assertEqual(rows[2]["ip"], "IP3")
        self.assertEqual(report["host_aliases"], ["H1", "H2", "H3", "H4"])
        self.assertEqual(report["ip_aliases"], ["IP1", "IP2", "IP3"])

    def test_delay_from_matches_previous_node_alias(self):
        report = build_share_report(HEADERS)
        first, second, third = report["path"]
        self.assertIsNone(first["delay_from"])
        self.assertEqual(second["node"], "H3")
        self.assertEqual(second["delay_from"], "H1")
        self.assertEqual(second["delay_seconds"], 60.0)
        self.assertEqual(third["delay_from"], "H3")

    def test_same_value_keeps_one_alias_across_labels(self):
        report = build_share_report(SAMPLE_HEADERS)
        # 首跳 from 为 [10.10.0.5]（方括号 IP），与解析出的对端 IP 同源，
        # 次跳的对端 IP 同为 10.10.0.5：都应是同一个 IP 别名。
        first, second = report["path"][0], report["path"][1]
        self.assertEqual(first["from_host"], first["ip"])
        self.assertEqual(second["ip"], first["ip"])
        # 首跳节点 smtp01 与次跳来源 smtp01 是同一主机名：同一 H 别名
        self.assertEqual(first["node"], second["from_host"])
        # 末两跳同主机 mailbox.final.example：node 别名相同
        self.assertEqual(report["path"][-1]["node"], report["path"][-2]["node"])

    def test_host_alias_case_and_dot_insensitive(self):
        headers = (
            "Received: by mx.example with ESMTP; Wed, 23 Sep 2026 02:02:00 +0000\n"
            "Received: from mx.example by relay.example with ESMTP; "
            "Wed, 23 Sep 2026 02:01:00 +0000\n"
            "Received: by Relay.Example. with ESMTP; "
            "Wed, 23 Sep 2026 02:00:00 +0000\n"
        )
        report = build_share_report(headers)
        # 投递顺序：首跳 Relay.Example.（规范化 relay.example = H1）
        # -> relay.example（同一 H1）-> mx.example（H2）
        self.assertEqual(report["host_aliases"], ["H1", "H2"])
        first, second, third = report["path"]
        self.assertEqual(first["node"], "H1")
        self.assertEqual(second["node"], "H1")
        self.assertEqual(second["from_host"], "H2")
        self.assertEqual(third["node"], "H2")
        self.assertIsNone(third["from_host"])

    def test_bracketed_ip_from_host_shares_ip_alias(self):
        headers = (
            "Received: from [10.20.30.40] by mx.example with ESMTP; "
            "Wed, 23 Sep 2026 02:01:00 +0000\n"
        )
        report = build_share_report(headers)
        row = report["path"][0]
        self.assertIsNotNone(row["ip"])
        self.assertEqual(row["from_host"], row["ip"])
        self.assertTrue(row["from_host"].startswith("IP"))
        self.assertEqual(report["host_aliases"], ["H1"])  # 仅 mx 一个主机名

    def test_missing_identity_and_time_remain_empty(self):
        # 投递顺序反转后：完全无身份的一跳为首跳
        headers = (
            "Received: by mx.example with ESMTP; totally-not-a-date\n"
            "Received: with ESMTP\n"
        )
        report = build_share_report(headers)
        first, second = report["path"]
        self.assertIsNone(first["node"])
        self.assertIsNone(first["from_host"])
        self.assertIsNone(first["ip"])
        self.assertIsNone(first["time_utc"])
        self.assertIsNone(first["delay_seconds"])
        self.assertEqual(second["node"], "H1")
        self.assertIsNone(second["time_utc"])
        self.assertTrue(
            any(a["level"] == "error" for a in second["anomalies"])
        )

    def test_report_is_whitelisted_and_anon(self):
        report = build_share_report(HEADERS)
        self.assertEqual(set(report.keys()), ALLOWED_TOP_KEYS)
        blob = json.dumps(report, ensure_ascii=False)
        for secret in (
            "edge.example",
            "mid.example",
            "final.example",
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "SECRET-ID",
            "secret subject",
            "secret@example.com",
        ):
            self.assertNotIn(secret, blob)
        for row in report["path"]:
            self.assertEqual(set(row.keys()), ALLOWED_ROW_KEYS)
            for anomaly in row["anomalies"]:
                self.assertEqual(set(anomaly.keys()), ALLOWED_ANOMALY_KEYS)

    def test_no_received_returns_error(self):
        report = build_share_report("Subject: hello\nFrom: a@b.c\n")
        self.assertIn("error", report)
        self.assertNotIn("path", report)


@unittest.skipIf(create_app is None, "未安装 Flask")
class ShareApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_share_success(self):
        resp = self.client.post(
            "/api/analyze/share",
            json={"headers": HEADERS},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(set(data.keys()), ALLOWED_TOP_KEYS)
        self.assertEqual(data["path"][0]["node"], "H1")

    def test_api_share_no_received_returns_400(self):
        resp = self.client.post(
            "/api/analyze/share", json={"headers": "Subject: hi\n"}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_share_empty_returns_400(self):
        resp = self.client.post("/api/analyze/share", json={"headers": "   "})
        self.assertEqual(resp.status_code, 400)

    def test_api_share_non_string_returns_400(self):
        resp = self.client.post("/api/analyze/share", json={"headers": 123})
        self.assertEqual(resp.status_code, 400)

    def test_api_share_oversize_returns_400(self):
        app = create_app()
        app.config["MAX_INPUT_BYTES"] = 64
        client = app.test_client()
        resp = client.post(
            "/api/analyze/share",
            json={"headers": "Received: " + "x" * 200},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("上限", resp.get_json()["error"])

    def test_api_share_anon_against_sample(self):
        resp = self.client.post(
            "/api/analyze/share",
            data={"headers": SAMPLE_HEADERS},
        )
        self.assertEqual(resp.status_code, 200)
        blob = resp.get_data(as_text=True)
        for secret in (
            "final.example",
            "provider.example",
            "198.51.100.10",
            "10.10.0.5",
            "Message-ID",
        ):
            self.assertNotIn(secret, blob)

    def test_index_page_has_share_button(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("下载脱敏报告", html)
        self.assertIn("/api/analyze/share", html)


if __name__ == "__main__":
    unittest.main()
