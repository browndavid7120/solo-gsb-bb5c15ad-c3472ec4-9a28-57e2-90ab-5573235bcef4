import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import audit_dkim_coverage  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS_DKIM  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def dkim(h="From:To:Subject:Date", d="example.com", s="sel", extra_tags=""):
    """构造一条单行 DKIM-Signature。"""
    tags = f"v=1; a=rsa-sha256; d={d}; s={s};"
    if h is not None:
        tags += f" h={h};"
    if extra_tags:
        tags += " " + extra_tags
    tags += " b=c2ln"
    return f"DKIM-Signature: {tags}\n"


BASE_TAIL = (
    "Received: from a.example by b.example; Thu, 24 Sep 2026 02:01:00 +0000\n"
    "Date: Thu, 24 Sep 2026 02:00:00 +0000\n"
    "From: Sender <sender@example.com>\n"
    "To: User <user@final.example>\n"
    "Subject: hello\n"
)


class NoSignatureTests(unittest.TestCase):
    def test_no_dkim_returns_none_status(self):
        result = audit_dkim_coverage(BASE_TAIL)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["status_label"], "无 DKIM 签名")
        self.assertEqual(result["signature_count"], 0)
        self.assertEqual(result["anomaly_count"], 0)
        self.assertEqual(result["signatures"], [])
        self.assertIn("没有 DKIM-Signature", result["notice"])

    def test_dkim_after_body_ignored_is_none(self):
        result = audit_dkim_coverage("Subject: hi\n\n" + dkim())
        self.assertEqual(result["status"], "none")


class BasicCoverageTests(unittest.TestCase):
    def test_simple_full_coverage(self):
        result = audit_dkim_coverage(dkim() + BASE_TAIL)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["signature_count"], 1)
        sig = result["signatures"][0]
        self.assertEqual(sig["status"], "ok")
        self.assertEqual(sig["field_position"], 1)
        self.assertEqual(sig["domain"], "example.com")
        self.assertEqual(sig["selector"], "sel")
        self.assertEqual(sig["h_count"], 4)
        self.assertEqual(sig["matched_count"], 4)
        self.assertEqual(sig["unmatched_count"], 0)
        self.assertEqual(sig["issues"], [])
        # h= 顺序保留
        self.assertEqual(
            [item["name"] for item in sig["h_results"]],
            ["From", "To", "Subject", "Date"],
        )
        # 全部核心字段被覆盖
        self.assertEqual(sig["uncovered_core"], [])
        # 字段位置：DKIM 之后依次是 Received(2) Date(3) From(4) To(5) Subject(6)
        positions = {item["name"]: item["field_position"] for item in sig["h_results"]}
        self.assertEqual(positions["From"], 4)
        self.assertEqual(positions["To"], 5)
        self.assertEqual(positions["Subject"], 6)
        self.assertEqual(positions["Date"], 3)

    def test_header_and_h_names_case_insensitive(self):
        raw = (
            "dkim-signature: v=1; d=e.com; s=s; h=from:TO:SubJeCt:DATE; b=x\n"
            + BASE_TAIL
        )
        result = audit_dkim_coverage(raw)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(all(i["matched"] for i in result["signatures"][0]["h_results"]))

    def test_folded_h_list_is_unfolded(self):
        raw = (
            "DKIM-Signature: v=1; d=e.com; s=s;\n"
            "\th=From:To:Subject\n"
            "\t:Date; b=x\n"
            + BASE_TAIL
        )
        result = audit_dkim_coverage(raw)
        sig = result["signatures"][0]
        self.assertEqual(sig["matched_count"], 4)
        self.assertIn("\n", sig["raw"])

    def test_notice_does_not_claim_authenticity(self):
        result = audit_dkim_coverage(dkim() + BASE_TAIL)
        self.assertIn("不", result["notice"])
        self.assertIn("签名真伪", result["notice"])


class BottomUpDuplicateTests(unittest.TestCase):
    def test_duplicate_h_name_matches_distinct_bottom_up(self):
        # 两个 From 副本：注入副本（位置靠后/顶部）与原始副本（位置更靠下）
        raw = (
            dkim(h="From:From")
            + "From: injected@evil.example\n"
            + BASE_TAIL
        )
        sig = audit_dkim_coverage(raw)["signatures"][0]
        items = sig["h_results"]
        self.assertEqual([i["name"] for i in items], ["From", "From"])
        # 第一项自底部向上命中更靠下的原始 From（DKIM 之后：From 注入=2,
        # Received=3, Date=4, From=5 ...），第二项命中注入副本
        self.assertTrue(all(i["matched"] for i in items))
        self.assertNotEqual(items[0]["field_position"], items[1]["field_position"])
        self.assertGreater(items[0]["field_position"], items[1]["field_position"])
        self.assertIn("sender@example.com", items[0]["value"])
        self.assertIn("injected@evil.example", items[1]["value"])
        # 两个 From 都被占用 -> 无未覆盖 From 副本
        self.assertEqual(
            [f for f in sig["uncovered_core"] if f["field"] == "From"], []
        )

    def test_single_h_name_leaves_injected_copy_uncovered(self):
        raw = (
            dkim(h="From:To:Subject:Date")
            + "From: injected@evil.example\n"
            + BASE_TAIL
        )
        sig = audit_dkim_coverage(raw)["signatures"][0]
        # h= 中的 From 自底部向上命中原始 From，顶部注入副本未被覆盖
        uncovered_from = [f for f in sig["uncovered_core"] if f["field"] == "From"]
        self.assertEqual(len(uncovered_from), 1)
        self.assertIn("injected@evil.example", uncovered_from[0]["value"])

    def test_more_h_occurrences_than_real_fields_leaves_unmatched(self):
        raw = dkim(h="From:From:From") + BASE_TAIL
        sig = audit_dkim_coverage(raw)["signatures"][0]
        self.assertEqual(sig["matched_count"], 1)
        self.assertEqual(sig["unmatched_count"], 2)
        self.assertEqual([u["list_index"] for u in sig["unmatched"]], [2, 3])
        self.assertTrue(all(u["name"] == "From" for u in sig["unmatched"]))

    def test_duplicate_field_names_not_merged_as_set(self):
        # h= 中 Received 出现 3 次，但只有 2 个实际副本
        raw = (
            dkim(h="Received:Received:Received")
            + "Received: from c by d; Thu, 24 Sep 2026 02:02:00 +0000\n"
            + BASE_TAIL
        )
        sig = audit_dkim_coverage(raw)["signatures"][0]
        self.assertEqual([i["matched"] for i in sig["h_results"]],
                         [True, True, False])


class UnmatchedAndUncoveredTests(unittest.TestCase):
    def test_unknown_h_item_unmatched(self):
        result = audit_dkim_coverage(dkim(h="From:X-Nope") + BASE_TAIL)
        sig = result["signatures"][0]
        self.assertEqual(sig["matched_count"], 1)
        self.assertEqual(sig["unmatched_count"], 1)
        u = sig["unmatched"][0]
        self.assertEqual(u["list_index"], 2)
        self.assertEqual(u["name"], "X-Nope")
        # 有未匹配项但 h= 本身存在且非空 -> 不算异常
        self.assertEqual(sig["status"], "ok")
        self.assertEqual(sig["issues"], [])

    def test_uncovered_to_and_date_listed(self):
        result = audit_dkim_coverage(dkim(h="From:Subject") + BASE_TAIL)
        sig = result["signatures"][0]
        uncovered = {(f["field"], f["position"]) for f in sig["uncovered_core"]}
        fields = {f["field"] for f in sig["uncovered_core"]}
        self.assertIn("To", fields)
        self.assertIn("Date", fields)
        self.assertNotIn("From", fields)
        self.assertNotIn("Subject", fields)
        # 位置与值
        to_field = next(f for f in sig["uncovered_core"] if f["field"] == "To")
        self.assertIn("user@final.example", to_field["value"])
        self.assertGreaterEqual(to_field["position"], 1)

    def test_empty_colon_item_in_h_list(self):
        result = audit_dkim_coverage(dkim(h="From::To") + BASE_TAIL)
        sig = result["signatures"][0]
        self.assertEqual([i["name"] for i in sig["h_results"]],
                         ["From", "", "To"])
        empty = sig["h_results"][1]
        self.assertFalse(empty["matched"])
        self.assertIsNone(empty["field_position"])
        self.assertEqual(sig["unmatched"][0]["list_index"], 2)


class MissingAndEmptyHTests(unittest.TestCase):
    def test_missing_h_is_anomaly(self):
        result = audit_dkim_coverage(dkim(h=None) + BASE_TAIL)
        sig = result["signatures"][0]
        self.assertEqual(sig["status"], "anomaly")
        self.assertEqual(result["status"], "anomaly")
        self.assertEqual(result["anomaly_count"], 1)
        codes = [i["code"] for i in sig["issues"]]
        self.assertIn("missing_h", codes)
        self.assertFalse(sig["h_present"])

    def test_empty_h_is_anomaly(self):
        result = audit_dkim_coverage(dkim(h="") + BASE_TAIL)
        sig = result["signatures"][0]
        self.assertEqual(sig["status"], "anomaly")
        self.assertIn("empty_h", [i["code"] for i in sig["issues"]])
        self.assertEqual(sig["h_count"], 1)  # 切分出一个空串
        self.assertEqual(sig["matched_count"], 0)

    def test_whitespace_only_h_is_anomaly(self):
        result = audit_dkim_coverage(dkim(h="   ") + BASE_TAIL)
        self.assertEqual(result["signatures"][0]["status"], "anomaly")

    def test_duplicate_h_tag_is_anomaly(self):
        raw = (
            "DKIM-Signature: v=1; d=e.com; s=s; h=From; h=To; b=x\n"
            + BASE_TAIL
        )
        sig = audit_dkim_coverage(raw)["signatures"][0]
        self.assertIn("duplicate_h", [i["code"] for i in sig["issues"]])
        self.assertEqual(sig["status"], "anomaly")


class MultipleSignatureTests(unittest.TestCase):
    def test_signatures_audited_independently(self):
        # 两条签名：一条覆盖 From/To，一条只覆盖 From；使用集合互不影响
        raw = (
            dkim(h="From:To", d="a.example")
            + dkim(h="From", d="b.example")
            + BASE_TAIL
        )
        result = audit_dkim_coverage(raw)
        self.assertEqual(result["signature_count"], 2)
        self.assertEqual([s["index"] for s in result["signatures"]], [1, 2])
        self.assertEqual([s["domain"] for s in result["signatures"]],
                         ["a.example", "b.example"])
        s1, s2 = result["signatures"]
        # 两条签名各自独立匹配 From，互不占用
        self.assertEqual(s1["matched_count"], 2)
        self.assertEqual(s2["matched_count"], 1)
        self.assertEqual(
            sorted(f["field"] for f in s2["uncovered_core"]),
            ["Date", "Subject", "To"],
        )

    def test_countersignature_matches_other_dkim_not_self(self):
        # 顶部签名 h= 含 DKIM-Signature，应匹配下方另一条，而非自身
        raw = (
            dkim(h="DKIM-Signature:From:Subject:To:Date", d="forwarder.example")
            + dkim(h="From:To:Subject:Date", d="origin.example")
            + BASE_TAIL
        )
        top, bottom = audit_dkim_coverage(raw)["signatures"]
        dkim_item = top["h_results"][0]
        self.assertTrue(dkim_item["matched"])
        # 命中第 2 个字段（下方原始签名），不是第 1 个（自身）
        self.assertEqual(dkim_item["field_position"], 2)
        # 下方签名若 h= 不含 dkim-signature，则无此项
        self.assertFalse(
            any(i["name"].lower() == "dkim-signature" for i in bottom["h_results"])
        )

    def test_one_bad_signature_marks_overall_anomaly_but_keeps_other(self):
        raw = (
            dkim(h="From:To:Subject:Date", d="good.example")
            + dkim(h=None, d="bad.example")
            + BASE_TAIL
        )
        result = audit_dkim_coverage(raw)
        self.assertEqual(result["status"], "anomaly")
        self.assertEqual(result["anomaly_count"], 1)
        statuses = [s["status"] for s in result["signatures"]]
        self.assertEqual(statuses, ["ok", "anomaly"])

    def test_page_sample(self):
        result = audit_dkim_coverage(SAMPLE_HEADERS_DKIM)
        self.assertEqual(result["signature_count"], 2)
        # 示例两条签名 h= 都存在且非空（未匹配项不构成异常）
        self.assertEqual(result["anomaly_count"], 0)
        self.assertEqual(result["status"], "ok")
        top = result["signatures"][0]
        # countersignature 命中第 2 个字段
        self.assertEqual(top["h_results"][2]["field_position"], 2)
        # X-Missing 未匹配
        self.assertFalse(top["h_results"][5]["matched"])
        # 两个 Received 自底部向上分别命中 #4、#3
        self.assertEqual(
            [top["h_results"][i]["field_position"] for i in (0, 1)], [4, 3]
        )
        # 第 2 条签名只覆盖底部 To(#8)，注入 To(#7) 未覆盖
        bottom = result["signatures"][1]
        self.assertEqual(bottom["h_results"][3]["field_position"], 8)
        uncovered_to = [f for f in bottom["uncovered_core"] if f["field"] == "To"]
        self.assertEqual([f["position"] for f in uncovered_to], [7])


@unittest.skipIf(create_app is None, "未安装 Flask")
class DkimApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_success_same_structure(self):
        resp = self.client.post(
            "/api/dkim/coverage", json={"headers": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data, audit_dkim_coverage(SAMPLE_HEADERS_DKIM))
        self.assertEqual(data["signature_count"], 2)

    def test_api_no_signature_returns_none(self):
        resp = self.client.post(
            "/api/dkim/coverage", json={"headers": "Subject: hi\n"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "none")
        self.assertEqual(data["signature_count"], 0)

    def test_api_empty_returns_400(self):
        resp = self.client.post("/api/dkim/coverage", json={"headers": "  "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_non_string_returns_400(self):
        resp = self.client.post("/api/dkim/coverage", json={"headers": 123})
        self.assertEqual(resp.status_code, 400)

    def test_api_missing_h_is_anomaly_status_200(self):
        raw = "DKIM-Signature: v=1; d=e.com; s=s; b=x\n" + BASE_TAIL
        resp = self.client.post("/api/dkim/coverage", json={"headers": raw})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "anomaly")

    def test_api_form_field_accepted(self):
        resp = self.client.post(
            "/api/dkim/coverage", data={"headers": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["signature_count"], 2)

    def test_form_page_renders_signatures(self):
        resp = self.client.post(
            "/dkim-coverage", data={"headers_dkim": SAMPLE_HEADERS_DKIM}
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("DKIM 头字段覆盖审计结果", html)
        self.assertIn("DKIM 签名 1", html)
        self.assertIn("DKIM 签名 2", html)
        self.assertIn("forwarder.example", html)

    def test_form_page_none_state(self):
        resp = self.client.post(
            "/dkim-coverage", data={"headers_dkim": "Subject: hi\n"}
        )
        html = resp.get_data(as_text=True)
        self.assertIn("无 DKIM 签名", html)

    def test_index_page_has_dkim_section(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("DKIM 头字段覆盖审计", html)
        self.assertIn("/api/dkim/coverage", html)


if __name__ == "__main__":
    unittest.main()
