import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import check_arc_chain  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_HEADERS_ARC  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None
from mailtrace.parsing.sample import SAMPLE_HEADERS_ARC  # noqa: E402


def arc_set(i, cv=None, authserv="mx.example"):
    """生成一组标准 ARC 三字段（i=1 默认 cv=none，其余默认 cv=pass）。"""
    if cv is None:
        cv = "none" if i == 1 else "pass"
    return (
        "ARC-Seal: i=%d; a=rsa-sha256; t=1790216000; cv=%s;"
        " d=example.com; s=arc2026; b=c2lnMQ==\n"
        "ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed;"
        " d=example.com; s=arc2026; t=1790216000; bh=aGFzaA==;"
        " h=From:To:Subject; b=bXNpZw==\n"
        "ARC-Authentication-Results: i=%d; %s;"
        " spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com\n"
    ) % (i, cv, i, i, authserv)


def issue_codes(result):
    return [issue["code"] for issue in result["issues"]]


class ValidChainTests(unittest.TestCase):
    def test_two_instance_chain_passes(self):
        # 真实邮件中 i=2 的字段组写在 i=1 之前（接收方在顶部追加）
        raw = arc_set(2) + arc_set(1) + "Subject: hi\n"
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["status_label"], "ARC 链结构完整")
        self.assertEqual(result["instance_count"], 2)
        self.assertEqual(result["arc_field_count"], 6)
        self.assertEqual(result["error_count"], 0)
        # 实例按 i 升序展示，与原文书写顺序无关
        self.assertEqual([inst["i"] for inst in result["instances"]], [1, 2])
        self.assertTrue(all(inst["ok"] for inst in result["instances"]))
        first, second = result["instances"]
        self.assertEqual(first["seal"]["cv"], "none")
        self.assertEqual(first["seal"]["cv_expected"], "none")
        self.assertTrue(first["seal"]["cv_ok"])
        self.assertEqual(second["seal"]["cv"], "pass")
        self.assertTrue(second["seal"]["cv_ok"])
        self.assertTrue(result["numbering"]["ok"])
        self.assertEqual(result["numbering"]["found"], [1, 2])

    def test_folding_and_tag_order_still_recognized(self):
        raw = (
            "ARC-Seal: cv=none;\n"
            "\ti=1; a=rsa-sha256;\n"
            "\td=example.com; s=arc; b=xx\n"
            "ARC-Message-Signature: t=1790216000;\n"
            "\ti=1; a=rsa-sha256; d=example.com; s=arc; bh=yy; h=From; b=zz\n"
            "ARC-Authentication-Results: mx.example;\n"
            "\ti=1; spf=pass smtp.mailfrom=example.com\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["instances"][0]["seal"]["cv"], "none")
        # 原始折行文本被保留
        self.assertIn("\n", result["instances"][0]["seal"]["raw"])

    def test_header_and_tag_names_case_insensitive(self):
        raw = (
            "arc-seal: I=1; CV=none; a=rsa-sha256; d=example.com; s=arc; b=xx\n"
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc;"
            " bh=yy; h=From; b=zz\n"
            "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "pass")

    def test_page_sample_chain_passes(self):
        result = check_arc_chain(SAMPLE_HEADERS_ARC)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["instance_count"], 2)
        self.assertEqual(result["error_count"], 0)


class NoArcTests(unittest.TestCase):
    def test_no_arc_fields_returns_none_not_pass(self):
        raw = (
            "Received: by mx.example id 1; Tue, 23 Sep 2026 02:00:00 +0000\n"
            "Authentication-Results: mx.example; spf=pass\n"
            "Subject: hello\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["status_label"], "无 ARC 链")
        self.assertNotEqual(result["status"], "pass")
        self.assertEqual(result["arc_field_count"], 0)
        self.assertEqual(result["instance_count"], 0)
        self.assertEqual(result["error_count"], 0)
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["instances"], [])

    def test_arc_fields_after_body_ignored(self):
        raw = "Subject: hi\n\n" + arc_set(1)
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "none")


class InvalidITests(unittest.TestCase):
    def test_non_numeric_i(self):
        raw = (
            "ARC-Seal: i=abc; cv=none; a=rsa-sha256; d=example.com; s=arc; b=xx\n"
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc;"
            " bh=yy; h=From; b=zz\n"
            "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        codes = issue_codes(result)
        self.assertIn("invalid_i", codes)
        # i=1 实例因 Seal 无法归组而缺少 Seal 字段
        self.assertIn("missing_field", codes)
        self.assertEqual(len(result["invalid_fields"]), 1)
        bad = result["invalid_fields"][0]
        self.assertEqual(bad["field"], "ARC-Seal")
        self.assertEqual(bad["i_raw"], "abc")
        self.assertIn("ARC-Seal", bad["raw"])

    def test_zero_and_negative_i(self):
        for bad in ("0", "-1"):
            raw = (
                f"ARC-Seal: i={bad}; cv=none; a=rsa; d=e.com; s=a; b=x\n"
                "ARC-Message-Signature: i=1; a=rsa; d=e.com; s=a; bh=y;"
                " h=From; b=z\n"
                "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
            )
            result = check_arc_chain(raw)
            self.assertEqual(result["status"], "fail")
            self.assertIn("invalid_i", issue_codes(result))

    def test_i_above_rfc_max_is_invalid(self):
        # RFC 8617 规定 i 合法范围为 1-50；超大值不得触发巨大的缺失号码列表
        for bad in ("51", "1000000000"):
            raw = (
                f"ARC-Seal: i={bad}; cv=pass; a=rsa; d=e.com; s=a; b=x\n"
                "ARC-Message-Signature: i=1; a=rsa; d=e.com; s=a; bh=y;"
                " h=From; b=z\n"
                "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
            )
            result = check_arc_chain(raw)
            self.assertEqual(result["status"], "fail")
            self.assertIn("invalid_i", issue_codes(result))
            self.assertEqual(result["invalid_fields"][0]["i_raw"], bad)
            self.assertLessEqual(len(result["numbering"]["missing"]), 50)

    def test_missing_i_tag(self):
        raw = "ARC-Seal: cv=none; a=rsa-sha256; d=example.com; s=arc; b=xx\n"
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["issues"][0]["code"], "missing_i")
        self.assertIsNone(result["issues"][0]["instance"])
        self.assertEqual(result["instance_count"], 0)
        self.assertIsNone(result["invalid_fields"][0]["i_raw"])

    def test_duplicate_i_tag_in_one_field(self):
        raw = arc_set(1).replace("ARC-Seal: i=1;", "ARC-Seal: i=1; i=1;")
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        self.assertIn("invalid_i", issue_codes(result))


class FieldCountTests(unittest.TestCase):
    def test_duplicate_seal(self):
        raw = (
            "ARC-Seal: i=1; cv=none; a=rsa; d=e.com; s=a; b=x\n"
            "ARC-Seal: i=1; cv=none; a=rsa; d=e.com; s=b; b=y\n"
            "ARC-Message-Signature: i=1; a=rsa; d=e.com; s=a; bh=h; h=From; b=z\n"
            "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        dup = [i for i in result["issues"] if i["code"] == "duplicate_field"]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0]["instance"], 1)
        self.assertEqual(dup[0]["field"], "ARC-Seal")
        self.assertIn("2", dup[0]["message"])
        self.assertEqual(result["instances"][0]["seal"]["count"], 2)
        self.assertFalse(result["instances"][0]["ok"])

    def test_missing_aar(self):
        raw = (
            "ARC-Seal: i=1; cv=none; a=rsa; d=e.com; s=a; b=x\n"
            "ARC-Message-Signature: i=1; a=rsa; d=e.com; s=a; bh=h; h=From; b=z\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        miss = [i for i in result["issues"] if i["code"] == "missing_field"]
        self.assertEqual(len(miss), 1)
        self.assertEqual(miss[0]["instance"], 1)
        self.assertEqual(miss[0]["field"], "ARC-Authentication-Results")
        self.assertFalse(
            result["instances"][0]["authentication_results"]["present"]
        )
        self.assertFalse(result["instances"][0]["ok"])


class NumberingTests(unittest.TestCase):
    def test_gap_detected(self):
        raw = arc_set(3) + arc_set(1)
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        gaps = [i for i in result["issues"] if i["code"] == "gap"]
        self.assertEqual([g["instance"] for g in gaps], [2])
        self.assertEqual(result["numbering"]["missing"], [2])
        self.assertFalse(result["numbering"]["ok"])

    def test_chain_not_starting_at_one(self):
        raw = arc_set(2)
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["numbering"]["missing"], [1])
        # 唯一的 i=2 实例 cv 默认 pass，cv 本身不报错
        self.assertNotIn("cv_bad", issue_codes(result))


class CvTests(unittest.TestCase):
    def test_first_seal_cv_must_be_none(self):
        result = check_arc_chain(arc_set(1, cv="pass"))
        self.assertEqual(result["status"], "fail")
        cv_issues = [i for i in result["issues"] if i["code"] == "cv_bad"]
        self.assertEqual(len(cv_issues), 1)
        self.assertEqual(cv_issues[0]["instance"], 1)
        self.assertEqual(cv_issues[0]["field"], "ARC-Seal")
        seal = result["instances"][0]["seal"]
        self.assertFalse(seal["cv_ok"])
        self.assertEqual(seal["cv_expected"], "none")

    def test_later_seal_cv_must_be_pass(self):
        result = check_arc_chain(arc_set(2, cv="none") + arc_set(1))
        self.assertEqual(result["status"], "fail")
        cv_issues = [i for i in result["issues"] if i["code"] == "cv_bad"]
        self.assertEqual(len(cv_issues), 1)
        self.assertEqual(cv_issues[0]["instance"], 2)
        self.assertIn("pass", cv_issues[0]["message"])

    def test_cv_fail_value_reported(self):
        result = check_arc_chain(arc_set(2, cv="fail") + arc_set(1))
        self.assertEqual(result["status"], "fail")
        self.assertIn("cv_bad", issue_codes(result))

    def test_cv_missing(self):
        raw = (
            "ARC-Seal: i=1; a=rsa; d=e.com; s=a; b=x\n"
            "ARC-Message-Signature: i=1; a=rsa; d=e.com; s=a; bh=h; h=From; b=z\n"
            "ARC-Authentication-Results: i=1; mx.example; spf=pass\n"
        )
        result = check_arc_chain(raw)
        self.assertEqual(result["status"], "fail")
        self.assertIn("cv_missing", issue_codes(result))
        self.assertIsNone(result["instances"][0]["seal"]["cv"])

    def test_cv_value_case_insensitive(self):
        result = check_arc_chain(arc_set(1, cv="NONE"))
        self.assertEqual(result["status"], "pass")


@unittest.skipIf(create_app is None, "未安装 Flask")
class ArcApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_arc_check_success_same_structure(self):
        resp = self.client.post("/api/arc/check", json={"headers": SAMPLE_HEADERS_ARC})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        # 与解析核心返回结构完全一致
        self.assertEqual(data, check_arc_chain(SAMPLE_HEADERS_ARC))
        self.assertEqual(data["status"], "pass")
        self.assertEqual(data["instance_count"], 2)

    def test_api_arc_check_no_arc_returns_none_not_pass(self):
        resp = self.client.post(
            "/api/arc/check", json={"headers": "Subject: hi\n"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "none")
        self.assertEqual(data["status_label"], "无 ARC 链")
        self.assertNotEqual(data["status"], "pass")

    def test_api_arc_check_empty_returns_400(self):
        resp = self.client.post("/api/arc/check", json={"headers": "  "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_arc_check_non_string_returns_400(self):
        resp = self.client.post("/api/arc/check", json={"headers": 123})
        self.assertEqual(resp.status_code, 400)

    def test_api_arc_check_form_field_accepted(self):
        resp = self.client.post(
            "/api/arc/check", data={"headers": SAMPLE_HEADERS_ARC}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "pass")

    def test_arc_form_page_renders_instances(self):
        resp = self.client.post("/arc-check", data={"headers_arc": SAMPLE_HEADERS_ARC})
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("ARC 链结构完整", html)
        self.assertIn("ARC 实例 1", html)
        self.assertIn("ARC 实例 2", html)

    def test_index_page_has_arc_section(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("ARC 链结构检查", html)
        self.assertIn("/api/arc/check", html)


if __name__ == "__main__":
    unittest.main()
