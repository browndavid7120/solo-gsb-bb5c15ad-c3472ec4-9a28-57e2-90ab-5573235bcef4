"""邮件投递路径检查 Flask 应用。"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from mailtrace.parsing import (
    analyze_auth_results,
    analyze_headers,
    analyze_trust_boundary,
    audit_dkim_coverage,
    audit_sender_alignment,
    batch_delay_analysis,
    build_share_report,
    check_arc_chain,
    compare_headers,
    split_batch_headers,
)
from mailtrace.parsing.sample import (
    SAMPLE_HEADERS,
    SAMPLE_HEADERS_ALIGN,
    SAMPLE_HEADERS_ARC,
    SAMPLE_HEADERS_AUTHRES,
    SAMPLE_HEADERS_B,
    SAMPLE_HEADERS_BATCH,
    SAMPLE_HEADERS_DKIM,
    SAMPLE_HEADERS_TRUST,
    SAMPLE_ORG_DOMAIN,
    SAMPLE_TRUSTED_HOSTS,
)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def create_app() -> Flask:
    app = Flask(__name__)
    max_input_kb = _env_int("MAX_INPUT_KB", 256)
    app.config["MAX_INPUT_BYTES"] = max_input_kb * 1024
    app.config["SAMPLE_HEADERS"] = SAMPLE_HEADERS
    app.config["SAMPLE_HEADERS_B"] = SAMPLE_HEADERS_B

    def render_index(**extra):
        context = {
            "sample": SAMPLE_HEADERS,
            "sample_b": SAMPLE_HEADERS_B,
            "sample_batch": SAMPLE_HEADERS_BATCH,
            "sample_arc": SAMPLE_HEADERS_ARC,
            "sample_dkim": SAMPLE_HEADERS_DKIM,
            "sample_trust": SAMPLE_HEADERS_TRUST,
            "sample_trusted_hosts": SAMPLE_TRUSTED_HOSTS,
            "sample_authres": SAMPLE_HEADERS_AUTHRES,
            "sample_align": SAMPLE_HEADERS_ALIGN,
            "sample_org_domain": SAMPLE_ORG_DOMAIN,
            "max_input_kb": max_input_kb,
        }
        context.update(extra)
        return render_template("index.html", **context)

    @app.get("/")
    def index():
        return render_index()

    def _check_size(raw_headers: str, side: str | None = None) -> str | None:
        """返回错误消息；未超限返回 None。side 为超限提示前缀（如 “A 侧”、“第 2 封”）。"""
        max_bytes = app.config["MAX_INPUT_BYTES"]
        if len(raw_headers.encode("utf-8", errors="ignore")) > max_bytes:
            prefix = f"{side}输入" if side else "输入"
            return f"{prefix}超过 {max_input_kb} KB 上限，请截取头部后重试"
        return None

    def _do_analyze(raw_headers: str) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error, "hop_count": 0, "path": []}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部（包含至少一个 Received 字段）",
                "hop_count": 0,
                "path": [],
            }
        return analyze_headers(raw_headers)

    def _do_share(raw_headers: str) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部（包含至少一个 Received 字段）"
            }
        return build_share_report(raw_headers)

    def _do_compare(headers_a: str, headers_b: str) -> dict:
        for side, raw in (("A 侧", headers_a), ("B 侧", headers_b)):
            error = _check_size(raw, side)
            if error:
                return {"error": error}
        if not headers_a.strip() or not headers_b.strip():
            return {
                "error": "请在 A、B 两侧分别粘贴邮件原始头部"
                "（各包含至少一个 Received 字段）"
            }
        return compare_headers(headers_a, headers_b)

    def _do_batch_delays(headers_list: list[str]) -> dict:
        for idx, raw in enumerate(headers_list, start=1):
            error = _check_size(raw, f"第 {idx} 封")
            if error:
                return {"error": error}
        return batch_delay_analysis(headers_list)

    def _do_arc_check(raw_headers: str) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部（包含 ARC-Seal / "
                "ARC-Message-Signature / ARC-Authentication-Results 字段）"
            }
        return check_arc_chain(raw_headers)

    def _do_dkim_coverage(raw_headers: str) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {"error": "请先粘贴邮件原始头部（包含 DKIM-Signature 字段）"}
        return audit_dkim_coverage(raw_headers)

    def _do_trust_boundary(raw_headers: str, trusted_hosts) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部（包含至少一个 Received 字段）"
            }
        return analyze_trust_boundary(raw_headers, trusted_hosts)

    def _do_auth_results(raw_headers: str, trusted_hosts) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部"
                "（包含 Authentication-Results 与 Received 字段）"
            }
        return analyze_auth_results(raw_headers, trusted_hosts)

    def _do_sender_alignment(raw_headers: str, trusted_hosts, org_domain, mode) -> dict:
        error = _check_size(raw_headers)
        if error:
            return {"error": error}
        if not raw_headers.strip():
            return {
                "error": "请先粘贴邮件原始头部"
                "（包含 From、Authentication-Results 与 Received 字段）"
            }
        return audit_sender_alignment(raw_headers, trusted_hosts, org_domain, mode)

    @app.post("/analyze")
    def analyze_form():
        raw_headers = request.form.get("headers_a", "") or request.form.get("headers", "")
        result = _do_analyze(raw_headers)
        return render_index(
            headers_a=raw_headers,
            headers_b=request.form.get("headers_b", ""),
            result=result,
        )

    @app.post("/compare")
    def compare_form():
        headers_a = request.form.get("headers_a", "")
        headers_b = request.form.get("headers_b", "")
        compare = _do_compare(headers_a, headers_b)
        return render_index(
            headers_a=headers_a,
            headers_b=headers_b,
            compare=compare,
        )

    @app.post("/batch-delays")
    def batch_delays_form():
        raw_batch = request.form.get("headers_batch", "")
        headers_list = split_batch_headers(raw_batch)
        if not headers_list:
            batch = {
                "error": "未识别到任何邮件头部，请用分隔行（如 "
                "“===== 下一封邮件 =====”）分开至少一份原始头部",
                "message_count": 0,
                "analyzed_count": 0,
                "message_errors": [],
                "segment_count": 0,
                "sample_count": 0,
                "excluded": {"invalid_time": 0, "backflow": 0, "identity_less": 0},
                "duplicate_collapsed": 0,
                "segments": [],
            }
        else:
            batch = _do_batch_delays(headers_list)
        return render_index(headers_batch=raw_batch, batch=batch)

    @app.post("/arc-check")
    def arc_check_form():
        raw_headers = request.form.get("headers_arc", "")
        arc = _do_arc_check(raw_headers)
        return render_index(headers_arc=raw_headers, arc=arc)

    @app.post("/dkim-coverage")
    def dkim_coverage_form():
        raw_headers = request.form.get("headers_dkim", "")
        dkim = _do_dkim_coverage(raw_headers)
        return render_index(headers_dkim=raw_headers, dkim=dkim)

    @app.post("/trust-boundary")
    def trust_boundary_form():
        raw_headers = request.form.get("headers_trust", "")
        trusted_hosts = request.form.get("trusted_hosts", "")
        trust = _do_trust_boundary(raw_headers, trusted_hosts)
        return render_index(
            headers_trust=raw_headers,
            trusted_hosts_text=trusted_hosts,
            trust=trust,
        )

    @app.post("/auth-results")
    def auth_results_form():
        raw_headers = request.form.get("headers_authres", "")
        trusted_hosts = request.form.get("trusted_hosts_authres", "")
        authres = _do_auth_results(raw_headers, trusted_hosts)
        return render_index(
            headers_authres=raw_headers,
            trusted_hosts_authres_text=trusted_hosts,
            authres=authres,
        )

    @app.post("/sender-alignment")
    def sender_alignment_form():
        raw_headers = request.form.get("headers_align", "")
        trusted_hosts = request.form.get("trusted_hosts_align", "")
        org_domain = request.form.get("org_domain", "")
        mode = request.form.get("align_mode", "strict")
        align = _do_sender_alignment(raw_headers, trusted_hosts, org_domain, mode)
        return render_index(
            headers_align=raw_headers,
            trusted_hosts_align_text=trusted_hosts,
            org_domain_text=org_domain,
            align_mode_selected=mode,
            align=align,
        )

    @app.post("/api/analyze")
    def analyze_api():
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw_headers = payload.get("headers", "")
        else:
            raw_headers = request.form.get("headers", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        result = _do_analyze(raw_headers)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/analyze/share")
    def analyze_share_api():
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw_headers = payload.get("headers", "")
        else:
            raw_headers = request.form.get("headers", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        result = _do_share(raw_headers)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/compare")
    def compare_api():
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            headers_a = payload.get("headers_a", "")
            headers_b = payload.get("headers_b", "")
        else:
            headers_a = request.form.get("headers_a", "")
            headers_b = request.form.get("headers_b", "")
        if not isinstance(headers_a, str) or not isinstance(headers_b, str):
            return jsonify({"error": "headers_a 和 headers_b 必须是字符串"}), 400
        result = _do_compare(headers_a, headers_b)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/batch-delays")
    def batch_delays_api():
        if not request.is_json:
            return jsonify(
                {"error": "请使用 application/json 提交 {\"headers\": [头部字符串, ...]}"}
            ), 400
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "请求体必须是 JSON 对象，含 headers 字符串数组"}), 400
        headers_list = payload.get("headers")
        if not isinstance(headers_list, list) or not all(
            isinstance(item, str) for item in headers_list
        ):
            return jsonify({"error": "headers 必须是字符串数组（每封邮件一个原始头部）"}), 400
        if len(headers_list) < 2:
            return jsonify({"error": "请至少提供两封邮件的原始头部"}), 400
        if any(not item.strip() for item in headers_list):
            return jsonify({"error": "headers 数组中存在空白项，请删除后重试"}), 400
        result = _do_batch_delays(headers_list)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/arc/check")
    def arc_check_api():
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw_headers = payload.get("headers", "")
        else:
            raw_headers = request.form.get("headers", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        result = _do_arc_check(raw_headers)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/dkim/coverage")
    def dkim_coverage_api():
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw_headers = payload.get("headers", "")
        else:
            raw_headers = request.form.get("headers", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        result = _do_dkim_coverage(raw_headers)
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/analyze/trust-boundary")
    def trust_boundary_api():
        if request.is_json:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify(
                    {"error": "请求体必须是 JSON 对象，含 headers 与 trusted_hosts"}
                ), 400
            raw_headers = payload.get("headers", "")
            trusted_hosts = payload.get("trusted_hosts", [])
        else:
            raw_headers = request.form.get("headers", "")
            # 表单只支持每行一个主机名的文本（也兼容逗号 / 空白分隔）
            trusted_hosts = request.form.get("trusted_hosts", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        if not isinstance(trusted_hosts, (str, list, tuple)) or (
            isinstance(trusted_hosts, list)
            and not all(isinstance(item, str) for item in trusted_hosts)
        ):
            return jsonify(
                {"error": "trusted_hosts 必须是主机名字符串数组，或每行一个主机名的字符串"}
            ), 400
        result = _do_trust_boundary(raw_headers, trusted_hosts)
        # 空名单、空白头部等输入错误为 400；no_received / untrusted_top 为 200
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/analyze/auth-results")
    def auth_results_api():
        if request.is_json:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify(
                    {"error": "请求体必须是 JSON 对象，含 headers 与 trusted_hosts"}
                ), 400
            raw_headers = payload.get("headers", "")
            trusted_hosts = payload.get("trusted_hosts", [])
        else:
            raw_headers = request.form.get("headers", "")
            # 表单只支持每行一个主机名的文本（也兼容逗号 / 空白分隔）
            trusted_hosts = request.form.get("trusted_hosts", "")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        if not isinstance(trusted_hosts, (str, list, tuple)) or (
            isinstance(trusted_hosts, list)
            and not all(isinstance(item, str) for item in trusted_hosts)
        ):
            return jsonify(
                {"error": "trusted_hosts 必须是主机名字符串数组，或每行一个主机名的字符串"}
            ), 400
        result = _do_auth_results(raw_headers, trusted_hosts)
        # 空名单、空白头部等输入错误为 400；no_received / untrusted_top 为 200
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.post("/api/analyze/sender-alignment")
    def sender_alignment_api():
        if request.is_json:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify(
                    {"error": "请求体必须是 JSON 对象，含 headers、trusted_hosts"
                              "（宽松模式另需 org_domain）"}
                ), 400
            raw_headers = payload.get("headers", "")
            trusted_hosts = payload.get("trusted_hosts", [])
            org_domain = payload.get("org_domain")
            mode = payload.get("mode", "strict")
        else:
            raw_headers = request.form.get("headers", "")
            # 表单只支持每行一个主机名的文本（也兼容逗号 / 空白分隔）
            trusted_hosts = request.form.get("trusted_hosts", "")
            org_domain = request.form.get("org_domain", "")
            mode = request.form.get("mode", "strict")
        if not isinstance(raw_headers, str):
            return jsonify({"error": "headers 必须是字符串"}), 400
        if not isinstance(trusted_hosts, (str, list, tuple)) or (
            isinstance(trusted_hosts, list)
            and not all(isinstance(item, str) for item in trusted_hosts)
        ):
            return jsonify(
                {"error": "trusted_hosts 必须是主机名字符串数组，或每行一个主机名的字符串"}
            ), 400
        if org_domain is not None and not isinstance(org_domain, str):
            return jsonify({"error": "org_domain 必须是字符串（发件组织域）"}), 400
        if mode is not None and not isinstance(mode, str):
            return jsonify({"error": "mode 必须是 strict 或 relaxed"}), 400
        result = _do_sender_alignment(raw_headers, trusted_hosts, org_domain, mode)
        # 空名单、非法模式、宽松缺组织域、空白头部等输入错误为 400；
        # no_received / untrusted_top / 证据不足等分析结论为 200
        status = 400 if result.get("error") else 200
        return jsonify(result), status

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    return app
