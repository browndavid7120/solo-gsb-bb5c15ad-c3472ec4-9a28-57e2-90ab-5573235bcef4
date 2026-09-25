"""Authentication-Results 字段的来源归属分析。

复用 :func:`mailtrace.parsing.parser.parse_header_blocks` 的折行展开与
:func:`mailtrace.parsing.trust.analyze_trust_boundary` 的可信边界分析，
把每条 ``Authentication-Results`` 字段归属到具体的接收跳：

- 每条 AR 字段归属到其后**紧邻的 Received**——沿头部书写顺序向下找到的
  第一条 ``Received``（两者之间不得有另一条 ``Received``；其后没有任何
  ``Received`` 时记为“无对应跳”）；
- 仅当该跳属于**自顶端连续可信前缀**（``by`` 主机连续命中本组织名单）、
  且 AR 的 ``authserv-id`` 与该跳 ``by`` 主机一致（忽略大小写与末尾点）
  时，才标为**本组织声明**；
- 其余逐条标明：**无对应跳**（其后没有 Received）、**越过边界**
  （对应跳不在连续可信前缀内）、**身份不符**（对应跳可信但
  authserv-id 与 by 主机不一致，含 authserv-id 缺失 / 为 ``none``）。

对本组织声明提取 ``spf`` / ``dkim`` / ``dmarc`` 的结果词，按原文顺序
展示并**保留重复声明**；没有可信前缀（或没有任何字段归属本组织）时，
通过 ``no_org_claims`` / ``no_org_reason`` 明确表示“无本组织声明”。
"""

from __future__ import annotations

from mailtrace.parsing.parser import _strip_paren_comments, parse_header_blocks
from mailtrace.parsing.trust import (
    STATUS_ESTABLISHED,
    STATUS_NO_RECEIVED,
    STATUS_UNTRUSTED_TOP,
    analyze_trust_boundary,
    normalize_host,
    parse_trusted_hosts,
)

AR_FIELD_NAME = "authentication-results"
RECEIVED_FIELD_NAME = "received"

# 每条 Authentication-Results 的归属状态
STATUS_OWN = "own"  # 本组织声明
STATUS_NO_HOP = "no_hop"  # 无对应跳（其后没有任何 Received）
STATUS_BEYOND_BOUNDARY = "beyond_boundary"  # 越过边界（对应跳不在可信前缀内）
STATUS_IDENTITY_MISMATCH = "identity_mismatch"  # 身份不符（authserv-id ≠ by）

_STATUS_LABELS = {
    STATUS_OWN: "本组织声明",
    STATUS_NO_HOP: "无对应跳",
    STATUS_BEYOND_BOUNDARY: "越过边界",
    STATUS_IDENTITY_MISMATCH: "身份不符",
}

# 无本组织声明的原因（no_org_claims 为 True 时给出）
REASON_NO_TRUSTED_PREFIX = "no_trusted_prefix"  # 无法建立连续可信前缀
REASON_NO_AUTH_RESULTS = "no_auth_results"  # 头部没有 Authentication-Results
REASON_NONE_ATTRIBUTED = "none_attributed"  # 有字段但无一归属本组织

# 需要提取结果词的认证方法（小写）
METHODS_OF_INTEREST = ("spf", "dkim", "dmarc")


def _parse_authserv_id(value: str) -> str | None:
    """取 AR 字段的 authserv-id（第一个分号前的标识，圆括号注释先剥离）。

    缺失（字段直接以 ``method=result`` 开头）、空值或 ``none``
    （RFC 7601 的“未做认证”占位）时返回 ``None``。
    """
    first = _strip_paren_comments(value.split(";", 1)[0]).strip()
    if not first or "=" in first:
        return None
    token = first.split()[0]
    if token.lower() == "none":
        return None
    return token


def _extract_methods(value: str) -> list[dict]:
    """提取 spf / dkim / dmarc 的 ``method=结果词``，保持原文顺序与重复。

    结果词为 ``=`` 后的第一个空白分隔词（其后的属性如
    ``smtp.mailfrom=`` / ``header.d=`` 不纳入）；圆括号注释先剥离，
    避免注释里的分号或等号干扰切分。
    """
    cleaned = _strip_paren_comments(value)
    methods: list[dict] = []
    for segment in cleaned.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, _, rest = segment.partition("=")
        method = name.strip().lower()
        if method not in METHODS_OF_INTEREST:
            continue
        tokens = rest.strip().split()
        methods.append(
            {"method": method, "result": tokens[0] if tokens else ""}
        )
    return methods


def analyze_auth_results(
    raw_headers: str, trusted_hosts: str | list[str] | tuple[str, ...]
) -> dict:
    """把每条 Authentication-Results 归属到接收跳并判定是否本组织声明。

    返回供页面 / ``POST /api/analyze/auth-results`` 共用的结构化结果；
    名单为空或类型错误时返回 ``{"error": ...}``（调用方据此回 400）。
    可信前缀状态（``status``）直接复用可信边界分析的
    ``established`` / ``untrusted_top`` / ``no_received``。
    """
    try:
        hosts, _host_set = parse_trusted_hosts(trusted_hosts)
    except TypeError as exc:
        return {"error": str(exc)}
    if not hosts:
        return {
            "error": "本组织接收服务器主机名名单不能为空，请每行填写一个主机名"
        }

    trust = analyze_trust_boundary(raw_headers, hosts)
    trusted_indexes = {
        h["top_index"] for h in trust["hops"] if h["trusted"]
    }
    by_host_of = {h["top_index"]: h.get("by_host") for h in trust["hops"]}

    blocks = parse_header_blocks(raw_headers)
    # Received 字段按书写顺序编号，与可信边界分析的 top_index 一一对应
    received_top_index: dict[int, int] = {}  # block.order -> top_index
    received_after: list[tuple[int, int]] = []  # (block.order, top_index) 有序
    for block in blocks:
        if block.name.lower() == RECEIVED_FIELD_NAME:
            top_index = len(received_after) + 1
            received_top_index[block.order] = top_index
            received_after.append((block.order, top_index))

    ar_blocks = [b for b in blocks if b.name.lower() == AR_FIELD_NAME]

    results: list[dict] = []
    auth_summary: list[dict] = []
    for index, block in enumerate(ar_blocks, start=1):
        authserv_id = _parse_authserv_id(block.value)

        # 其后紧邻的 Received：向下第一条（两者之间不得有另一条 Received）
        hop_top_index: int | None = None
        for order, top_index in received_after:
            if order > block.order:
                hop_top_index = top_index
                break

        hop_by: str | None = None
        if hop_top_index is None:
            status = STATUS_NO_HOP
            detail = "该字段之后没有任何 Received 字段，找不到对应的接收跳"
        else:
            hop_by = by_host_of.get(hop_top_index)
            if hop_top_index not in trusted_indexes:
                status = STATUS_BEYOND_BOUNDARY
                detail = (
                    f"对应头部自上而下第 {hop_top_index} 跳"
                    f"（by {hop_by or '（缺失）'}），该跳不在自顶端连续"
                    "可信前缀内（越过可信边界）"
                )
            else:
                auth_norm = normalize_host(authserv_id)
                by_norm = normalize_host(hop_by)
                if auth_norm is None or auth_norm != by_norm:
                    status = STATUS_IDENTITY_MISMATCH
                    detail = (
                        f"对应头部自上而下第 {hop_top_index} 跳"
                        f"（by {hop_by or '（缺失）'}）在可信前缀内，但 "
                        f"authserv-id（{authserv_id or '（缺失）'}）"
                        "与该跳 by 主机不一致"
                    )
                else:
                    status = STATUS_OWN
                    detail = (
                        f"归属头部自上而下第 {hop_top_index} 跳"
                        f"（by {hop_by}）：该跳在自顶端连续可信前缀内，"
                        "且 authserv-id 与 by 主机一致"
                    )

        # 仅对本组织声明提取 spf / dkim / dmarc 结果词
        methods = _extract_methods(block.value) if status == STATUS_OWN else []
        results.append(
            {
                "index": index,
                "field_position": block.order + 1,
                "authserv_id": authserv_id,
                "status": status,
                "status_label": _STATUS_LABELS[status],
                "detail": detail,
                "hop_top_index": hop_top_index,
                "hop_by_host": hop_by,
                "methods": methods,
                "raw": block.raw,
            }
        )
        for item in methods:
            auth_summary.append(
                {
                    "method": item["method"],
                    "result": item["result"],
                    "field_index": index,
                    "hop_top_index": hop_top_index,
                }
            )

    ar_count = len(results)
    own_count = sum(1 for r in results if r["status"] == STATUS_OWN)
    no_org_claims = own_count == 0

    trust_status = trust["status"]
    if trust_status != STATUS_ESTABLISHED:
        no_org_reason: str | None = REASON_NO_TRUSTED_PREFIX
    elif ar_count == 0:
        no_org_reason = REASON_NO_AUTH_RESULTS
    elif no_org_claims:
        no_org_reason = REASON_NONE_ATTRIBUTED
    else:
        no_org_reason = None

    if trust_status == STATUS_NO_RECEIVED:
        message = "头部中未找到 Received 字段，无法建立可信前缀：无本组织声明。"
        if ar_count:
            message += (
                f"（仍逐条列出 {ar_count} 条 Authentication-Results 字段，"
                "均无对应跳）"
            )
    elif trust_status == STATUS_UNTRUSTED_TOP:
        message = (
            "无法从顶端建立可信前缀（顶端第 1 跳未命中本组织名单或缺少 by）："
            "无本组织声明。"
        )
    elif ar_count == 0:
        message = (
            f"可信前缀已建立（自顶端连续 {trust['trusted_count']} 跳），"
            "但头部中没有 Authentication-Results 字段：无本组织声明。"
        )
    elif own_count:
        message = (
            f"共 {ar_count} 条 Authentication-Results 字段，其中 "
            f"{own_count} 条归属本组织连续可信前缀内的接收跳，"
            "判定为本组织声明；"
            f"其余 {ar_count - own_count} 条已逐条标明无对应跳 / "
            "越过边界 / 身份不符。"
        )
    else:
        message = (
            f"共 {ar_count} 条 Authentication-Results 字段，但没有一条"
            "归属本组织连续可信前缀内的接收跳：无本组织声明。"
        )

    return {
        "status": trust_status,
        "status_label": trust["status_label"],
        "message": message,
        "trusted_hosts": trust["trusted_hosts"],
        "hop_count": trust["hop_count"],
        "trusted_count": trust["trusted_count"],
        "boundary": trust["boundary"],
        "ar_count": ar_count,
        "own_count": own_count,
        "no_org_claims": no_org_claims,
        "no_org_reason": no_org_reason,
        "auth_summary": auth_summary,
        "results": results,
    }
