"""DKIM-Signature 的 ``h=`` 头字段覆盖审计（RFC 6376），复用邮件头折行解析。

审计口径（只判断“字段覆盖”，**不校验签名真伪**）：
- 复用 :func:`mailtrace.parsing.parser.parse_header_blocks` 的折行展开，
  收集每一条 ``DKIM-Signature`` 字段（字段名大小写不敏感），每条签名独立审计。
- 解析签名标签（与 :mod:`mailtrace.parsing.arc` 共用同一套分号
  ``tag=value`` 解析），取出 ``h=`` 标签：按冒号切分为字段名列表，
  字段名去除空白、大小写不敏感，**保留重复出现的同名项**（重复字段名
  不能按集合合并），保持列表顺序。
- 按 RFC 6376 §3.7 / §5.4.2 的规则逐项匹配：自左向右处理 ``h=`` 列表，
  每一项从邮件头部**底部向上**（即从后追加的最新字段开始）寻找同名、且
  **尚未被本签名使用**的实际字段；同名字段存在多个副本时，后出现的
  ``h=`` 项会继续匹配更靠上的副本。字段位置为头部中实际出现的序号
  （1 = 第一个字段，按出现先后计数）。
- 当前被审计的这条 ``DKIM-Signature`` 自身不参与匹配（签名生成时它
  尚不存在；对他人签名做 countersignature 时，其他 DKIM-Signature
  照常可以被匹配）。
- 缺失 ``h=`` 标签或 ``h=`` 列表为空，对该签名记为异常；审计结果只
  表示字段覆盖情况，不宣称签名是否真实有效。
"""

from __future__ import annotations

from mailtrace.parsing.arc import _parse_tags
from mailtrace.parsing.parser import parse_header_blocks

STATUS_OK = "ok"
STATUS_ANOMALY = "anomaly"
STATUS_NONE = "none"

_STATUS_LABELS = {
    STATUS_OK: "DKIM 字段覆盖正常",
    STATUS_ANOMALY: "DKIM 字段覆盖异常",
    STATUS_NONE: "无 DKIM 签名",
}

DKIM_FIELD_NAME = "dkim-signature"

# 重点关注的实际字段副本（展示名大小写规范，匹配时统一小写）
CORE_FIELDS = [
    ("from", "From"),
    ("subject", "Subject"),
    ("to", "To"),
    ("date", "Date"),
]


def _split_h_list(h_value: str) -> list[str]:
    """把 ``h=`` 标签值按冒号切分为字段名列表（保留重复与空项，不做去重）。"""
    return [part.strip() for part in h_value.split(":")]


def _match_signature(index: int, block, blocks: list) -> dict:
    """审计单条 DKIM-Signature 字段的 h= 覆盖情况。"""
    tags, dup = _parse_tags(block.value)

    issues: list[dict] = []
    h_present = "h" in tags

    h_items: list[str] = []
    if not h_present:
        issues.append(
            {
                "code": "missing_h",
                "message": "该 DKIM-Signature 缺少 h= 标签"
                "（RFC 6376 要求签名列出已签名的头字段）",
            }
        )
    else:
        h_items = _split_h_list(tags["h"])
        if not h_items or all(item == "" for item in h_items):
            issues.append(
                {
                    "code": "empty_h",
                    "message": "该 DKIM-Signature 的 h= 标签为空"
                    "（未列出任何已签名头字段）",
                }
            )
        if "h" in dup:
            issues.append(
                {
                    "code": "duplicate_h",
                    "message": f"h= 标签在该 DKIM-Signature 中重复出现 {dup['h']} 次",
                }
            )

    used_positions: set[int] = set()
    h_results: list[dict] = []
    unmatched: list[dict] = []

    # RFC 6376 §5.4.2：自左向右处理 h= 列表，每项自头部底部向上取
    # 第一个同名且尚未被本签名使用的实际字段。
    for list_index, raw_name in enumerate(h_items, start=1):
        wanted = raw_name.lower()
        matched_block = None
        if wanted != "":
            for candidate in reversed(blocks):
                if candidate.order in used_positions:
                    continue
                if candidate.order == block.order:
                    # 被审计的签名自身不参与匹配
                    continue
                if candidate.name.lower() == wanted:
                    matched_block = candidate
                    break

        entry = {
            "list_index": list_index,
            "name": raw_name,
            "matched": matched_block is not None,
            "field_position": matched_block.order + 1 if matched_block else None,
            "value": matched_block.value if matched_block else None,
        }
        h_results.append(entry)
        if matched_block is not None:
            used_positions.add(matched_block.order)
        else:
            unmatched.append(
                {
                    "list_index": list_index,
                    "name": raw_name,
                    "message": (
                        "h= 中出现空字段名，无法匹配"
                        if wanted == ""
                        else f"头部中没有未被本签名使用的 {raw_name} 字段"
                    ),
                }
            )

    # From / Subject / To / Date 中未被该签名覆盖的实际字段副本
    uncovered: list[dict] = []
    for lower_name, display in CORE_FIELDS:
        for candidate in blocks:
            if candidate.order == block.order:
                continue
            if candidate.name.lower() != lower_name:
                continue
            if candidate.order in used_positions:
                continue
            uncovered.append(
                {
                    "field": display,
                    "position": candidate.order + 1,
                    "value": candidate.value,
                }
            )

    matched_count = sum(1 for item in h_results if item["matched"])
    status = STATUS_ANOMALY if issues else STATUS_OK

    return {
        "index": index,
        "status": status,
        "field_position": block.order + 1,
        "domain": tags.get("d"),
        "selector": tags.get("s"),
        "h_present": h_present,
        "h_count": len(h_items),
        "matched_count": matched_count,
        "unmatched_count": len(h_items) - matched_count,
        "issues": issues,
        "h_results": h_results,
        "unmatched": unmatched,
        "uncovered_core": uncovered,
        "raw": block.raw,
    }


def audit_dkim_coverage(raw_headers: str) -> dict:
    """审计邮件原始头部中每条 DKIM-Signature 的 h= 头字段覆盖情况。

    返回页面与 ``POST /api/dkim/coverage`` 共用的结构化结果；完全没有
    DKIM-Signature 字段时 ``status`` 为 ``"none"``。结果仅表示字段覆盖，
    不宣称签名真伪。
    """
    blocks = parse_header_blocks(raw_headers)
    dkim_blocks = [b for b in blocks if b.name.lower() == DKIM_FIELD_NAME]

    if not dkim_blocks:
        return {
            "status": STATUS_NONE,
            "status_label": _STATUS_LABELS[STATUS_NONE],
            "signature_count": 0,
            "anomaly_count": 0,
            "header_field_count": len(blocks),
            "signatures": [],
            "notice": "头部中没有 DKIM-Signature 字段：无 DKIM 签名，不判定通过。",
        }

    signatures = [
        _match_signature(i, block, blocks)
        for i, block in enumerate(dkim_blocks, start=1)
    ]
    anomaly_count = sum(1 for sig in signatures if sig["status"] == STATUS_ANOMALY)
    if anomaly_count:
        status = STATUS_ANOMALY
    else:
        status = STATUS_OK

    return {
        "status": status,
        "status_label": _STATUS_LABELS[status],
        "signature_count": len(signatures),
        "anomaly_count": anomaly_count,
        "header_field_count": len(blocks),
        "signatures": signatures,
        "notice": "结果仅表示 DKIM-Signature 的 h= 列表覆盖了哪些实际头字段，"
        "不校验也不宣称签名真伪（未验证 b= 签名值、域名与密钥）。",
    }
