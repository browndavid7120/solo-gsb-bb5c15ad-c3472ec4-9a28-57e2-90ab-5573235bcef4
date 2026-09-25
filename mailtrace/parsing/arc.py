"""ARC 链结构检查（RFC 8617），复用邮件头折行解析。

检查口径：
- 复用 :func:`mailtrace.parsing.parser.parse_header_blocks` 的折行展开，
  收集 ``ARC-Seal`` / ``ARC-Message-Signature`` /
  ``ARC-Authentication-Results`` 三类字段（字段名大小写不敏感）。
- 按 ``i`` 标签（实例号）归组：tag=value 列表按分号切分，标签名大小写
  不敏感、与书写顺序无关，因此折行与标签顺序变化不影响识别。
- 每个实例必须恰好各有三类字段一条；实例号必须从 1 开始连续（不允许
  跳号）；首个实例（i=1）的 ARC-Seal ``cv`` 必须为 ``none``，后续实例
  必须为 ``pass``（cv 比较忽略大小写）。
- 非法 ``i``（缺失 / 非正整数 / 超出 RFC 8617 规定的 1-50 / 同一字段内
  重复）、字段重复或缺失、跳号、``cv`` 异常都会逐项定位到具体实例与
  字段；完全没有 ARC 字段时返回 ``status="none"``（无 ARC 链），
  不判定通过。
"""

from __future__ import annotations

import re

from mailtrace.parsing.parser import parse_header_blocks

# 三类 ARC 字段：小写字段名 -> (结果字典键, 展示名)
ARC_FIELD_TYPES = {
    "arc-seal": ("seal", "ARC-Seal"),
    "arc-message-signature": ("message_signature", "ARC-Message-Signature"),
    "arc-authentication-results": (
        "authentication_results",
        "ARC-Authentication-Results",
    ),
}

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_NONE = "none"

_STATUS_LABELS = {
    STATUS_PASS: "ARC 链结构完整",
    STATUS_FAIL: "ARC 链结构异常",
    STATUS_NONE: "无 ARC 链",
}

_I_VALUE_RE = re.compile(r"^[0-9]+$")

# RFC 8617：实例号 i 的合法范围为 1-50
MAX_INSTANCE = 50


def _parse_tags(value: str) -> tuple[dict[str, str], dict[str, int]]:
    """把分号分隔的 tag=value 列表解析为字典。

    返回 ``(标签字典, 重复标签总次数)``；标签名统一小写，与标签书写
    顺序无关。不带 ``=`` 的片段（如 AAR 的 authserv-id）直接跳过。
    """
    tags: dict[str, str] = {}
    duplicates: dict[str, int] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, val = part.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in tags:
            duplicates[name] = duplicates.get(name, 1) + 1
        else:
            tags[name] = val.strip()
    return tags, duplicates


def _add_issue(
    issues: list[dict],
    instance: int | None,
    field: str | None,
    code: str,
    message: str,
) -> None:
    issues.append(
        {
            "instance": instance,
            "field": field,
            "code": code,
            "message": message,
        }
    )


def _check_seal_cv(
    issues: list[dict], i: int, items: list[dict], info: dict
) -> None:
    """校验单个实例 ARC-Seal 的 cv 标签（i=1 须为 none，其余须为 pass）。"""
    expected = "none" if i == 1 else "pass"
    info["cv_expected"] = expected
    if not items:
        info["cv"] = None
        info["cv_ok"] = None
        return
    tags = items[0]["tags"]
    dup = items[0]["dup"]
    cv = tags.get("cv")
    info["cv"] = cv
    if "cv" in dup:
        info["cv_ok"] = False
        _add_issue(
            issues, i, "ARC-Seal", "cv_bad",
            f"实例 i={i} 的 ARC-Seal cv 标签重复出现 {dup['cv']} 次",
        )
    elif cv is None:
        info["cv_ok"] = False
        _add_issue(
            issues, i, "ARC-Seal", "cv_missing",
            f"实例 i={i} 的 ARC-Seal 缺少 cv 标签（应为 {expected}）",
        )
    elif cv.lower() != expected:
        info["cv_ok"] = False
        _add_issue(
            issues, i, "ARC-Seal", "cv_bad",
            f"实例 i={i} 的 ARC-Seal cv={cv}，应为 {expected}"
            f"（{'首个实例' if i == 1 else '后续实例'}的 Seal cv 须为 {expected}）",
        )
    else:
        info["cv_ok"] = True


def check_arc_chain(raw_headers: str) -> dict:
    """检查邮件原始头部中的 ARC 链结构。

    返回页面与 ``POST /api/arc/check`` 共用的结构化结果；完全没有
    ARC 字段时 ``status`` 为 ``"none"``（无 ARC 链，不判通过）。
    """
    blocks = parse_header_blocks(raw_headers)
    arc_blocks = [b for b in blocks if b.name.lower() in ARC_FIELD_TYPES]

    issues: list[dict] = []
    invalid_fields: list[dict] = []
    # 实例号 -> 字段键 -> [{"block": ..., "tags": ..., "dup": ...}, ...]
    grouped: dict[int, dict[str, list[dict]]] = {}

    for block in arc_blocks:
        key, display = ARC_FIELD_TYPES[block.name.lower()]
        tags, dup_tags = _parse_tags(block.value)
        i_raw = tags.get("i")
        i_num: int | None = None
        code = ""
        message = ""
        if i_raw is None:
            code = "missing_i"
            message = f"{display} 字段缺少 i 标签，无法归入任何实例"
        elif "i" in dup_tags:
            code = "invalid_i"
            message = f"{display} 字段的 i 标签重复出现 {dup_tags['i']} 次"
        elif not _I_VALUE_RE.match(i_raw):
            code = "invalid_i"
            message = f"{display} 字段的 i 标签值 “{i_raw}” 不是正整数"
        elif not 1 <= int(i_raw) <= MAX_INSTANCE:
            code = "invalid_i"
            message = (
                f"{display} 字段的 i 标签值 “{i_raw}” 超出有效范围"
                f"（RFC 8617 规定 1-{MAX_INSTANCE}）"
            )
        else:
            i_num = int(i_raw)

        if i_num is None:
            _add_issue(issues, None, display, code, message)
            invalid_fields.append(
                {
                    "field": display,
                    "i_raw": i_raw,
                    "raw": block.raw,
                    "message": message,
                }
            )
            continue
        grouped.setdefault(i_num, {}).setdefault(key, []).append(
            {"block": block, "tags": tags, "dup": dup_tags}
        )

    instances: list[dict] = []
    found = sorted(grouped)
    for i in found:
        fields = grouped[i]
        entry: dict = {"i": i}
        for key, display in ARC_FIELD_TYPES.values():
            items = fields.get(key, [])
            count = len(items)
            info: dict = {
                "present": count > 0,
                "count": count,
                "raw": items[0]["block"].raw if items else None,
            }
            if count == 0:
                _add_issue(
                    issues, i, display, "missing_field",
                    f"实例 i={i} 缺少 {display} 字段（每实例须三类字段各一条）",
                )
            elif count > 1:
                _add_issue(
                    issues, i, display, "duplicate_field",
                    f"实例 i={i} 的 {display} 字段重复出现 {count} 次"
                    "（每实例应恰好一条）",
                )
            if key == "seal":
                _check_seal_cv(issues, i, items, info)
            entry[key] = info
        instances.append(entry)

    # 实例号必须从 1 开始连续：1..max 中缺失的号码逐项报告
    if found:
        missing_numbers = [n for n in range(1, found[-1] + 1) if n not in grouped]
    else:
        missing_numbers = []
    for n in missing_numbers:
        _add_issue(
            issues, n, None, "gap",
            f"实例号 i={n} 缺失：实例号必须从 1 开始连续，不允许跳号",
        )

    bad_instances = {
        iss["instance"] for iss in issues if iss["instance"] is not None
    }
    for entry in instances:
        entry["ok"] = entry["i"] not in bad_instances

    if not arc_blocks:
        status = STATUS_NONE
    elif issues:
        status = STATUS_FAIL
    else:
        status = STATUS_PASS

    return {
        "status": status,
        "status_label": _STATUS_LABELS[status],
        "arc_field_count": len(arc_blocks),
        "instance_count": len(instances),
        "error_count": len(issues),
        "issues": issues,
        "instances": instances,
        "invalid_fields": invalid_fields,
        "numbering": {
            "ok": not missing_numbers,
            "found": found,
            "missing": missing_numbers,
        },
    }
