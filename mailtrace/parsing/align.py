"""发件域对齐审计（单封邮件）。

复用 :func:`mailtrace.parsing.authres.analyze_auth_results` 的
Authentication-Results 归属结果，**只采纳本组织声明**（归属状态为
``own`` 的字段），从中提取 ``spf=pass`` 声明的 ``smtp.mailfrom`` 与
``dkim=pass`` 声明的 ``header.d`` 身份域，与头部**唯一 From 地址域**
比较：

- **严格模式**（``strict``）：身份域与 From 域完全相同
  （忽略大小写与末尾点）；
- **宽松模式**（``relaxed``）：身份域与 From 域**均为**所填发件组织域
  或其子域（按标签边界匹配：``sub.example.com`` 属于 ``example.com``，
  而 ``evil-example.com`` / ``example.com.evil.org`` 不属于）。

结论三选一：

- 任一可信通过声明对齐 → ``aligned``（**有对齐证据**）；
- 有可用通过声明（含身份域）但均不对齐 → ``not_aligned``
  （**未见对齐证据**）；
- 其余情况（From 域不可用、无本组织声明、无通过声明、通过声明缺
  身份域）→ ``insufficient``（**证据不足**）。

From 域必须**唯一**：重复 From 字段、单个 From 字段内多个地址、
缺失 From 字段或地址缺少域部分都会明确标记为对应状态，
**绝不静默择一**。
"""

from __future__ import annotations

from email.utils import getaddresses

from mailtrace.parsing.authres import STATUS_OWN, analyze_auth_results
from mailtrace.parsing.parser import _strip_paren_comments, parse_header_blocks
from mailtrace.parsing.trust import normalize_host

# 对齐结论
ALIGNED = "aligned"  # 有对齐证据
NOT_ALIGNED = "not_aligned"  # 未见对齐证据
INSUFFICIENT = "insufficient"  # 证据不足

_ALIGNMENT_LABELS = {
    ALIGNED: "有对齐证据",
    NOT_ALIGNED: "未见对齐证据",
    INSUFFICIENT: "证据不足",
}

# 比较模式
MODE_STRICT = "strict"
MODE_RELAXED = "relaxed"
_MODES = (MODE_STRICT, MODE_RELAXED)
_MODE_LABELS = {
    MODE_STRICT: "严格模式",
    MODE_RELAXED: "宽松模式",
}

# From 解析状态
FROM_OK = "ok"
FROM_MISSING_FIELD = "missing_field"  # 没有 From 字段
FROM_MULTIPLE_FIELDS = "multiple_fields"  # 重复 From 字段
FROM_NO_ADDRESS = "no_address"  # From 字段内解析不到地址
FROM_MULTIPLE_ADDRESSES = "multiple_addresses"  # 一个 From 字段内多个地址
FROM_MISSING_DOMAIN = "missing_domain"  # 地址缺少域部分

_FROM_STATUS_LABELS = {
    FROM_OK: "唯一 From 域",
    FROM_MISSING_FIELD: "缺少 From 字段",
    FROM_MULTIPLE_FIELDS: "重复 From 字段",
    FROM_NO_ADDRESS: "From 无地址",
    FROM_MULTIPLE_ADDRESSES: "From 含多个地址",
    FROM_MISSING_DOMAIN: "From 地址缺域",
}

# 证据不足的原因（alignment 为 insufficient 时给出；
# From 相关原因以 "from_" 前缀复用 From 状态码）
REASON_NO_ORG_CLAIMS = "no_org_claims"  # 无本组织声明
REASON_NO_PASS_CLAIMS = "no_pass_claims"  # 本组织声明中没有 spf/dkim 的 pass
REASON_NO_IDENTITY = "no_identity_domain"  # 通过声明均缺少身份域属性

# 各方法用于对齐比较的身份属性（属性名小写）
_IDENTITY_PROPS = {"spf": "smtp.mailfrom", "dkim": "header.d"}

# 单条声明的比较结果
COMPARE_ALIGNED = "aligned"
COMPARE_NOT_ALIGNED = "not_aligned"
COMPARE_NO_IDENTITY = "no_identity"  # 声明缺少身份域属性
COMPARE_NO_FROM = "no_from"  # From 域不可用，无法比较


def _is_org_or_subdomain(domain: str | None, org: str | None) -> bool:
    """``domain`` 是否为 ``org`` 本身或其子域（按标签边界匹配）。

    两者都应先经 :func:`normalize_host` 规范化；任一缺失返回 ``False``。
    ``evil-example.com`` 不是 ``example.com`` 的子域（标签边界），
    ``example.com.evil.org`` 也不是。
    """
    if not domain or not org:
        return False
    return domain == org or domain.endswith("." + org)


def _parse_from_domain(blocks: list) -> dict:
    """解析头部**唯一** From 地址域。

    重复 From 字段、单字段内多个地址、无 From、无地址、地址缺域
    都明确标记，绝不静默择一。
    """
    from_blocks = [b for b in blocks if b.name.lower() == "from"]
    info = {
        "status": FROM_OK,
        "status_label": _FROM_STATUS_LABELS[FROM_OK],
        "field_count": len(from_blocks),
        "field_positions": [b.order + 1 for b in from_blocks],
        "address": None,
        "domain": None,
        "detail": "",
    }

    if not from_blocks:
        info.update(
            status=FROM_MISSING_FIELD,
            status_label=_FROM_STATUS_LABELS[FROM_MISSING_FIELD],
            detail="头部中没有 From 字段，无法确定发件域",
        )
        return info

    if len(from_blocks) > 1:
        positions = "、".join(str(p) for p in info["field_positions"])
        info.update(
            status=FROM_MULTIPLE_FIELDS,
            status_label=_FROM_STATUS_LABELS[FROM_MULTIPLE_FIELDS],
            detail=(
                f"头部中出现 {len(from_blocks)} 个 From 字段"
                f"（分别位于第 {positions} 个字段），发件域不唯一，"
                "不静默择一"
            ),
        )
        return info

    value = from_blocks[0].value
    addresses = [addr.strip() for _name, addr in getaddresses([value]) if addr.strip()]
    if not addresses:
        info.update(
            status=FROM_NO_ADDRESS,
            status_label=_FROM_STATUS_LABELS[FROM_NO_ADDRESS],
            detail="From 字段中未解析到任何邮箱地址",
        )
        return info

    if len(addresses) > 1:
        shown = "、".join(addresses)
        info.update(
            status=FROM_MULTIPLE_ADDRESSES,
            status_label=_FROM_STATUS_LABELS[FROM_MULTIPLE_ADDRESSES],
            detail=(
                f"From 字段含有 {len(addresses)} 个地址（{shown}），"
                "发件域不唯一，不静默择一"
            ),
        )
        return info

    address = addresses[0]
    info["address"] = address
    domain = None
    if "@" in address:
        domain = normalize_host(address.rsplit("@", 1)[1])
    if domain is None:
        info.update(
            status=FROM_MISSING_DOMAIN,
            status_label=_FROM_STATUS_LABELS[FROM_MISSING_DOMAIN],
            detail=f"From 地址（{address}）缺少有效的域部分",
        )
        return info

    info.update(
        domain=domain,
        detail=f"唯一 From 地址 {address}，发件域 {domain}",
    )
    return info


def _parse_method_props(value: str) -> list[dict]:
    """把 Authentication-Results 值解析为带属性的方法列表（保持原文顺序）。

    每个条目为 ``{"method": 小写方法名, "result": 结果词, "props": dict}``；
    ``props`` 的键为小写属性名（如 ``smtp.mailfrom`` / ``header.d``），
    同名属性保留首次出现。圆括号注释先剥离，避免注释中的分号或等号
    干扰切分。
    """
    cleaned = _strip_paren_comments(value)
    entries: list[dict] = []
    for segment in cleaned.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, _, rest = segment.partition("=")
        method = name.strip().lower()
        tokens = rest.strip().split()
        result = tokens[0] if tokens else ""
        props: dict[str, str] = {}
        for token in tokens[1:]:
            if "=" not in token:
                continue
            pname, _, pval = token.partition("=")
            props.setdefault(pname.strip().lower(), pval.strip())
        entries.append({"method": method, "result": result, "props": props})
    return entries


def _compare_identity(
    method: str,
    prop: str,
    identity_domain: str | None,
    from_domain: str | None,
    mode: str,
    org_domain: str | None,
) -> tuple[str, bool | None, str]:
    """比较单条通过声明的身份域与 From 域。

    返回 ``(compare, aligned, detail)``：``compare`` 为
    ``aligned`` / ``not_aligned`` / ``no_identity`` / ``no_from``；
    无法比较时 ``aligned`` 为 ``None``。
    """
    if identity_domain is None:
        return (
            COMPARE_NO_IDENTITY,
            None,
            f"声明缺少 {prop} 属性（或属性值为空），无法提取身份域",
        )
    if from_domain is None:
        return (
            COMPARE_NO_FROM,
            None,
            "From 域不可用（见 From 域解析），无法比较",
        )

    if mode == MODE_STRICT:
        if identity_domain == from_domain:
            return (
                COMPARE_ALIGNED,
                True,
                f"严格模式：身份域 {identity_domain} 与 From 域完全相同",
            )
        return (
            COMPARE_NOT_ALIGNED,
            False,
            f"严格模式：身份域 {identity_domain} ≠ From 域 {from_domain}",
        )

    # 宽松模式：两域均为组织域或其子域（标签边界）
    identity_in = _is_org_or_subdomain(identity_domain, org_domain)
    from_in = _is_org_or_subdomain(from_domain, org_domain)
    if identity_in and from_in:
        return (
            COMPARE_ALIGNED,
            True,
            f"宽松模式：身份域 {identity_domain} 与 From 域 {from_domain} "
            f"均为组织域 {org_domain} 或其子域",
        )
    misses = []
    if not identity_in:
        misses.append(f"身份域 {identity_domain} 不在组织域 {org_domain} 内")
    if not from_in:
        misses.append(f"From 域 {from_domain} 不在组织域 {org_domain} 内")
    return (
        COMPARE_NOT_ALIGNED,
        False,
        "宽松模式：" + "；".join(misses) + "（按标签边界匹配）",
    )


def analyze_from_alignment(
    raw_headers: str,
    trusted_hosts: str | list[str] | tuple[str, ...],
    org_domain: str | None = None,
    mode: str = MODE_STRICT,
) -> dict:
    """发件域对齐审计：本组织通过声明的身份域是否与 From 域对齐。

    返回供页面 / ``POST /api/analyze/from-alignment`` 共用的结构化结果；
    名单为空、宽松模式缺组织域、模式非法等输入错误返回
    ``{"error": ...}``（调用方据此回 400）。
    """
    if mode not in _MODES:
        return {"error": "mode 必须是 strict（严格模式）或 relaxed（宽松模式）"}
    org = normalize_host(org_domain)
    if mode == MODE_RELAXED and org is None:
        return {
            "error": "宽松模式需要填写发件组织域（如 example.com），"
            "用于判断两域是否均为组织域或其子域"
        }

    # 复用现有 Authentication-Results 归属，只采纳本组织声明
    authres = analyze_auth_results(raw_headers, trusted_hosts)
    if "error" in authres:
        return {"error": authres["error"]}

    blocks = parse_header_blocks(raw_headers)
    blocks_by_position = {b.order + 1: b for b in blocks}
    from_info = _parse_from_domain(blocks)
    from_domain = from_info["domain"]

    # 逐条提取本组织声明中 spf=pass / dkim=pass 的身份域并比较
    claims: list[dict] = []
    for entry in authres["results"]:
        if entry["status"] != STATUS_OWN:
            continue
        block = blocks_by_position.get(entry["field_position"])
        if block is None:  # pragma: no cover - 归属结果与字段位置一一对应
            continue
        for item in _parse_method_props(block.value):
            method = item["method"]
            if method not in _IDENTITY_PROPS:
                continue
            if item["result"].lower() != "pass":
                continue
            prop = _IDENTITY_PROPS[method]
            identity_raw = item["props"].get(prop) or None
            identity_domain = normalize_host(identity_raw)
            compare, aligned, detail = _compare_identity(
                method,
                prop,
                identity_domain,
                from_domain,
                mode,
                org,
            )
            claims.append(
                {
                    "method": method,
                    "result": "pass",
                    "identity_prop": prop,
                    "identity_raw": identity_raw,
                    "identity_domain": identity_domain,
                    "field_index": entry["index"],
                    "field_position": entry["field_position"],
                    "hop_top_index": entry["hop_top_index"],
                    "authserv_id": entry["authserv_id"],
                    "compare": compare,
                    "aligned": aligned,
                    "detail": detail,
                }
            )

    usable_claims = [c for c in claims if c["identity_domain"] is not None]
    aligned_claims = [c for c in usable_claims if c["aligned"]]
    own_count = authres["own_count"]
    mode_label = _MODE_LABELS[mode]

    # 结论：任一对齐 → 有对齐证据；有可用通过声明但均不对齐 →
    # 未见对齐证据；其余 → 证据不足
    if from_info["status"] != FROM_OK:
        alignment = INSUFFICIENT
        reason: str | None = f"from_{from_info['status']}"
        message = f"证据不足：{from_info['detail']}。"
    elif aligned_claims:
        alignment = ALIGNED
        reason = None
        first = aligned_claims[0]
        message = (
            f"有对齐证据：第 {first['field_index']} 条 Authentication-Results"
            f"（归属头部自上而下第 {first['hop_top_index']} 跳）的 "
            f"{first['method']}=pass 声明身份域 {first['identity_domain']} "
            f"与 From 域 {from_domain} 对齐（{mode_label}）"
        )
        if len(aligned_claims) > 1:
            message += f"；另有 {len(aligned_claims) - 1} 条声明同样对齐"
        message += "。"
    elif usable_claims:
        alignment = NOT_ALIGNED
        reason = None
        message = (
            f"未见对齐证据：{len(usable_claims)} 条本组织通过声明的身份域"
            f"均未与 From 域 {from_domain} 对齐（{mode_label}），"
            "逐条比较结果见下。"
        )
    else:
        alignment = INSUFFICIENT
        if own_count == 0:
            reason = REASON_NO_ORG_CLAIMS
            message = (
                "证据不足：无本组织声明（Authentication-Results 归属），"
                "没有可用于对齐判断的可信通过声明。"
            )
        elif not claims:
            reason = REASON_NO_PASS_CLAIMS
            message = (
                f"证据不足：{own_count} 条本组织声明中没有 "
                "spf=pass / dkim=pass 通过声明。"
            )
        else:
            reason = REASON_NO_IDENTITY
            message = (
                "证据不足：本组织通过声明均缺少 smtp.mailfrom / header.d "
                "身份域，无法比较。"
            )

    return {
        "status": authres["status"],
        "status_label": authres["status_label"],
        "message": message,
        "mode": mode,
        "mode_label": mode_label,
        "org_domain": org,
        "alignment": alignment,
        "alignment_label": _ALIGNMENT_LABELS[alignment],
        "alignment_reason": reason,
        "from": from_info,
        "trusted_hosts": authres["trusted_hosts"],
        "trusted_count": authres["trusted_count"],
        "ar_count": authres["ar_count"],
        "own_count": own_count,
        "no_org_claims": authres["no_org_claims"],
        "no_org_reason": authres["no_org_reason"],
        "claim_count": len(claims),
        "usable_claim_count": len(usable_claims),
        "aligned_claim_count": len(aligned_claims),
        "claims": claims,
    }
