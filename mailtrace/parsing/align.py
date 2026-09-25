"""发件域对齐审计（基于本组织 Authentication-Results 声明）。

复用 :func:`mailtrace.parsing.authres.analyze_auth_results` 的归属判定，
**只采纳本组织声明**（归属自顶端连续可信前缀内接收跳、且 authserv-id
与该跳 ``by`` 主机一致的 ``Authentication-Results`` 字段），从中提取：

- ``spf=pass`` 声明的 ``smtp.mailfrom`` 身份域；
- ``dkim=pass`` 声明的 ``header.d`` 身份域；

并解析头部**唯一** ``From`` 地址的域，与上述身份域比较：

- **严格模式**（``strict``）：身份域与 From 域**完全相同**（忽略大小写
  与末尾点）才算对齐；
- **宽松模式**（``relaxed``）：From 域与身份域**均为所填发件组织域或
  其子域**（按标签边界匹配——``example.com`` 不匹配
  ``notexample.com``，但匹配 ``mail.example.com``）才算对齐。

总体结论三选一：

- ``aligned``（**有对齐证据**）：至少一条可信通过声明对齐；
- ``not_aligned``（**未见对齐证据**）：有可用通过声明但均不对齐；
- ``insufficient``（**证据不足**）：其余情况——无本组织声明、没有
  ``spf=pass`` / ``dkim=pass``、通过声明缺少身份域，或 From 域
  缺失 / 重复 / 无法解析。

``From`` 字段重复、单个字段含多个地址、或地址缺失域时**不静默择一**，
一律明确标记并判定证据不足。审计仅采纳本组织接收服务器当时写下的
认证结果声明，本工具不自行验证 SPF / DKIM。
"""

from __future__ import annotations

import re
from email.utils import getaddresses

from mailtrace.parsing.authres import STATUS_OWN, analyze_auth_results
from mailtrace.parsing.parser import _strip_paren_comments, parse_header_blocks
from mailtrace.parsing.trust import parse_trusted_hosts

# 总体结论
STATUS_ALIGNED = "aligned"  # 有对齐证据
STATUS_NOT_ALIGNED = "not_aligned"  # 未见对齐证据
STATUS_INSUFFICIENT = "insufficient"  # 证据不足

_STATUS_LABELS = {
    STATUS_ALIGNED: "有对齐证据",
    STATUS_NOT_ALIGNED: "未见对齐证据",
    STATUS_INSUFFICIENT: "证据不足",
}

# 比较模式
MODE_STRICT = "strict"
MODE_RELAXED = "relaxed"

_MODE_LABELS = {
    MODE_STRICT: "严格模式",
    MODE_RELAXED: "宽松模式",
}

# From 解析状态
FROM_OK = "ok"  # 唯一 From 字段、唯一地址、域合法
FROM_MISSING = "missing"  # 没有 From 字段
FROM_MULTIPLE_FIELDS = "multiple_fields"  # 重复 From 字段
FROM_MULTIPLE_ADDRESSES = "multiple_addresses"  # 单个字段含多个地址
FROM_NO_ADDRESS = "no_address"  # 解析不出地址
FROM_NO_DOMAIN = "no_domain"  # 地址中缺少域
FROM_INVALID_DOMAIN = "invalid_domain"  # 域格式非法

_FROM_LABELS = {
    FROM_OK: "已解析唯一 From 域",
    FROM_MISSING: "缺少 From 字段",
    FROM_MULTIPLE_FIELDS: "重复 From 字段",
    FROM_MULTIPLE_ADDRESSES: "From 含多个地址",
    FROM_NO_ADDRESS: "From 中无可解析地址",
    FROM_NO_DOMAIN: "From 地址缺少域",
    FROM_INVALID_DOMAIN: "From 域格式非法",
}

# 单条声明的比较状态
CLAIM_ALIGNED = "aligned"  # 对齐（采纳为证据）
CLAIM_NOT_ALIGNED = "not_aligned"  # 不对齐
CLAIM_NO_IDENTITY = "no_identity"  # pass 但缺少身份域
CLAIM_NOT_PASS = "not_pass"  # 非 pass 声明，不参与
CLAIM_UNCOMPARABLE = "uncomparable"  # From 域不可用，无法比较

_CLAIM_LABELS = {
    CLAIM_ALIGNED: "对齐",
    CLAIM_NOT_ALIGNED: "不对齐",
    CLAIM_NO_IDENTITY: "缺少身份域",
    CLAIM_NOT_PASS: "非 pass 声明",
    CLAIM_UNCOMPARABLE: "无法比较",
}

# 证据不足的原因（status 为 insufficient 时给出；from 类原因直接加前缀）
REASON_NO_OWN_CLAIMS = "no_own_claims"  # 无本组织声明
REASON_NO_PASS_CLAIMS = "no_pass_claims"  # 本组织声明中没有 spf=pass / dkim=pass
REASON_NO_USABLE_CLAIMS = "no_usable_claims"  # 有 pass 声明但都缺少身份域

# 每种方法用于对齐的身份属性
_METHOD_PROPS = {"spf": "smtp.mailfrom", "dkim": "header.d"}

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str | None) -> str | None:
    """域名规范化：去空白、转小写、去末尾点并逐标签校验；非法返回 ``None``。"""
    if not value:
        return None
    domain = value.strip().lower().rstrip(".").strip()
    if not domain or len(domain) > 253:
        return None
    for label in domain.split("."):
        if not _DOMAIN_LABEL_RE.match(label):
            return None
    return domain


def _in_org_tree(domain: str, org_domain: str) -> bool:
    """``domain`` 是否为 ``org_domain`` 本身或其子域（按标签边界匹配）。"""
    return domain == org_domain or domain.endswith("." + org_domain)


def _parse_from_domain(blocks: list) -> dict:
    """解析头部唯一 ``From`` 地址的域。

    重复 ``From`` 字段、单字段多地址、缺地址 / 缺域 / 域非法都明确标记，
    **不静默择一**（此时 ``domain`` 为 ``None``，总体结论为证据不足）。
    """
    from_blocks = [b for b in blocks if b.name.lower() == "from"]
    base = {
        "domain": None,
        "address": None,
        "field_count": len(from_blocks),
        "field_positions": [b.order + 1 for b in from_blocks],
        "addresses": [],
    }

    if not from_blocks:
        return {
            **base,
            "status": FROM_MISSING,
            "status_label": _FROM_LABELS[FROM_MISSING],
            "detail": "头部中没有 From 字段，无法确定发件人地址域",
        }

    if len(from_blocks) > 1:
        positions = "、".join(str(p) for p in base["field_positions"])
        return {
            **base,
            "status": FROM_MULTIPLE_FIELDS,
            "status_label": _FROM_LABELS[FROM_MULTIPLE_FIELDS],
            "detail": (
                f"头部中出现 {len(from_blocks)} 个 From 字段"
                f"（分别位于第 {positions} 个字段），不静默择一，"
                "无法确定唯一 From 域"
            ),
        }

    block = from_blocks[0]
    parsed = getaddresses([block.value])
    addresses = [addr.strip() for _name, addr in parsed if addr and addr.strip()]
    # 只有含 @ 的才是可用于取域的邮箱地址（裸显示名等噪声不计入）
    mailboxes = [a for a in addresses if "@" in a]
    base["addresses"] = addresses

    if not mailboxes:
        return {
            **base,
            "status": FROM_NO_ADDRESS,
            "status_label": _FROM_LABELS[FROM_NO_ADDRESS],
            "detail": "From 字段中解析不出任何含域的邮箱地址",
        }
    if len(mailboxes) > 1:
        return {
            **base,
            "status": FROM_MULTIPLE_ADDRESSES,
            "status_label": _FROM_LABELS[FROM_MULTIPLE_ADDRESSES],
            "detail": (
                f"From 字段含有 {len(mailboxes)} 个邮箱地址"
                f"（{'、'.join(mailboxes)}），不静默择一，"
                "无法确定唯一 From 域"
            ),
        }

    address = mailboxes[0]
    domain_part = address.rsplit("@", 1)[1].strip().strip("<>").strip()
    if not domain_part:
        return {
            **base,
            "address": address,
            "status": FROM_NO_DOMAIN,
            "status_label": _FROM_LABELS[FROM_NO_DOMAIN],
            "detail": f"From 地址（{address}）中 @ 之后没有域",
        }
    domain = normalize_domain(domain_part)
    if domain is None:
        return {
            **base,
            "address": address,
            "status": FROM_INVALID_DOMAIN,
            "status_label": _FROM_LABELS[FROM_INVALID_DOMAIN],
            "detail": f"From 地址（{address}）中的域（{domain_part}）不是合法域名",
        }
    return {
        **base,
        "domain": domain,
        "address": address,
        "status": FROM_OK,
        "status_label": _FROM_LABELS[FROM_OK],
        "detail": f"唯一 From 地址 {address}，地址域 {domain}",
    }


def _extract_claims(value: str) -> list[dict]:
    """从一条 Authentication-Results 字段值提取 spf / dkim 声明及身份属性。

    保持原文顺序与重复；圆括号注释先剥离，避免注释里的分号或等号干扰
    切分。每条声明记录方法、结果词与对应身份属性（spf → smtp.mailfrom，
    dkim → header.d）的原始值。
    """
    cleaned = _strip_paren_comments(value)
    claims: list[dict] = []
    for segment in cleaned.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, _, rest = segment.partition("=")
        method = name.strip().lower()
        if method not in _METHOD_PROPS:
            continue
        tokens = rest.strip().split()
        result = tokens[0] if tokens else ""
        props: dict[str, str] = {}
        for token in tokens[1:]:
            if "=" not in token:
                continue
            pname, _, pval = token.partition("=")
            props.setdefault(pname.strip().lower(), pval.strip())
        prop_name = _METHOD_PROPS[method]
        claims.append(
            {
                "method": method,
                "result": result,
                "identity_prop": prop_name,
                "identity_raw": props.get(prop_name),
            }
        )
    return claims


def _identity_domain(method: str, identity_raw: str | None) -> tuple[str | None, str | None]:
    """从声明身份属性值提取身份域；失败时返回 ``(None, 原因说明)``。

    ``smtp.mailfrom`` 是邮箱地址（取 ``@`` 之后部分；空地址如退信的
    ``<>`` 无域可取），``header.d`` 直接是域名。
    """
    prop = _METHOD_PROPS[method]
    if identity_raw is None:
        return None, f"声明中缺少 {prop} 属性"
    value = identity_raw.strip().strip("<>").strip()
    if not value:
        return None, f"{prop} 为空（如退信的空 MAIL FROM）"
    if method == "spf" and "@" in value:
        value = value.rsplit("@", 1)[1].strip()
    domain = normalize_domain(value)
    if domain is None:
        return None, f"{prop} 中的值（{identity_raw}）不含合法域名"
    return domain, None


def _compare_identity(
    identity_domain: str, from_domain: str, mode: str, org_domain: str | None
) -> tuple[bool, str]:
    """按模式比较身份域与 From 域，返回 ``(是否对齐, 比较说明)``。"""
    if mode == MODE_STRICT:
        if identity_domain == from_domain:
            return True, (
                f"身份域 {identity_domain} 与 From 域 {from_domain} 完全相同"
                "（严格模式要求完全相同）"
            )
        return False, (
            f"身份域 {identity_domain} 与 From 域 {from_domain} 不完全相同"
            "（严格模式要求完全相同，子域也不算对齐）"
        )
    # 宽松模式：两域均为发件组织域或其子域（按标签边界匹配）
    identity_in = _in_org_tree(identity_domain, org_domain or "")
    from_in = _in_org_tree(from_domain, org_domain or "")
    if identity_in and from_in:
        return True, (
            f"身份域 {identity_domain} 与 From 域 {from_domain} 均为发件组织域 "
            f"{org_domain} 或其子域（按标签边界匹配）"
        )
    if not identity_in:
        return False, (
            f"身份域 {identity_domain} 不在发件组织域 {org_domain} 及其子域内"
            "（按标签边界匹配）"
        )
    return False, (
        f"From 域 {from_domain} 不在发件组织域 {org_domain} 及其子域内"
        "（按标签边界匹配）"
    )


def audit_sender_alignment(
    raw_headers: str,
    trusted_hosts: str | list[str] | tuple[str, ...],
    org_domain: str | None = None,
    mode: str | None = None,
) -> dict:
    """审计发件域对齐：本组织通过声明的身份域是否与唯一 From 域对齐。

    返回供页面 / ``POST /api/analyze/sender-alignment`` 共用的结构化结果；
    名单为空、``mode`` 非法、宽松模式缺少发件组织域或组织域非法时返回
    ``{"error": ...}``（调用方据此回 400）。
    """
    if mode is None or (isinstance(mode, str) and not mode.strip()):
        mode_norm = MODE_STRICT
    elif isinstance(mode, str) and mode.strip().lower() in _MODE_LABELS:
        mode_norm = mode.strip().lower()
    else:
        return {"error": "mode 必须是 strict（严格模式）或 relaxed（宽松模式）"}

    if org_domain is not None and not isinstance(org_domain, str):
        return {"error": "org_domain 必须是字符串（发件组织域，如 example.com）"}
    org = normalize_domain(org_domain)
    if org_domain is not None and org_domain.strip() and org is None:
        return {"error": f"发件组织域（{org_domain}）不是合法域名"}
    if mode_norm == MODE_RELAXED and org is None:
        return {
            "error": "宽松模式必须填写发件组织域（org_domain）："
            "From 域与身份域均须为该域或其子域（按标签边界匹配）"
        }

    try:
        hosts, _host_set = parse_trusted_hosts(trusted_hosts)
    except TypeError as exc:
        return {"error": str(exc)}
    if not hosts:
        return {
            "error": "本组织接收服务器主机名名单不能为空，请每行填写一个主机名"
        }

    # 复用现有 Authentication-Results 归属，只采纳本组织声明
    authres = analyze_auth_results(raw_headers, hosts)
    blocks = parse_header_blocks(raw_headers)
    from_info = _parse_from_domain(blocks)
    from_ok = from_info["status"] == FROM_OK
    from_domain = from_info["domain"]

    claim_rows: list[dict] = []
    pass_count = 0
    usable_count = 0
    aligned_count = 0
    for entry in authres["results"]:
        if entry["status"] != STATUS_OWN:
            continue  # 只采纳本组织声明
        # field_position 即字段在 blocks 中的序号（从 1 开始）
        block = blocks[entry["field_position"] - 1]
        for claim in _extract_claims(block.value):
            row = {
                "index": len(claim_rows) + 1,
                "method": claim["method"],
                "result": claim["result"],
                "field_index": entry["index"],
                "field_position": entry["field_position"],
                "hop_top_index": entry["hop_top_index"],
                "hop_by_host": entry["hop_by_host"],
                "authserv_id": entry["authserv_id"],
                "identity_prop": claim["identity_prop"],
                "identity_raw": claim["identity_raw"],
                "identity_domain": None,
            }
            if claim["result"].lower() != "pass":
                row["status"] = CLAIM_NOT_PASS
                row["status_label"] = _CLAIM_LABELS[CLAIM_NOT_PASS]
                row["detail"] = (
                    f"{claim['method']}={claim['result'] or '（空）'} 不是 pass，"
                    "不作为对齐证据（仅 spf=pass / dkim=pass 参与比较）"
                )
            else:
                pass_count += 1
                domain, note = _identity_domain(
                    claim["method"], claim["identity_raw"]
                )
                row["identity_domain"] = domain
                if domain is None:
                    row["status"] = CLAIM_NO_IDENTITY
                    row["status_label"] = _CLAIM_LABELS[CLAIM_NO_IDENTITY]
                    row["detail"] = note + "，无法参与对齐比较"
                elif not from_ok:
                    usable_count += 1
                    row["status"] = CLAIM_UNCOMPARABLE
                    row["status_label"] = _CLAIM_LABELS[CLAIM_UNCOMPARABLE]
                    row["detail"] = (
                        f"身份域 {domain} 可用，但 From 域"
                        f"（{from_info['status_label']}）无法确定，不能比较"
                    )
                else:
                    usable_count += 1
                    aligned, detail = _compare_identity(
                        domain, from_domain, mode_norm, org
                    )
                    row["status"] = (
                        CLAIM_ALIGNED if aligned else CLAIM_NOT_ALIGNED
                    )
                    row["status_label"] = _CLAIM_LABELS[row["status"]]
                    row["detail"] = detail
                    if aligned:
                        aligned_count += 1
            claim_rows.append(row)

    # 总体结论
    reason: str | None = None
    if not from_ok:
        status = STATUS_INSUFFICIENT
        reason = f"from_{from_info['status']}"
        message = (
            f"证据不足：{from_info['detail']}。不静默择一，"
            "无法确定唯一 From 域时不做任何对齐判定。"
        )
    elif aligned_count:
        status = STATUS_ALIGNED
        message = (
            f"有对齐证据：{aligned_count} 条本组织通过声明的身份域与 From 域 "
            f"{from_domain} 对齐（{_MODE_LABELS[mode_norm]}）。"
            "仅采纳归属本组织可信前缀的 Authentication-Results 声明。"
        )
    elif usable_count:
        status = STATUS_NOT_ALIGNED
        message = (
            f"未见对齐证据：{usable_count} 条可用通过声明"
            "（spf=pass / dkim=pass 且含身份域）的身份域均不与 From 域 "
            f"{from_domain} 对齐（{_MODE_LABELS[mode_norm]}）。"
        )
    else:
        status = STATUS_INSUFFICIENT
        if authres["no_org_claims"]:
            reason = REASON_NO_OWN_CLAIMS
            message = (
                "证据不足：无本组织声明，没有可采纳的认证结果"
                f"（{authres['message'].rstrip('。')}）。"
            )
        elif pass_count == 0:
            reason = REASON_NO_PASS_CLAIMS
            message = (
                "证据不足：本组织声明中没有 spf=pass 或 dkim=pass"
                "（仅 pass 结果可作为对齐证据）。"
            )
        else:
            reason = REASON_NO_USABLE_CLAIMS
            message = (
                f"证据不足：{pass_count} 条通过声明均缺少可用身份域"
                "（spf 需 smtp.mailfrom、dkim 需 header.d）。"
            )

    return {
        "status": status,
        "status_label": _STATUS_LABELS[status],
        "reason": reason,
        "message": message,
        "mode": mode_norm,
        "mode_label": _MODE_LABELS[mode_norm],
        "org_domain": org,
        "trusted_hosts": authres["trusted_hosts"],
        "from": from_info,
        "trust_status": authres["status"],
        "trust_status_label": authres["status_label"],
        "trusted_count": authres["trusted_count"],
        "ar_count": authres["ar_count"],
        "own_count": authres["own_count"],
        "no_org_claims": authres["no_org_claims"],
        "no_org_reason": authres["no_org_reason"],
        "claim_count": len(claim_rows),
        "pass_claim_count": pass_count,
        "usable_claim_count": usable_count,
        "aligned_count": aligned_count,
        "claims": claim_rows,
        "notice": (
            "对齐结论仅采纳归属本组织可信前缀的 Authentication-Results 声明"
            "（本组织接收服务器当时写下的认证结果）；本工具不自行验证 "
            "SPF / DKIM，结论可信度取决于这些声明本身。"
        ),
    }
