"""单封邮件接收链可信边界分析。

从头部**最上方**（最终接收服务器最新追加的一条）开始，自上而下逐跳检查
``Received`` 的 ``by`` 主机名：

- 只有从第一跳起**连续命中**本组织接收服务器名单的跳才标记为可信；
- 首个 ``by`` 未命中名单（或该跳缺少 ``by``）的跳即可信**边界**；
- 边界之后的所有跳一律不可信——即使 ``by`` 再次命中名单（外部主机
  冒用本组织主机名、退信后重新注入等），也**不会重新接入**可信链。

最后可信跳记录的 ``from`` 主机与对端 IP，就是本组织边缘接收服务器看到的
**外部交接点**。主机名比较忽略大小写与末尾点（与 compare/batch 的
规范化口径一致）。

解析直接复用 :func:`mailtrace.parsing.parser.analyze_headers` 的结果，
不重复实现 Received 解析。
"""

from __future__ import annotations

import re

from mailtrace.parsing.parser import analyze_headers

# 名单支持“每行一个”，也兼容逗号 / 空白分隔
_SPLIT_RE = re.compile(r"[,\s]+")

# 已建立可信链（至少顶端连续一跳命中；可能在中间到达边界）
STATUS_ESTABLISHED = "established"
# 顶端第一跳即未命中 / 缺少 by：无法建立可信链
STATUS_UNTRUSTED_TOP = "untrusted_top"
# 头部中没有任何 Received 字段
STATUS_NO_RECEIVED = "no_received"


def normalize_host(value: str | None) -> str | None:
    """主机名规范化：去空白、转小写、去末尾点；空值返回 ``None``。"""
    if not value:
        return None
    host = value.strip().lower().rstrip(".").strip()
    return host or None


def parse_trusted_hosts(
    raw: str | list[str] | tuple[str, ...],
) -> tuple[list[str], set[str]]:
    """把名单输入（字符串或字符串数组）规范化为 ``(有序去重名单, 集合)``。

    字符串按逗号 / 换行 / 空白切分；名单项忽略大小写与末尾点，
    规范化后去重并保留首次出现顺序。非字符串元素抛出 ``TypeError``，
    由调用方转为输入错误。
    """
    if isinstance(raw, str):
        tokens = _SPLIT_RE.split(raw)
    elif isinstance(raw, (list, tuple)):
        tokens: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                raise TypeError("trusted_hosts 数组中的每一项都必须是字符串")
            tokens.extend(_SPLIT_RE.split(item))
    else:
        raise TypeError("trusted_hosts 必须是字符串数组，或每行一个主机名的字符串")

    ordered: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        host = normalize_host(token)
        if host is not None and host not in seen:
            seen.add(host)
            ordered.append(host)
    return ordered, seen


def _hop_row(hop: dict, top_index: int) -> dict:
    return {
        "top_index": top_index,
        # 投递方向（发件方 -> 收件方）序号，仅作交叉参照
        "path_index": hop["path_index"],
        "node": hop["node"],
        "from_host": hop.get("from_host"),
        "by_host": hop.get("by_host"),
        "ip": hop.get("ip"),
        "time_utc": hop.get("time_utc"),
        "raw": hop.get("raw"),
    }


def analyze_trust_boundary(
    raw_headers: str, trusted_hosts: str | list[str] | tuple[str, ...]
) -> dict:
    """分析单封邮件的接收链可信边界。

    返回供页面 / API 使用的结构化结果；名单为空或类型错误时返回
    ``{"error": ...}``（调用方据此回 400）。头部没有 Received、
    顶端未命中属于正常分析结果（200），分别以 ``status`` 为
    ``no_received`` / ``untrusted_top`` 明确表示无法建立可信链。
    """
    try:
        hosts, host_set = parse_trusted_hosts(trusted_hosts)
    except TypeError as exc:
        return {"error": str(exc)}
    if not hosts:
        return {
            "error": "本组织接收服务器主机名名单不能为空，请每行填写一个主机名"
        }

    parsed = analyze_headers(raw_headers)
    base = {
        "trusted_hosts": hosts,
        "hop_count": parsed["hop_count"],
    }

    if parsed["hop_count"] == 0:
        return {
            **base,
            "status": STATUS_NO_RECEIVED,
            "status_label": "无法建立可信链",
            "message": "头部中未找到 Received 字段，无法建立可信链",
            "trusted_count": 0,
            "untrusted_count": 0,
            "boundary": None,
            "last_trusted_hop": None,
            "hops": [],
        }

    # analyze_headers 的 path 是投递顺序（发件方 -> 收件方）；
    # 可信链检查必须按头部书写顺序（最上方 = 最终接收方），故反转。
    top_down = list(reversed(parsed["path"]))

    rows: list[dict] = []
    boundary: dict | None = None
    last_trusted_row: dict | None = None
    chain_open = True  # 是否仍处于“自顶端延伸的连续可信前缀”中

    for i, hop in enumerate(top_down, start=1):
        row = _hop_row(hop, i)
        by_norm = normalize_host(hop.get("by_host"))
        has_by = by_norm is not None
        by_listed = has_by and by_norm in host_set

        if chain_open and by_listed:
            trusted = True
        else:
            trusted = False
            if chain_open:
                # 首个未命中 / 缺少 by 的跳：边界在此闭合，后续不再接入
                chain_open = False
                boundary = {
                    "top_index": i,
                    "by_host": hop.get("by_host"),
                    "reason": "not_listed" if has_by else "missing_by",
                    "reason_label": (
                        "by 主机不在本组织名单内"
                        if has_by
                        else "该跳缺少 by 主机名"
                    ),
                }

        is_boundary = boundary is not None and boundary["top_index"] == i
        row.update(
            {
                "has_by": has_by,
                "by_listed": by_listed,
                "trusted": trusted,
                "is_boundary": is_boundary,
                "beyond_boundary": (
                    boundary is not None and i > boundary["top_index"]
                ),
                # 边界之后 by 仍命中名单：显式提示“不重新接入”
                "reentry_listed": (
                    not chain_open and not is_boundary and by_listed
                ),
            }
        )
        rows.append(row)
        if trusted:
            last_trusted_row = row

    trusted_count = sum(1 for r in rows if r["trusted"])

    last_trusted_hop = None
    if last_trusted_row is not None:
        last_trusted_hop = {
            "top_index": last_trusted_row["top_index"],
            "by_host": last_trusted_row["by_host"],
            "from_host": last_trusted_row["from_host"],
            "ip": last_trusted_row["ip"],
            "time_utc": last_trusted_row["time_utc"],
        }

    if trusted_count == 0:
        top = rows[0]
        if top["has_by"]:
            message = (
                f"头部最上方第 1 跳的 by 主机（{top['by_host']}）"
                "不在本组织接收服务器名单内，无法从顶端建立可信链；"
                "请确认名单是否包含最终接收服务器，或该头部是否来自本组织。"
            )
        else:
            message = (
                "头部最上方第 1 跳缺少 by 主机名，无法从顶端建立可信链。"
            )
        return {
            **base,
            "status": STATUS_UNTRUSTED_TOP,
            "status_label": "无法建立可信链",
            "message": message,
            "trusted_count": 0,
            "untrusted_count": len(rows),
            "boundary": boundary,
            "last_trusted_hop": None,
            "hops": rows,
        }

    if boundary is None:
        message = (
            f"全部 {len(rows)} 跳的 by 主机均自顶端连续命中名单，"
            "整段接收链都在可信边界内，未出现外部交接跳。"
        )
    else:
        target = (
            f"：{boundary['by_host']}" if boundary.get("by_host") else ""
        )
        message = (
            f"自顶端连续 {trusted_count} 跳命中本组织名单；可信边界位于"
            f"头部自上而下第 {boundary['top_index']} 跳"
            f"（{boundary['reason_label']}{target}）。"
            "边界之后的跳即使 by 再次命中名单也不纳入可信链；"
            "最后可信跳记录的 from 主机与对端 IP 即外部交接点。"
        )

    return {
        **base,
        "status": STATUS_ESTABLISHED,
        "status_label": "可信链已建立",
        "message": message,
        "trusted_count": trusted_count,
        "untrusted_count": len(rows) - trusted_count,
        "boundary": boundary,
        "last_trusted_hop": last_trusted_hop,
        "hops": rows,
    }
