"""多封邮件慢段归因：聚合多条投递路径中实际相邻节点对的耗时。

设计要点：
- 直接复用 :func:`mailtrace.parsing.parser.analyze_headers` 的解析结果
  （节点身份、相邻耗时），不重复实现 Received 解析。
- 聚合单位是各邮件**投递顺序中实际相邻的两个节点**构成的有向区段
  （上游/发件侧 -> 下游/收件侧），不跨节点拼接耗时。
- 节点身份为“规范化 ``by`` 主机名 + 对端 IP”的**完整已知字段组合**：
  任一字段缺失都保留为 ``None``，因此 ``(mx, 1.2.3.4)`` 与
  ``(mx, None)`` 是不同身份；两端任一节点完全没有身份（by 与 IP
  皆缺）的区段不参与合并。
- 同一封邮件内同键区段重复出现（如回流/退信绕环）时，仅取**最大的
  有效非负耗时**作为该邮件在该区段上的唯一样本。
- 时间无效（任一端缺少可解析时间）记为 ``invalid_time``；耗时为负
  （时间倒灌/时钟偏移）记为 ``backflow``，均排除出统计并计数。
- 每个区段输出样本数、中位耗时与最大耗时，结果按中位耗时从慢到快排序。
"""

from __future__ import annotations

import re
from statistics import median

from mailtrace.parsing.compare import _norm_host
from mailtrace.parsing.parser import _humanize_delay, analyze_headers

# 页面多封粘贴时的规范分隔符：单独成行，前后各至少 3 个 =
BATCH_DELIMITER = "===== 下一封邮件 ====="
# 分隔符识别：行首（不允许空白，避免误吞折行续行）为 >=3 个
# = / - / # / * 字符，其后可带任意说明文字（如 “===== 邮件 2 =====”）
_DELIMITER_RE = re.compile(r"^(?:={3,}|-{3,}|#{3,}|\*{3,})[^\n]*$", re.MULTILINE)


def split_batch_headers(text: str) -> list[str]:
    """按显式分隔符把粘贴文本切分为多封邮件的原始头部。

    空段（连续分隔符、首尾空白）会被丢弃；返回的每一项均已 strip。
    """
    if not text:
        return []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    parts = _DELIMITER_RE.split(text)
    return [part.strip() for part in parts if part.strip()]


def _identity(hop: dict) -> tuple[str | None, str | None] | None:
    """节点身份：(规范化 by 主机, 对端 IP) 的完整已知字段组合。

    与 :mod:`mailtrace.parsing.compare` 使用同一套规范化规则；
    by 与 IP 都缺失时返回 ``None``（无身份节点）。
    """
    by = _norm_host(hop.get("by_host"))
    ip = hop.get("ip") or None
    if by is None and ip is None:
        return None
    return (by, ip)


def _node_view(hop: dict) -> dict:
    """区段端点的展示信息。"""
    return {
        "node": hop.get("node"),
        "by_host": hop.get("by_host"),
        "ip": hop.get("ip"),
    }


def batch_delay_analysis(headers_list: list[str]) -> dict:
    """对多封邮件原始头部做慢段归因。

    参数为头部字符串列表（页面粘贴文本可先用 :func:`split_batch_headers`
    切分）。任一封没有 ``Received`` 字段时记入 ``message_errors`` 且不
    参与统计；所有邮件都没有 ``Received`` 时返回带 ``error`` 的字典。
    """
    excluded = {"invalid_time": 0, "backflow": 0, "identity_less": 0}
    message_errors: list[dict] = []
    # segment key -> 各邮件样本（每封邮件每键至多一个值）
    samples: dict[tuple, list[float]] = {}
    # segment key -> (上游节点视图, 下游节点视图)
    views: dict[tuple, tuple[dict, dict]] = {}
    duplicate_collapsed = 0
    analyzed_count = 0

    if not headers_list:
        return {
            "error": "请至少提供一封邮件的原始头部（含 Received 字段）",
            "message_count": 0,
            "analyzed_count": 0,
            "message_errors": message_errors,
            "segment_count": 0,
            "sample_count": 0,
            "excluded": excluded,
            "duplicate_collapsed": 0,
            "segments": [],
        }

    for index, raw in enumerate(headers_list):
        result = analyze_headers(raw)
        if result["hop_count"] == 0:
            message_errors.append(
                {"index": index + 1, "error": "该头部中未找到 Received 字段"}
            )
            continue
        analyzed_count += 1

        path = result["path"]
        # 同一封邮件内：segment key -> 该邮件的样本值（取最大有效非负耗时）
        per_mail: dict[tuple, float] = {}
        for i in range(1, len(path)):
            upstream = path[i - 1]
            current = path[i]
            id_up = _identity(upstream)
            id_down = _identity(current)
            if id_up is None or id_down is None:
                # 区段任一端没有身份：不与任何其他区段合并
                excluded["identity_less"] += 1
                continue

            key = (id_up, id_down)
            views.setdefault(key, (_node_view(upstream), _node_view(current)))

            delay = current.get("delay_seconds")
            if delay is None:
                # 相邻耗时不可计算（本节点或上游时间缺失/无法解析）
                excluded["invalid_time"] += 1
                continue
            if delay < 0:
                # 时间倒灌（下游时间早于上游，时钟偏移或伪造）
                excluded["backflow"] += 1
                continue

            if key in per_mail:
                duplicate_collapsed += 1
                if delay > per_mail[key]:
                    per_mail[key] = delay
            else:
                per_mail[key] = delay

        for key, value in per_mail.items():
            samples.setdefault(key, []).append(value)

    if analyzed_count == 0:
        return {
            "error": "所有头部中均未找到 Received 字段，无法进行慢段归因",
            "message_count": len(headers_list),
            "analyzed_count": 0,
            "message_errors": message_errors,
            "segment_count": 0,
            "sample_count": 0,
            "excluded": excluded,
            "duplicate_collapsed": 0,
            "segments": [],
        }

    segments: list[dict] = []
    for key, values in samples.items():
        upstream_view, downstream_view = views[key]
        med = median(values)
        maximum = max(values)
        segments.append(
            {
                "from": upstream_view,
                "to": downstream_view,
                "sample_count": len(values),
                "median_seconds": med,
                "median_human": _humanize_delay(med),
                "max_seconds": maximum,
                "max_human": _humanize_delay(maximum),
            }
        )

    # 从慢到快：中位耗时降序，平手看最大耗时，再按节点名保证顺序稳定
    segments.sort(
        key=lambda s: (
            -s["median_seconds"],
            -s["max_seconds"],
            s["from"].get("node") or "",
            s["to"].get("node") or "",
        )
    )
    for rank, segment in enumerate(segments, start=1):
        segment["rank"] = rank

    return {
        "message_count": len(headers_list),
        "analyzed_count": analyzed_count,
        "message_errors": message_errors,
        "segment_count": len(segments),
        "sample_count": sum(len(v) for v in samples.values()),
        "excluded": excluded,
        "duplicate_collapsed": duplicate_collapsed,
        "segments": segments,
    }
