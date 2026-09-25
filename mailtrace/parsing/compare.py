"""双邮件头路径对照：对齐两份头部的 Received 中继节点。

设计要点：
- 直接复用 :func:`mailtrace.parsing.parser.analyze_headers` 的解析结果
  （节点身份、时间、相邻耗时），不重复实现 Received 解析。
- 节点身份由 ``by`` 主机名与对端 IP 共同决定：两者都不冲突且至少一项
  共同相等才可视为同一跳；两项都缺失的节点没有身份，**不允许**仅凭
  时间戳相近就配对（匹配过程完全不参考时间）。
- 同名节点重复出现时，对两条路径做保序全局对齐（LCS 动态规划），
  而不是“首次命中”式的贪心匹配，保证同名节点按结构顺序一一对应。
- 共有节点的耗时差值直接取各自路径内**相邻**节点耗时之差；任一侧
  耗时无效（本节点或上游节点时间缺失/异常）即标记为不可比较，
  不会跳过中间无效节点去拼接耗时。
"""

from __future__ import annotations

from mailtrace.parsing.parser import _humanize_delay, analyze_headers

# 行类型：common = 共有，added = 仅 B 侧（新增），missing = 仅 A 侧（缺失）
KIND_COMMON = "common"
KIND_ADDED = "added"
KIND_MISSING = "missing"


def _norm_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    return host or None


def _identity(hop: dict) -> tuple[str | None, str | None] | None:
    """节点的匹配身份：(规范化 by 主机, 对端 IP)；两者皆无则没有身份。"""
    by = _norm_host(hop.get("by_host"))
    ip = hop.get("ip") or None
    if by is None and ip is None:
        return None
    return (by, ip)


def _compatible(
    id_a: tuple[str | None, str | None] | None,
    id_b: tuple[str | None, str | None] | None,
) -> bool:
    """两个身份是否可判为同一跳。

    by 主机与对端 IP 任一冲突即否；至少一项双方都有且相等才是同一跳；
    任一侧没有身份（by 与 IP 全缺）永远不能配对。
    """
    if id_a is None or id_b is None:
        return False
    by_a, ip_a = id_a
    by_b, ip_b = id_b
    shared = False
    if by_a is not None and by_b is not None:
        if by_a != by_b:
            return False
        shared = True
    if ip_a is not None and ip_b is not None:
        if ip_a != ip_b:
            return False
        shared = True
    return shared


def _align(path_a: list[dict], path_b: list[dict]) -> list[tuple[str, int | None, int | None]]:
    """对两条投递路径（发件方 -> 收件方顺序）做保序全局对齐。

    返回 ``(kind, index_a 或 None, index_b 或 None)`` 行列表，行顺序即
    结构（投递）顺序。采用 LCS 动态规划最大化匹配对数，同名重复节点
    因此按出现顺序依次配对，而非首次命中。
    """
    ids_a = [_identity(h) for h in path_a]
    ids_b = [_identity(h) for h in path_b]
    n, m = len(path_a), len(path_b)

    # dp[i][j] = path_a[i:] 与 path_b[j:] 之间最多能匹配的节点对数
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        row, nxt = dp[i], dp[i + 1]
        id_ai = ids_a[i]
        for j in range(m - 1, -1, -1):
            best = row[j + 1] if row[j + 1] >= nxt[j] else nxt[j]
            if _compatible(id_ai, ids_b[j]):
                matched = nxt[j + 1] + 1
                if matched > best:
                    best = matched
            row[j] = best

    rows: list[tuple[str, int | None, int | None]] = []
    i = j = 0
    while i < n and j < m:
        if _compatible(ids_a[i], ids_b[j]) and dp[i][j] == dp[i + 1][j + 1] + 1:
            rows.append((KIND_COMMON, i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            # 与 diff 惯例一致：先列出缺失（仅 A），再列出新增（仅 B）
            rows.append((KIND_MISSING, i, None))
            i += 1
        else:
            rows.append((KIND_ADDED, None, j))
            j += 1
    while i < n:
        rows.append((KIND_MISSING, i, None))
        i += 1
    while j < m:
        rows.append((KIND_ADDED, None, j))
        j += 1
    return rows


def _humanize_diff(seconds: float) -> str:
    """耗时差值的可读形式，始终带正负号（0 除外）。"""
    if seconds == 0:
        return "0 秒"
    sign = "+" if seconds > 0 else "-"
    return sign + _humanize_delay(abs(seconds))


def _common_row(hop_a: dict, hop_b: dict) -> dict:
    """共有节点行：两份各自的相邻耗时与差值（B - A）。

    任一侧耗时无效（本节点或其上游时间缺失/异常）时不可比较；
    耗时取自各自路径的相邻节点，不跳过中间节点拼接。
    """
    delay_a = hop_a.get("delay_seconds")
    delay_b = hop_b.get("delay_seconds")
    both_first = hop_a.get("path_index") == 1 and hop_b.get("path_index") == 1

    if delay_a is not None and delay_b is not None:
        diff = delay_b - delay_a
        diff_status = "ok"
        diff_human = _humanize_diff(diff)
    elif both_first:
        diff = None
        diff_status = "first_hop"
        diff_human = None
    else:
        diff = None
        diff_status = "incomparable"
        diff_human = None

    return {
        "kind": KIND_COMMON,
        "a": hop_a,
        "b": hop_b,
        "delay_a_seconds": delay_a,
        "delay_b_seconds": delay_b,
        "delay_a_human": _humanize_delay(delay_a) if delay_a is not None else None,
        "delay_b_human": _humanize_delay(delay_b) if delay_b is not None else None,
        "delay_diff_seconds": diff,
        "delay_diff_human": diff_human,
        # ok = 可比较；first_hop = 双方均为首跳；incomparable = 任一侧时间无效
        "diff_status": diff_status,
    }


def _single_row(kind: str, hop: dict, side: str) -> dict:
    return {
        "kind": kind,
        "a": hop if side == "a" else None,
        "b": hop if side == "b" else None,
        "delay_a_seconds": None,
        "delay_b_seconds": None,
        "delay_a_human": None,
        "delay_b_human": None,
        "delay_diff_seconds": None,
        "delay_diff_human": None,
        "diff_status": "none",
    }


def compare_headers(headers_a: str, headers_b: str) -> dict:
    """对照两份邮件原始头部的投递路径。

    返回 ``{"a": ..., "b": ..., "alignment": {...}}``；任一侧没有
    Received 字段时返回带 ``error`` 与 ``side_errors`` 的字典。
    """
    result_a = analyze_headers(headers_a)
    result_b = analyze_headers(headers_b)

    side_errors: dict[str, str] = {}
    if result_a["hop_count"] == 0:
        side_errors["a"] = "A 侧头部中未找到 Received 字段"
    if result_b["hop_count"] == 0:
        side_errors["b"] = "B 侧头部中未找到 Received 字段"
    if side_errors:
        detail = "；".join(side_errors.values())
        return {
            "error": f"{detail}，无法进行路径对照",
            "side_errors": side_errors,
        }

    rows: list[dict] = []
    common_count = added_count = missing_count = 0
    for kind, idx_a, idx_b in _align(result_a["path"], result_b["path"]):
        if kind == KIND_COMMON:
            rows.append(_common_row(result_a["path"][idx_a], result_b["path"][idx_b]))
            common_count += 1
        elif kind == KIND_MISSING:
            rows.append(_single_row(kind, result_a["path"][idx_a], "a"))
            missing_count += 1
        else:
            rows.append(_single_row(kind, result_b["path"][idx_b], "b"))
            added_count += 1

    return {
        "a": result_a,
        "b": result_b,
        "alignment": {
            "row_count": len(rows),
            "common_count": common_count,
            "added_count": added_count,
            "missing_count": missing_count,
            "rows": rows,
        },
    }
