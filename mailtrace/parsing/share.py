"""单封邮件脱敏分享报告：仅保留路径骨架，替换所有可识别值。

设计要点：
- 直接复用 :func:`mailtrace.parsing.parser.analyze_headers` 的解析结果
  （投递顺序、时间、相邻耗时、异常），不重复实现 Received 解析。
- 按**投递顺序**（发件方 -> 收件方）为首次出现的不同主机名 / IP 分别
  分配本次请求内稳定的别名：主机名 ``H1``、``H2``……，IP ``IP1``、
  ``IP2``……。同一值（忽略主机名大小写与末尾点、剥去 ``[ ]`` 与
  Postfix 的 ``IPv6:`` 前缀）在节点、来源（from）与上一跳标签中
  始终得到同一个别名；缺失身份的节点对应字段留空（``None``）。
- 输出采用白名单：仅包含路径序号、各类别名、UTC 时间、相邻耗时及
  异常级别 / 说明。原始头部、邮件摘要、Received ID、协议等可识别
  文本一律不输出。
"""

from __future__ import annotations

from ipaddress import ip_address

from mailtrace.parsing.parser import analyze_headers

# 解析器对“完全无身份节点”使用的展示标签，脱敏后留空
UNKNOWN_NODE = "(未知节点)"
_HOST_PREFIX = "H"
_IP_PREFIX = "IP"


def _canon_value(value: str | None) -> tuple[str, bool] | None:
    """把标签值规范化为 ``(查表键, 是否为 IP)``；无身份时返回 ``None``。

    主机名忽略大小写与末尾点（与 compare/batch 的规范化一致）；
    方括号字面量与 ``IPv6:`` / ``IPv4:`` 前缀会被剥去后按 IP 校验，
    因此 ``[10.0.0.5]`` 与解析出的 ``10.0.0.5`` 命中同一 IP 别名。
    """
    if not value:
        return None
    token = value.strip()
    if len(token) >= 2 and token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if token.lower().startswith(("ipv6:", "ipv4:")):
        token = token[5:]
    token = token.rstrip(".").strip()
    if not token or token == UNKNOWN_NODE:
        return None
    try:
        return str(ip_address(token)), True
    except ValueError:
        return token.lower(), False


def build_share_report(raw_headers: str) -> dict:
    """由单封邮件原始头部生成脱敏分享报告。

    没有 ``Received`` 字段时返回 ``{"error": ...}``（调用方据此回 400）。
    """
    result = analyze_headers(raw_headers)
    if result["hop_count"] == 0:
        return {"error": "头部中未找到 Received 字段，无法生成脱敏分享报告"}

    host_aliases: dict[str, str] = {}
    ip_aliases: dict[str, str] = {}

    def alias_for(value: str | None) -> str | None:
        canon = _canon_value(value)
        if canon is None:
            return None
        key, is_ip = canon
        table = ip_aliases if is_ip else host_aliases
        prefix = _IP_PREFIX if is_ip else _HOST_PREFIX
        alias = table.get(key)
        if alias is None:
            alias = f"{prefix}{len(table) + 1}"
            table[key] = alias
        return alias

    rows: list[dict] = []
    for hop in result["path"]:
        # 注册顺序即投递顺序；同一跳内先节点、再来源、再对端 IP
        node_alias = alias_for(hop.get("node"))
        from_alias = alias_for(hop.get("from_host"))
        ip_alias = alias_for(hop.get("ip"))
        # 上一跳标签与上一节点的节点别名天然一致（值相同、表共享）
        delay_from_alias = alias_for(hop.get("delay_from"))

        rows.append(
            {
                "path_index": hop["path_index"],
                "node": node_alias,
                "from_host": from_alias,
                "ip": ip_alias,
                "time_utc": hop.get("time_utc"),
                "delay_from": delay_from_alias,
                "delay_seconds": hop.get("delay_seconds"),
                "delay_human": hop.get("delay_human"),
                "anomalies": [
                    {"level": a["level"], "message": a["message"]}
                    for a in hop.get("anomalies", [])
                ],
            }
        )

    return {
        "host_aliases": list(host_aliases.values()),
        "ip_aliases": list(ip_aliases.values()),
        "path": rows,
    }
