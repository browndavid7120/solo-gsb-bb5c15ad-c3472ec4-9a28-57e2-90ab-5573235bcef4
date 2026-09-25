"""邮件原始头部解析核心（仅依赖 Python 标准库）。

处理流程：
1. 折行展开（unfolding）：以空白字符开头的续行并入上一行，符合 RFC 5322。
2. 按出现顺序收集所有 ``Received`` 字段，同时保留原始折行文本。
3. 提取每个 Received 字段中最后一个分号后的时间戳并解析为带时区的时间。
4. 邮件中继路径按 Received 的实际嵌套顺序排列（最先生成的在前，最终接收方在后）；
   并以时间戳校验该顺序、计算相邻节点耗时。
5. 无法解析或缺少时间的节点仍然列出，并以异常标记呈现。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from ipaddress import IPv4Address, IPv6Address, ip_address

# RFC 5322 字段名：可打印 ASCII，不含空白与冒号
_HEADER_NAME_RE = re.compile(r"^([\x21-\x39\x3B-\x7E]+):[ \t]?(.*)$")
_WS_RUN_RE = re.compile(r"[ \t]+")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# 方括号内的裸 IPv6（常见于 helo 注释，如 [2001:db8::1] 或 [IPv6:2001:db8::1])
_IPV6_BRACKET_RE = re.compile(r"\[([0-9a-fA-F:]{3,}|IPv[46]:[0-9a-fA-F:]{3,})\]")
# 不在方括号内的裸 IPv6（兜底）
_IPV6_BARE_RE = re.compile(r"(?<![:\w])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![:\w])")
_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9-]+)", re.IGNORECASE)
_VIA_RE = re.compile(r"\bvia\s+(\S+)", re.IGNORECASE)
_ID_RE = re.compile(r"\bid\s+([^\s;]+)", re.IGNORECASE)

MIN_VALID_YEAR = 1990
MAX_VALID_YEAR = 2100
# 小于该负偏差（秒）视为时钟异常，避免秒级取整误差误报
SKEW_TOLERANCE_SECONDS = 1.0
SKEW_TOLERANCE = timedelta(seconds=SKEW_TOLERANCE_SECONDS)


@dataclass
class HeaderBlock:
    """一个已展开的头部字段。"""

    name: str
    unfolded: str          # 折行展开后的完整字段（保留折行处的空白）
    value: str             # 去掉字段名与冒号后的折叠空白规整值
    raw: str               # 原始折行文本（含字段名）
    order: int             # 在原文中出现的顺序（0 最先）


@dataclass
class Anomaly:
    level: str             # "error" 或 "warn"
    message: str


@dataclass
class Hop:
    """一个 Received 中继节点。"""

    order: int                         # 结构序号（0 = 最靠近收件方的一跳）
    raw: str
    unfolded: str
    date_raw: str | None = None
    dt_utc: datetime | None = None
    naive_assumed_utc: bool = False
    from_host: str | None = None
    by_host: str | None = None
    via: str | None = None
    with_proto: str | None = None
    received_id: str | None = None
    ip: str | None = None
    anomalies: list[Anomaly] = field(default_factory=list)
    # 由上一个（更靠近发件方的）节点到本节点的耗时秒数
    delay_seconds: float | None = None
    delay_from: str | None = None


def parse_header_blocks(text: str) -> list[HeaderBlock]:
    """把原始头部文本切分并展开为 HeaderBlock 列表，保持出现顺序。

    头部之前的非头部行（如 mbox 的 ``From `` 分隔行）会被忽略；
    遇到第一个空行即认为头部结束（与正文分隔）。
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    blocks: list[HeaderBlock] = []
    current: list[str] | None = None  # 当前字段的原始行（含字段名行）
    headers_started = False

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        name_line = current[0]
        m = _HEADER_NAME_RE.match(name_line)
        if m:
            name = m.group(1)
            # RFC 5322 unfolding：删去 CRLF 本身，保留其后的 WSP
            unfolded = "".join(part.strip("\n") for part in current)
            # value: 去掉 "Name:" 前缀
            value_part = unfolded[len(name) + 1 :]
            value = _WS_RUN_RE.sub(" ", value_part.strip())
            blocks.append(
                HeaderBlock(
                    name=name,
                    unfolded=unfolded.strip(),
                    value=value,
                    raw="\n".join(current),
                    order=len(blocks),
                )
            )
        current = None

    for line in lines:
        if line.startswith((" ", "\t")):
            # 续行（folding）
            if current is not None:
                current.append(line)
            # 头部开始前出现的孤立空白行忽略
            continue

        if line == "":
            # 空行：头部与正文的分隔
            if headers_started:
                break
            continue

        if not headers_started and line.startswith("From "):
            # mbox 邮箱格式分隔行，跳过
            continue

        if not _HEADER_NAME_RE.match(line):
            # 头部开始前的杂散文本忽略；开始后出现的非字段行结束头部
            if headers_started:
                break
            continue

        flush()
        current = [line]
        headers_started = True

    flush()
    return blocks


def _strip_paren_comments(text: str) -> str:
    """删除 Received 字段里的圆括号注释（不支持嵌套注释的极端写法）。"""
    return re.sub(r"\([^()]*\)", " ", text)


def _coerce_valid_datetime(dt: datetime) -> bool:
    return MIN_VALID_YEAR <= dt.year <= MAX_VALID_YEAR


def _parse_rfc2822(candidate: str) -> datetime | None:
    try:
        dt = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt is None or not _coerce_valid_datetime(dt):
        return None
    return dt


def _parse_iso(candidate: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    if not _coerce_valid_datetime(dt):
        return None
    return dt


def parse_received_date(date_raw: str) -> tuple[datetime | None, bool]:
    """解析 Received 分号后的时间字符串。

    返回 ``(带 UTC 时区的 datetime, 是否为缺失时区而按 UTC 处理)``；
    解析失败时返回 ``(None, False)``。
    """
    tail = _WS_RUN_RE.sub(" ", date_raw.strip())
    if not tail:
        return None, False

    # 依次尝试：原文、去圆括号注释、从右侧逐词裁剪（容忍尾部多余文字）
    candidates: list[str] = []
    seen: set[str] = set()

    def add(c: str) -> None:
        c = c.strip().rstrip(";,").strip()
        if c and c not in seen:
            seen.add(c)
            candidates.append(c)

    add(tail)
    add(_strip_paren_comments(tail))
    tokens = tail.split()
    for trim in range(1, min(3, len(tokens))):
        add(" ".join(tokens[:-trim]))

    for candidate in candidates:
        dt = _parse_rfc2822(candidate)
        if dt is None:
            dt = _parse_iso(candidate)
        if dt is not None:
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc), True
            return dt.astimezone(timezone.utc), False
    return None, False


def _valid_ip(token: str, version: int):
    """剥离 Postfix 的 ``IPv6:`` / ``IPv4:`` 前缀后校验地址。"""
    token = token.strip()
    for prefix in ("IPv6:", "IPv4:", "ipv6:", "ipv4:"):
        if token.startswith(prefix):
            token = token[len(prefix):]
            break
    try:
        ip = ip_address(token)
    except ValueError:
        return None
    if version == 4 and isinstance(ip, IPv4Address):
        return str(ip)
    if version == 6 and isinstance(ip, IPv6Address):
        return str(ip)
    return None


def _find_ip(text: str) -> str | None:
    """在 Received 的“分号前”部分中找出对端 IP（优先 IPv4，其次 IPv6）。"""
    cleaned = _strip_paren_comments(text)
    # 保留原文与去注释两份文本：IP 常出现在注释或方括号中
    sources = (text, cleaned)

    for version, patterns in (
        (4, (_IPV4_RE,)),
        (6, (_IPV6_BRACKET_RE, _IPV6_BARE_RE)),
    ):
        for source in sources:
            for pattern in patterns:
                for m in pattern.finditer(source):
                    found = _valid_ip(m.group(1), version)
                    if found:
                        return found
    return None


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1) if m else None


def _build_hop(block: HeaderBlock) -> Hop:
    value = block.value
    hop = Hop(order=block.order, raw=block.raw, unfolded=block.unfolded)

    if ";" in value:
        received_part, date_raw = value.rsplit(";", 1)
        received_part = received_part.strip()
        date_raw = date_raw.strip()
    else:
        received_part, date_raw = value.strip(), ""

    if date_raw:
        hop.date_raw = date_raw
        dt, naive = parse_received_date(date_raw)
        if dt is None:
            hop.anomalies.append(
                Anomaly("error", "时间戳无法解析，已保留原始字段")
            )
        else:
            hop.dt_utc = dt
            if naive:
                hop.naive_assumed_utc = True
                hop.anomalies.append(
                    Anomaly(
                        "warn",
                        "时间戳缺少时区信息，已按 UTC 解释，结果可能不准",
                    )
                )
    else:
        hop.anomalies.append(
            Anomaly("warn", "该 Received 字段缺少时间（分号后的 date-time）")
        )

    search_text = _strip_paren_comments(received_part)
    hop.from_host = _first_match(_FROM_RE, search_text)
    hop.by_host = _first_match(_BY_RE, search_text)
    hop.via = _first_match(_VIA_RE, search_text)
    hop.with_proto = _first_match(_WITH_RE, search_text)
    hop.received_id = _first_match(_ID_RE, search_text)
    hop.ip = _find_ip(received_part)
    return hop


def _present_node(hop: Hop) -> str:
    """生成用于展示的中继节点名称（投递该邮件的接收服务器）。"""
    host = hop.by_host or hop.from_host
    return host or hop.ip or "(未知节点)"


def _humanize_delay(seconds: float) -> str:
    if seconds < 0:
        return f"{seconds:.0f} 秒"
    if seconds < 1:
        return f"{seconds * 1000:.0f} 毫秒"
    if seconds < 60:
        rounded = round(seconds, 1)
        return f"{rounded} 秒"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} 分 {sec:.0f} 秒"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} 小时 {int(minutes)} 分"


def analyze_headers(text: str) -> dict:
    """分析整段原始邮件头部，返回供页面/API 使用的结构化结果。"""
    blocks = parse_header_blocks(text)
    received = [b for b in blocks if b.name.lower() == "received"]

    hops = [_build_hop(b) for b in received]

    # 实际投递路径：Received 是后到先写，反转后为发件方向 -> 收件方向。
    path = list(reversed(hops))
    node_labels = [_present_node(h) for h in path]

    # 相邻节点耗时：path[i] 的时间减去 path[i-1] 的时间
    for i, hop in enumerate(path):
        if i == 0:
            continue
        prev = path[i - 1]
        if hop.dt_utc is not None and prev.dt_utc is not None:
            delta = (hop.dt_utc - prev.dt_utc).total_seconds()
            hop.delay_seconds = delta
            hop.delay_from = node_labels[i - 1]
            if delta < -SKEW_TOLERANCE_SECONDS:
                hop.anomalies.append(
                    Anomaly(
                        "warn",
                        f"较上一节点时间早 {abs(delta):.0f} 秒，"
                        "可能存在时钟偏移或伪造时间戳",
                    )
                )

    # 顺序校验：结构顺序（新 -> 旧）下，已解析时间应单调不增
    timed_structural = [h for h in hops if h.dt_utc is not None]
    skew_marked = {
        id(h)
        for h in path
        if h.anomalies
        and any("时钟偏移" in a.message or "伪造时间戳" in a.message for a in h.anomalies)
    }
    for newer, older in zip(timed_structural, timed_structural[1:]):
        if newer.dt_utc < older.dt_utc - SKEW_TOLERANCE and id(newer) not in skew_marked:
            newer.anomalies.append(
                Anomaly(
                    "warn",
                    "时间戳顺序与 Received 嵌套顺序不一致（时钟偏移或路径伪造）",
                )
            )

    summary_names = [
        "Date",
        "From",
        "To",
        "Cc",
        "Subject",
        "Message-ID",
        "Reply-To",
        "Return-Path",
    ]
    summary: dict[str, str] = {}
    for block in blocks:
        key = block.name.lower()
        for name in summary_names:
            if name.lower() == key and name not in summary:
                summary[name] = block.value

    timed_path = [h for h in path if h.dt_utc is not None]
    total_span = None
    if len(timed_path) >= 2:
        total_span = (
            timed_path[-1].dt_utc - timed_path[0].dt_utc
        ).total_seconds()

    error_count = sum(
        1 for h in hops for a in h.anomalies if a.level == "error"
    )
    warn_count = sum(
        1 for h in hops for a in h.anomalies if a.level == "warn"
    )
    timed_count = sum(1 for h in hops if h.dt_utc is not None)

    return {
        "hop_count": len(hops),
        "timed_count": timed_count,
        "missing_count": len(hops) - timed_count,
        "error_count": error_count,
        "warn_count": warn_count,
        "total_span_seconds": total_span,
        "total_span_human": _humanize_delay(total_span) if total_span is not None else None,
        "summary": summary,
        "path": [_hop_to_dict(hop, node_labels[i], i, len(path)) for i, hop in enumerate(path)],
    }


def _hop_to_dict(hop: Hop, label: str, path_index: int, total: int) -> dict:
    return {
        "path_index": path_index + 1,
        "structural_index": hop.order,
        "direction_hint": (
            "最早一跳（靠近发件方）"
            if path_index == 0
            else "最终接收方（靠近收件方）" if path_index == total - 1 else "中转节点"
        ),
        "node": label,
        "from_host": hop.from_host,
        "by_host": hop.by_host,
        "via": hop.via,
        "with_proto": hop.with_proto,
        "id": hop.received_id,
        "ip": hop.ip,
        "date_raw": hop.date_raw,
        "time_utc": hop.dt_utc.strftime("%Y-%m-%d %H:%M:%S %Z") if hop.dt_utc else None,
        "time_iso": hop.dt_utc.isoformat() if hop.dt_utc else None,
        "naive_assumed_utc": hop.naive_assumed_utc,
        "anomalies": [{"level": a.level, "message": a.message} for a in hop.anomalies],
        "delay_seconds": hop.delay_seconds,
        "delay_human": _humanize_delay(hop.delay_seconds) if hop.delay_seconds is not None else None,
        "delay_from": hop.delay_from,
        "raw": hop.raw,
    }
