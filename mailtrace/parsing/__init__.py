"""邮件原始头部解析包。"""

from .arc import check_arc_chain
from .authres import analyze_auth_results
from .batch import BATCH_DELIMITER, batch_delay_analysis, split_batch_headers
from .compare import compare_headers
from .dkim import audit_dkim_coverage
from .parser import analyze_headers, parse_header_blocks
from .share import build_share_report
from .trust import analyze_trust_boundary, parse_trusted_hosts

__all__ = [
    "BATCH_DELIMITER",
    "analyze_auth_results",
    "analyze_headers",
    "analyze_trust_boundary",
    "audit_dkim_coverage",
    "batch_delay_analysis",
    "build_share_report",
    "check_arc_chain",
    "compare_headers",
    "parse_header_blocks",
    "parse_trusted_hosts",
    "split_batch_headers",
]
