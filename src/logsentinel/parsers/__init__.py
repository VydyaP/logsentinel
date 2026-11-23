"""Log parsers. Each one turns raw lines into :class:`ParsedEvent` objects."""

from __future__ import annotations

from collections.abc import Sequence

from logsentinel.parsers import ssh, web
from logsentinel.parsers.base import ParsedEvent, ParseResult

LOG_TYPES = ("ssh", "web")

__all__ = ["LOG_TYPES", "ParseResult", "ParsedEvent", "detect_log_type", "parse"]


def detect_log_type(lines: Sequence[str]) -> str | None:
    """Guess the log type from the first non-empty lines (majority vote)."""
    votes = {"ssh": 0, "web": 0}
    sample = [line for line in lines if line.strip()][:50]
    for line in sample:
        if web.COMBINED.match(line):
            votes["web"] += 1
        elif ssh.RFC3339_HEADER.match(line) or ssh.SYSLOG_HEADER.match(line):
            votes["ssh"] += 1
    best = max(votes, key=lambda k: votes[k])
    return best if votes[best] > 0 else None


def parse(
    lines: Sequence[str],
    log_type: str = "auto",
    source_file: str | None = None,
    year: int | None = None,
    start_line: int = 1,
) -> ParseResult:
    """Parse lines of the given type ("ssh", "web" or "auto")."""
    if log_type == "auto":
        detected = detect_log_type(lines)
        if detected is None:
            return ParseResult(skipped=sum(1 for line in lines if line.strip()))
        log_type = detected
    if log_type == "ssh":
        return ssh.parse_lines(lines, source_file, year=year, start_line=start_line)
    if log_type == "web":
        return web.parse_lines(lines, source_file, start_line=start_line)
    raise ValueError(f"Unknown log type {log_type!r}; expected one of {LOG_TYPES} or 'auto'")
