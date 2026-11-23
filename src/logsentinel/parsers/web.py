"""Parser for web server access logs in Nginx/Apache *combined* (or *common*) format.

Example line::

    203.0.113.7 - - [20/Nov/2026:03:14:15 +0000] "GET /a?id=1 HTTP/1.1" 200 512 "-" "curl/8.4"
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from logsentinel.parsers.base import ParsedEvent, ParseResult

# Quoted fields may contain escaped quotes (\"), which Nginx writes for odd user agents.
_QUOTED = r'"(?P<{name}>(?:[^"\\]|\\.)*)"'
COMBINED = re.compile(
    r"^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    + _QUOTED.format(name="request")
    + r"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
    + r"(?:\s+"
    + _QUOTED.format(name="referer")
    + r"\s+"
    + _QUOTED.format(name="ua")
    + r")?"
)
REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10})\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?$")


def parse_line(line: str, source_file: str | None = None, line_no: int = 0) -> ParsedEvent | None:
    """Parse one access-log line; return None if it is not in combined/common format."""
    line = line.rstrip("\r\n")
    match = COMBINED.match(line)
    if not match:
        return None
    try:
        ts = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    except ValueError:
        return None
    request = match["request"]
    req = REQUEST.match(request)
    method, path = (req["method"], req["path"]) if req else (None, request or None)
    user = match["user"]
    return ParsedEvent(
        ts=ts,
        source="web",
        action="http_request",
        raw=line,
        src_ip=match["ip"],
        username=None if user == "-" else user,
        method=method,
        path=path,
        status=int(match["status"]),
        bytes_sent=None if match["bytes"] == "-" else int(match["bytes"]),
        user_agent=(match["ua"] or None) if match["ua"] != "-" else None,
        source_file=source_file,
        line_no=line_no,
    )


def parse_lines(
    lines: Iterable[str], source_file: str | None = None, start_line: int = 1
) -> ParseResult:
    result = ParseResult()
    for offset, line in enumerate(lines):
        if not line.strip():
            continue
        event = parse_line(line, source_file, start_line + offset)
        if event:
            result.events.append(event)
        else:
            result.skipped += 1
    return result
