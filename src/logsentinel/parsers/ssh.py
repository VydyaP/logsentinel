"""Parser for Linux SSH authentication logs (``/var/log/auth.log``, ``/var/log/secure``).

Two timestamp styles are supported:

* classic syslog:  ``Nov 20 03:14:15 web01 sshd[1234]: Failed password for root from ...``
  (no year or timezone; we assume UTC and infer the year)
* RFC 3339 (default on Ubuntu 23.10+):
  ``2026-11-20T03:14:15.123456+00:00 web01 sshd[1234]: ...``

Only ``sshd`` lines are turned into events; CRON, sudo and other programs are skipped.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from logsentinel.parsers.base import ParsedEvent, ParseResult

SYSLOG_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
RFC3339_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./()]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# (action, pattern) - first match wins. Usernames may contain almost anything,
# including spaces in some attacks, so we match lazily up to " from <ip>".
MESSAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "login_failed",
        re.compile(
            r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*?) from "
            r"(?P<ip>[0-9a-fA-F:.]+) port \d+"
        ),
    ),
    (
        "login_success",
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>.*?) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
        ),
    ),
    (
        "invalid_user",
        re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9a-fA-F:.]+)"),
    ),
    (
        "pam_failure",
        re.compile(
            r"^pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>\S+)"
            r"(?:\s+user=(?P<user>\S+))?"
        ),
    ),
    (
        "disconnect",
        re.compile(
            r"^(?:Received disconnect from|Disconnected from|Connection closed by)"
            r"(?: (?:invalid |authenticating )?user (?P<user>\S+))? (?P<ip>[0-9a-fA-F:.]+)"
        ),
    ),
]
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")
MAX_REPEAT = 1000  # guard against absurd values in a hostile log


def parse_timestamp(text: str, year: int | None = None, now: datetime | None = None) -> datetime:
    """Parse a syslog or RFC 3339 timestamp into an aware UTC datetime.

    Classic syslog timestamps have no year. We use ``year`` if given, otherwise
    the current year - unless that would put the event in the future (e.g. a
    December log read in January), in which case we use last year.
    """
    if text[0].isdigit():
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    now = now or datetime.now(UTC)
    month_day_time = " ".join(text.split())  # "Nov  5" -> "Nov 5"
    guess_year = year or now.year
    ts = datetime.strptime(f"{guess_year} {month_day_time}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=UTC
    )
    if year is None and ts > now + timedelta(days=1):
        ts = ts.replace(year=guess_year - 1)
    return ts


def _classify(msg: str) -> tuple[str, dict[str, str | None]] | None:
    for action, pattern in MESSAGE_PATTERNS:
        match = pattern.search(msg)
        if match:
            return action, match.groupdict()
    return None


def parse_line(
    line: str, source_file: str | None = None, line_no: int = 0, year: int | None = None
) -> list[ParsedEvent]:
    """Parse one auth.log line. Returns [] for lines that are not interesting sshd events.

    A list is returned because rsyslog's ``message repeated N times: [...]``
    stands for N separate events.
    """
    line = line.rstrip("\r\n")
    header = RFC3339_HEADER.match(line) or SYSLOG_HEADER.match(line)
    if not header or not header["proc"].startswith("sshd"):
        return []
    msg = header["msg"]
    repeat = 1
    repeated = REPEATED.match(msg)
    if repeated:
        repeat = min(int(repeated["n"]), MAX_REPEAT)
        msg = repeated["msg"]
    classified = _classify(msg)
    if classified is None:
        return []
    action, fields = classified
    try:
        ts = parse_timestamp(header["ts"], year=year)
    except ValueError:
        return []
    events = []
    for i in range(repeat):
        events.append(
            ParsedEvent(
                ts=ts,
                source="ssh",
                action=action,
                raw=line,
                host=header["host"],
                src_ip=fields.get("ip"),
                username=fields.get("user") or None,
                method=fields.get("method"),
                source_file=source_file,
                line_no=line_no,
                sub_index=i,
            )
        )
    return events


def parse_lines(
    lines: Iterable[str],
    source_file: str | None = None,
    year: int | None = None,
    start_line: int = 1,
) -> ParseResult:
    """Parse many lines; count the ones that produced no event as skipped."""
    result = ParseResult()
    for offset, line in enumerate(lines):
        if not line.strip():
            continue
        events = parse_line(line, source_file, start_line + offset, year)
        if events:
            result.events.extend(events)
        else:
            result.skipped += 1
    return result
