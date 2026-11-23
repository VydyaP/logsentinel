from datetime import UTC, datetime

import pytest

from logsentinel import parsers
from logsentinel.parsers import web

COMBINED = (
    '203.0.113.7 - - [20/Nov/2026:08:44:15 +0530] "GET /index.php?id=1%27 HTTP/1.1" 404 512 '
    '"https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"'
)


def test_parses_combined_format():
    event = web.parse_line(COMBINED, "access.log", 7)
    assert event is not None
    assert event.src_ip == "203.0.113.7"
    assert event.method == "GET"
    assert event.path == "/index.php?id=1%27"  # stored raw; rules decode it
    assert event.status == 404
    assert event.bytes_sent == 512
    assert event.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"
    assert event.ts == datetime(2026, 11, 20, 3, 14, 15, tzinfo=UTC)  # converted to UTC
    assert event.action == "http_request"
    assert event.source_file == "access.log"


def test_parses_common_format_without_referer_and_agent():
    event = web.parse_line(
        '10.0.0.1 - bob [20/Nov/2026:03:14:15 +0000] "POST /login HTTP/1.0" 302 -'
    )
    assert event is not None
    assert event.username == "bob"
    assert event.bytes_sent is None
    assert event.user_agent is None


def test_ipv6_and_escaped_quotes_in_user_agent():
    line = '2001:db8::5 - - [20/Nov/2026:03:14:15 +0000] "GET / HTTP/2.0" 200 10 "-" "evil \\"agent\\""'
    event = web.parse_line(line)
    assert event is not None
    assert event.src_ip == "2001:db8::5"
    assert event.user_agent == 'evil \\"agent\\"'


def test_malformed_request_line_keeps_raw_request_as_path():
    line = '203.0.113.9 - - [20/Nov/2026:03:14:15 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'
    event = web.parse_line(line)
    assert event is not None
    assert event.method is None
    assert event.status == 400
    assert event.user_agent is None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a log line",
        '203.0.113.7 - - [99/Foo/2026:03:14:15 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',  # bad date
        "2026-11-20T03:14:15+00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
    ],
)
def test_rejects_non_access_log_lines(line):
    assert web.parse_line(line) is None


def test_detect_log_type():
    assert parsers.detect_log_type([COMBINED, COMBINED]) == "web"
    assert (
        parsers.detect_log_type(["Nov 20 03:14:15 h sshd[1]: Invalid user a from 1.2.3.4"]) == "ssh"
    )
    assert parsers.detect_log_type(["hello", "world"]) is None


def test_parse_auto_and_unknown_type():
    assert len(parsers.parse([COMBINED], "auto").events) == 1
    assert parsers.parse(["junk"], "auto").skipped == 1
    with pytest.raises(ValueError):
        parsers.parse([COMBINED], "windows")
