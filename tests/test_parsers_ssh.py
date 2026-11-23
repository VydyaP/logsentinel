from datetime import UTC, datetime

import pytest

from logsentinel.parsers import ssh

RFC = "2026-11-20T03:14:15.123456+00:00 web01 sshd[1234]: "
CLASSIC = "Nov 20 03:14:15 web01 sshd[1234]: "


@pytest.mark.parametrize(
    ("msg", "action", "user", "ip"),
    [
        (
            "Failed password for root from 203.0.113.5 port 40222 ssh2",
            "login_failed",
            "root",
            "203.0.113.5",
        ),
        (
            "Failed password for invalid user admin from 203.0.113.5 port 1 ssh2",
            "login_failed",
            "admin",
            "203.0.113.5",
        ),
        (
            "Failed publickey for git from 2001:db8::1 port 22 ssh2",
            "login_failed",
            "git",
            "2001:db8::1",
        ),
        (
            "Accepted password for alice from 10.0.0.5 port 50000 ssh2",
            "login_success",
            "alice",
            "10.0.0.5",
        ),
        (
            "Accepted publickey for bob from 10.0.0.6 port 50001 ssh2: ED25519 SHA256:abc",
            "login_success",
            "bob",
            "10.0.0.6",
        ),
        ("Invalid user oracle from 203.0.113.9 port 4444", "invalid_user", "oracle", "203.0.113.9"),
        (
            "Connection closed by authenticating user root 203.0.113.5 port 40222 [preauth]",
            "disconnect",
            "root",
            "203.0.113.5",
        ),
        (
            "Received disconnect from 10.0.0.5 port 50000:11: disconnected by user",
            "disconnect",
            None,
            "10.0.0.5",
        ),
        (
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root",
            "pam_failure",
            "root",
            "203.0.113.7",
        ),
    ],
)
def test_parses_sshd_messages(msg, action, user, ip):
    [event] = ssh.parse_line(RFC + msg)
    assert event.action == action
    assert event.username == user
    assert event.src_ip == ip
    assert event.source == "ssh"
    assert event.host == "web01"
    assert event.ts == datetime(2026, 11, 20, 3, 14, 15, 123456, tzinfo=UTC)


def test_username_with_spaces_is_kept():
    [event] = ssh.parse_line(
        RFC + "Failed password for invalid user john smith from 203.0.113.5 port 1 ssh2"
    )
    assert event.username == "john smith"


def test_classic_syslog_timestamp_uses_given_year():
    [event] = ssh.parse_line(
        CLASSIC + "Failed password for root from 203.0.113.5 port 1 ssh2", year=2015
    )
    assert event.ts == datetime(2015, 11, 20, 3, 14, 15, tzinfo=UTC)


def test_classic_timestamp_single_digit_day():
    [event] = ssh.parse_line(
        "Dec  5 06:55:46 LabSZ sshd[24200]: Invalid user x from 1.2.3.4", year=2015
    )
    assert event.ts == datetime(2015, 12, 5, 6, 55, 46, tzinfo=UTC)


def test_year_inference_never_puts_events_in_the_future():
    now = datetime(2026, 1, 3, tzinfo=UTC)
    assert ssh.parse_timestamp("Dec 30 23:59:59", now=now).year == 2025
    assert ssh.parse_timestamp("Jan  2 10:00:00", now=now).year == 2026


def test_message_repeated_expands_into_n_events():
    line = (
        RFC + "message repeated 3 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]"
    )
    events = ssh.parse_line(line)
    assert len(events) == 3
    assert {e.action for e in events} == {"login_failed"}
    assert len({e.line_hash for e in events}) == 3  # each stored separately


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage that is not syslog",
        RFC + "Server listening on 0.0.0.0 port 22.",  # sshd but not interesting
        "2026-11-20T03:14:15+00:00 web01 CRON[99]: pam_unix(cron:session): session opened",
        "2026-11-20T03:14:15+00:00 web01 sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls",
    ],
)
def test_ignores_non_sshd_or_uninteresting_lines(line):
    assert ssh.parse_line(line) == []


def test_parse_lines_counts_skipped():
    result = ssh.parse_lines(
        [RFC + "Failed password for root from 1.2.3.4 port 1 ssh2", "junk", ""]
    )
    assert len(result.events) == 1
    assert result.skipped == 1


def test_line_hash_depends_on_file_and_line_number():
    line = RFC + "Failed password for root from 1.2.3.4 port 1 ssh2"
    a = ssh.parse_line(line, "a.log", 1)[0]
    b = ssh.parse_line(line, "a.log", 2)[0]
    c = ssh.parse_line(line, "a.log", 1)[0]
    assert a.line_hash != b.line_hash
    assert a.line_hash == c.line_hash
