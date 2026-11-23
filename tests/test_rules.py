"""Every shipped detection rule, with at least one positive and one negative case.

``CASES`` maps rule id -> (events that must fire, events that must not fire).
``test_every_rule_has_cases`` fails if someone adds a rule to rules/*.yaml
without adding tests here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from conftest import frame, ssh, web
from logsentinel.detection.rules import run_rules

Rows = list[dict[str, Any]]


def brute_force(n: int, gap: float, ip: str = "203.0.113.10") -> Rows:
    return [ssh(i * gap, "login_failed", ip=ip, user="root") for i in range(n)]


def spray(users: int, gap: float = 30) -> Rows:
    return [ssh(i * gap, "login_failed", user=f"user{i}") for i in range(users)]


def fails_then_success(fails: int, gap: float = 5) -> Rows:
    rows = [ssh(i * gap, "login_failed", user="deploy") for i in range(fails)]
    return [*rows, ssh(fails * gap + 5, "login_success", user="deploy")]


def requests(n: int, status: int, gap: float = 1, ip: str = "203.0.113.20") -> Rows:
    return [web(i * gap, path=f"/x{i}", status=status, ip=ip) for i in range(n)]


# seconds offset from T0 (06:00 UTC = 11:30 IST); 18:00 UTC = 23:30 IST
NIGHT = 12 * 3600

CASES: dict[str, tuple[Callable[[], Rows], Callable[[], Rows]]] = {
    "SSH-001": (
        lambda: brute_force(10, gap=20),  # 10 failures in 3 minutes
        lambda: brute_force(9, gap=20) + brute_force(10, gap=600, ip="203.0.113.99"),
    ),
    "SSH-002": (
        lambda: spray(8),  # 8 usernames in 3.5 minutes
        # too few users; and another IP hammering one user many times
        lambda: spray(7) + brute_force(30, gap=5, ip="203.0.113.77"),
    ),
    "SSH-003": (
        lambda: fails_then_success(5),
        lambda: [
            *fails_then_success(4),  # too few failures
            ssh(0, "login_success", ip="10.0.0.5", user="alice"),
        ],
    ),
    "SSH-004": (
        lambda: [ssh(NIGHT, "login_success", ip="10.0.0.5", user="alice")],
        lambda: [
            ssh(0, "login_success", ip="10.0.0.5", user="alice"),  # 11:30 IST
            ssh(NIGHT, "login_failed", ip="10.0.0.5", user="alice"),  # failed, not a login
        ],
    ),
    "WEB-001": (
        lambda: requests(25, 404),
        # 24 not-found in a burst, lots of 200s, and a slow trickle of 404s from another IP
        lambda: requests(24, 404) + requests(100, 200) + requests(30, 404, gap=60, ip="10.0.0.9"),
    ),
    "WEB-002": (
        lambda: [
            web(0, path="/products?id=1%27%20OR%20%271%27%3D%271"),
            web(5, path="/p?id=1%20UNION%20SELECT%20password%20FROM%20users--"),
            web(9, path="/p?id=1%27%20AND%20SLEEP(5)--"),
        ],
        lambda: [
            web(0, path="/search?q=rock+and+roll"),
            web(1, path="/products?id=12&sort=price"),
            web(2, path="/blog/how-to-select-a-union-rep"),
        ],
    ),
    "WEB-003": (
        lambda: [
            web(0, path="/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
            web(1, path="/q?x=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"),
        ],
        lambda: [
            web(0, path="/scripts/app.js"),
            web(1, path="/search?q=onerror+handling+in+python"),
        ],
    ),
    "WEB-004": (
        lambda: [
            web(0, path="/download?file=../../../../etc/passwd"),
            web(1, path="/static/%252e%252e%252f%252e%252e%252fetc%252fshadow"),  # double-encoded
        ],
        lambda: [
            web(0, path="/docs/etc/passwords-policy"),
            web(1, path="/files/report..final.pdf"),
        ],
    ),
    "WEB-005": (
        lambda: [
            web(0, ua="Mozilla/5.00 (Nikto/2.5.0)"),
            web(1, ua="sqlmap/1.8 (https://sqlmap.org)"),
        ],
        lambda: [web(0, ua="Mozilla/5.0 (Windows NT 10.0)"), web(1, ua="curl/8.4.0")],
    ),
}


def ids(detections) -> set[str]:
    return {d.rule_id for d in detections}


def test_every_rule_has_cases(rules):
    assert set(rules) == set(CASES), "add positive and negative cases for new rules"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_positive_case(rule_id, rules):
    positive, _ = CASES[rule_id]
    detections = [d for d in run_rules([rules[rule_id]], frame(positive())) if d.rule_id == rule_id]
    assert detections, f"{rule_id} should fire"
    det = detections[0]
    assert det.severity == rules[rule_id].severity
    assert det.mitre_technique == rules[rule_id].mitre.technique_id
    assert det.event_ids
    assert det.description


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet_on_negative_case(rule_id, rules):
    _, negative = CASES[rule_id]
    assert rule_id not in ids(run_rules([rules[rule_id]], frame(negative())))


def test_one_alert_per_burst_not_per_event(rules):
    detections = run_rules([rules["SSH-001"]], frame(brute_force(200, gap=2)))
    assert len(detections) == 1
    assert detections[0].event_count == 200


def test_two_separate_bursts_give_two_alerts(rules):
    rows = brute_force(12, gap=5) + [ssh(7200 + i * 5, "login_failed") for i in range(12)]
    assert len(run_rules([rules["SSH-001"]], frame(rows))) == 2


def test_sequence_rule_reports_compromised_user(rules):
    [det] = run_rules([rules["SSH-003"]], frame(fails_then_success(6)))
    assert det.details["successful_user"] == "deploy"
    assert det.event_count == 7
    assert "deploy" in det.description


def test_old_failures_outside_window_do_not_count(rules):
    rows = [ssh(i * 5, "login_failed", user="deploy") for i in range(5)]
    rows.append(ssh(3 * 3600, "login_success", user="deploy"))  # 3 hours later
    assert run_rules([rules["SSH-003"]], frame(rows)) == []


def test_fingerprint_is_stable_across_runs(rules):
    rows = frame(brute_force(15, gap=3))
    a = run_rules([rules["SSH-001"]], rows)[0]
    b = run_rules([rules["SSH-001"]], rows)[0]
    assert a.fingerprint == b.fingerprint


def test_empty_input_gives_no_detections(rules):
    assert run_rules(list(rules.values()), frame([])) == []
