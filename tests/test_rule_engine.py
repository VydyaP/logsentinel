"""The generic rule engine: YAML loading/validation, windows and condition operators."""

from pathlib import Path

import pandas as pd
import pytest
from pydantic import ValidationError

from conftest import frame, ssh, web
from logsentinel.detection.rules import (
    Rule,
    condition_mask,
    load_rules,
    parse_window,
    prepare_events,
)

BASE = {
    "id": "TST-001",
    "name": "test",
    "description": "test rule",
    "severity": "low",
    "type": "threshold",
    "window": "5m",
    "mitre": {"technique_id": "T0000", "technique_name": "x", "tactic": "y"},
}


def test_parse_window():
    assert parse_window("30s") == pd.Timedelta(seconds=30)
    assert parse_window("5m") == pd.Timedelta(minutes=5)
    assert parse_window("2h") == pd.Timedelta(hours=2)
    assert parse_window("1d") == pd.Timedelta(days=1)
    with pytest.raises(ValueError):
        parse_window("5 minutes")


def test_shipped_rules_load_and_have_runbooks(rules):
    root = Path(__file__).resolve().parents[1]
    assert len(rules) >= 9
    for rule in rules.values():
        assert rule.runbook and (root / rule.runbook).exists(), f"missing runbook for {rule.id}"
        assert rule.response, f"{rule.id} needs response steps"
        assert rule.mitre.technique_id.startswith("T")


@pytest.mark.parametrize(
    "override",
    [
        {"severity": "urgent"},
        {"type": "magic"},
        {"window": "five minutes"},
        {"id": "bad id"},
        {"type": "distinct"},  # missing distinct_field
        {"type": "sequence"},  # missing then
        {"threshold": 0},
    ],
)
def test_invalid_rules_are_rejected(override):
    with pytest.raises(ValidationError):
        Rule.model_validate({**BASE, **override})


def test_duplicate_rule_ids_are_rejected(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "rules:\n  - {id: TST-001, name: a, description: a, severity: low, type: threshold,"
        " window: 1m, mitre: {technique_id: T1, technique_name: x, tactic: y}}\n"
    )
    (tmp_path / "b.yaml").write_text((tmp_path / "a.yaml").read_text())
    with pytest.raises(ValueError, match="Duplicate"):
        load_rules(tmp_path)


def test_new_rule_can_be_added_with_yaml_only(tmp_path):
    (tmp_path / "custom.yaml").write_text(
        """
rules:
  - id: CUS-001
    name: Admin page from outside
    description: Requests to /admin
    severity: medium
    type: threshold
    where: {source: web, path: {regex: "^/admin"}}
    threshold: 1
    window: 10m
    mitre: {technique_id: T1190, technique_name: Exploit Public-Facing Application, tactic: Initial Access}
"""
    )
    from logsentinel.detection.rules import run_rules

    [rule] = load_rules(tmp_path)
    dets = run_rules([rule], frame([web(0, path="/admin/login"), web(1, path="/home")]))
    assert [d.rule_id for d in dets] == ["CUS-001"]


def test_condition_operators():
    df = prepare_events(
        frame(
            [
                web(0, path="/a", status=200, ua="curl"),
                web(1, path="/b%20c", status=404, ua="Nikto"),
                web(2, path="/c", status=500, ua=None),
                ssh(3, "login_failed"),
            ]
        )
    )
    assert condition_mask(df, {"source": "web"}).sum() == 3
    assert condition_mask(df, {"status": [404, 500]}).sum() == 2
    assert condition_mask(df, {"status": {"gte": 400, "lte": 499}}).sum() == 1
    assert condition_mask(df, {"user_agent": {"regex": "nikto"}}).sum() == 1  # case-insensitive
    assert condition_mask(df, {"source": "web", "user_agent": {"not_regex": "nikto"}}).sum() == 2
    assert condition_mask(df, {"status": {"not_in": [200]}, "source": "web"}).sum() == 2
    assert condition_mask(df, {"path_decoded": {"regex": "b c"}}).sum() == 1
    assert condition_mask(df, {"hour": {"outside": [7, 21]}}, timezone="UTC").sum() == 4  # 06:00
    assert condition_mask(df, {"hour": {"outside": [7, 21]}}, timezone="Asia/Kolkata").sum() == 0
    with pytest.raises(ValueError):
        condition_mask(df, {"nonexistent": 1})
    with pytest.raises(ValueError):
        condition_mask(df, {"status": {"approx": 1}})


def test_disabled_rule_does_not_run(rules):
    from logsentinel.detection.rules import run_rules

    rule = rules["WEB-005"].model_copy(update={"enabled": False})
    assert run_rules([rule], frame([web(0, ua="sqlmap")])) == []
