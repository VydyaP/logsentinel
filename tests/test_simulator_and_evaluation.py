import csv
from datetime import UTC, datetime

import pytest

from conftest import RULES_DIR
from logsentinel.evaluate import evaluate, to_markdown
from simulator.generate import generate

START = datetime(2026, 11, 16, tzinfo=UTC)


@pytest.fixture(scope="module")
def sim(tmp_path_factory):
    out = tmp_path_factory.mktemp("sim")
    counts = generate(out, days=2, seed=7, start=START)
    return out, counts


def test_simulator_is_deterministic(sim, tmp_path):
    out, counts = sim
    again = generate(tmp_path, days=2, seed=7, start=START)
    assert counts == again
    assert (out / "auth.log").read_text() == (tmp_path / "auth.log").read_text()


def test_simulator_writes_labelled_attacks(sim):
    out, counts = sim
    with (out / "labels.csv").open() as fh:
        labels = list(csv.DictReader(fh))
    assert counts["attacks"] == len(labels) == 13
    kinds = {lb["attack_type"] for lb in labels}
    assert {"brute_force", "password_spray", "brute_force_success", "off_hours_login",
            "web_scan", "sqli", "xss", "path_traversal", "low_and_slow_brute_force"} <= kinds  # fmt: skip
    assert all(lb["src_ip"].startswith("203.0.113.") for lb in labels)  # documentation range only


def test_evaluation_on_synthetic_data(sim):
    out, _ = sim
    result = evaluate([out / "auth.log", out / "access.log"], out / "labels.csv", RULES_DIR)
    assert result.attacks == 13
    # Rules catch every attack except the deliberately stealthy one.
    missed = [r["attack_type"] for r in result.attack_rows if not r["detected_by_rules"]]
    assert missed == ["low_and_slow_brute_force"]
    assert result.rules_overall["alert_precision"] >= 0.7
    assert 0 < result.anomaly_windows["recall"] <= 1
    md = to_markdown(result, "logsentinel evaluate")
    assert "Isolation Forest" in md and "low_and_slow_brute_force" in md
