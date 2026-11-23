"""Measure detection quality against the simulator's ground-truth labels.

The evaluation runs on a throw-away in-memory database, so it is reproducible
and never touches real data. Two views are reported:

* **Attack level** - for each injected attack, did any rule (or the anomaly
  model) raise an alert for that source around that time? -> recall per attack type.
* **Alert level** - of all alerts raised, how many point at a real attack? -> precision.
  Alerts on unlabelled traffic count as false positives, even when the traffic is
  "noisy but harmless" by design (on-call logins at night, a broken-link checker).

For the Isolation Forest we also report precision/recall per (IP, hour) window,
and a sweep over the ``contamination`` setting to show the trade-off.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy.orm import Session

from logsentinel.alerts import save_detections
from logsentinel.db import init_db, make_engine
from logsentinel.detection import detect_anomalies, load_rules, run_rules
from logsentinel.detection.base import Detection
from logsentinel.ingest import ingest_file
from logsentinel.pipeline import load_events

MATCH_SLACK = timedelta(minutes=5)


@dataclass
class EvaluationResult:
    events: int
    attacks: int
    attack_rows: list[dict[str, Any]]
    per_type: list[dict[str, Any]]
    rule_precision: list[dict[str, Any]]
    rules_overall: dict[str, float]
    anomaly_windows: dict[str, float]
    contamination_sweep: list[dict[str, float]]
    combined_attack_recall: float
    notes: list[str] = field(default_factory=list)


def load_labels(path: Path) -> pd.DataFrame:
    labels = pd.read_csv(path, dtype={"username": "string"}, keep_default_na=False)
    labels["start"] = pd.to_datetime(labels["start"], utc=True, format="ISO8601")
    labels["end"] = pd.to_datetime(labels["end"], utc=True, format="ISO8601")
    return labels


def _matches(det: Detection, label: pd.Series) -> bool:
    """Does this detection point at this labelled attack (same source, overlapping time)?"""
    same_source = det.entity == label["src_ip"] or (
        det.entity_type == "user" and label["username"] and det.entity == label["username"]
    )
    overlaps = (
        pd.Timestamp(det.first_ts) <= label["end"] + MATCH_SLACK
        and pd.Timestamp(det.last_ts) >= label["start"] - MATCH_SLACK
    )
    return bool(same_source and overlaps)


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def _window_labels(features: pd.DataFrame, labels: pd.DataFrame) -> pd.Series:
    """True for (ip, hour) windows that overlap a labelled attack from that IP."""
    truth = pd.Series(False, index=features.index)
    for _, lb in labels.iterrows():
        bucket_end = features["bucket"] + pd.Timedelta(hours=1)
        truth |= (
            (features["src_ip"] == lb["src_ip"])
            & (features["bucket"] <= lb["end"])
            & (bucket_end > lb["start"])
        )
    return truth


def evaluate(
    log_files: list[Path], labels_path: Path, rules_dir: Path, contamination: float = 0.02
) -> EvaluationResult:
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    with Session(engine) as session:
        for path in log_files:
            ingest_file(session, path)
        session.commit()
        events = load_events(session)
        rules = load_rules(rules_dir)
        rule_dets = run_rules(rules, events)
        anomaly = detect_anomalies(events, contamination=contamination)
        # Exercise the real storage path too (dedupe + incident grouping).
        save_detections(session, rule_dets + anomaly.detections)

    labels = load_labels(labels_path)

    # ---- attack level
    attack_rows = []
    for _, lb in labels.iterrows():
        by_rules = sorted({d.rule_id for d in rule_dets if _matches(d, lb)})
        by_anomaly = any(_matches(d, lb) for d in anomaly.detections)
        expected = [r for r in str(lb["expected_rules"]).split(";") if r]
        attack_rows.append(
            {
                "attack_id": lb["attack_id"],
                "attack_type": lb["attack_type"],
                "src_ip": lb["src_ip"],
                "expected_rules": expected,
                "rules_fired": by_rules,
                "detected_by_rules": bool(by_rules),
                "expected_rule_fired": set(expected) <= set(by_rules),
                "detected_by_anomaly": by_anomaly,
            }
        )
    attacks = pd.DataFrame(attack_rows)
    per_type = (
        attacks.groupby("attack_type")
        .agg(
            attacks=("attack_id", "count"),
            detected_by_rules=("detected_by_rules", "sum"),
            detected_by_anomaly=("detected_by_anomaly", "sum"),
        )
        .reset_index()
        .to_dict("records")
    )

    # ---- alert level (rule precision)
    rule_precision = []
    for rule in rules:
        dets = [d for d in rule_dets if d.rule_id == rule.id]
        tp = sum(1 for d in dets if any(_matches(d, lb) for _, lb in labels.iterrows()))
        rule_precision.append(
            {
                "rule_id": rule.id,
                "alerts": len(dets),
                "true_positive_alerts": tp,
                "false_positive_alerts": len(dets) - tp,
                "precision": round(tp / len(dets), 3) if dets else None,
            }
        )
    tp_alerts = sum(r["true_positive_alerts"] for r in rule_precision)
    fp_alerts = sum(r["false_positive_alerts"] for r in rule_precision)
    missed = int((~attacks["detected_by_rules"]).sum())
    rules_overall = {
        "alert_precision": round(tp_alerts / (tp_alerts + fp_alerts), 3)
        if tp_alerts + fp_alerts
        else 0.0,
        "attack_recall": round(1 - missed / len(attacks), 3),
        "alerts": tp_alerts + fp_alerts,
        "false_positive_alerts": fp_alerts,
        "missed_attacks": missed,
    }

    # ---- anomaly model, per (ip, hour) window
    feats = anomaly.features
    truth = _window_labels(feats, labels)
    pred = feats["is_anomaly"]
    anomaly_windows = {
        "windows": len(feats),
        "attack_windows": int(truth.sum()),
        **_prf(int((pred & truth).sum()), int((pred & ~truth).sum()), int((~pred & truth).sum())),
    }
    sweep = []
    for c in [0.01, 0.02, 0.05, 0.1]:
        f = detect_anomalies(events, contamination=c).features
        p = f["is_anomaly"]
        t = _window_labels(f, labels)
        sweep.append(
            {"contamination": c, **_prf(int((p & t).sum()), int((p & ~t).sum()), int((~p & t).sum()))}
        )

    combined = attacks["detected_by_rules"] | attacks["detected_by_anomaly"]
    notes = []
    for row in attack_rows:
        if not row["detected_by_rules"]:
            how = "but the anomaly model flagged it" if row["detected_by_anomaly"] else "and so did the anomaly model"
            notes.append(f"{row['attack_id']} ({row['attack_type']}) was missed by the rules, {how}.")
    return EvaluationResult(
        events=len(events),
        attacks=len(attacks),
        attack_rows=attack_rows,
        per_type=per_type,
        rule_precision=rule_precision,
        rules_overall=rules_overall,
        anomaly_windows=anomaly_windows,
        contamination_sweep=sweep,
        combined_attack_recall=round(float(combined.mean()), 3),
        notes=notes,
    )


def to_markdown(result: EvaluationResult, command: str) -> str:
    """Render the evaluation as a Markdown page (docs/EVALUATION.md)."""
    r = result
    lines = [
        "# Detection evaluation",
        "",
        "> Generated by `" + command + "`. Data is **synthetic** (see `simulator/`), so these",
        "> numbers show how the detectors behave on known patterns, not real-world accuracy.",
        "",
        f"Events: **{r.events:,}** · labelled attacks: **{r.attacks}**",
        "",
        "## Headline numbers",
        "",
        "| Detector | Precision | Recall | Notes |",
        "|---|---|---|---|",
        f"| YAML rules (alert level / attack level) | {r.rules_overall['alert_precision']:.0%} "
        f"| {r.rules_overall['attack_recall']:.0%} | {r.rules_overall['alerts']} alerts, "
        f"{r.rules_overall['false_positive_alerts']} false positives, "
        f"{r.rules_overall['missed_attacks']} attack(s) missed |",
        f"| Isolation Forest (per IP-hour window) | {r.anomaly_windows['precision']:.0%} "
        f"| {r.anomaly_windows['recall']:.0%} | {r.anomaly_windows['windows']:,} windows, "
        f"{r.anomaly_windows['attack_windows']} contain an attack |",
        f"| Rules **or** Isolation Forest (attack level) | - | {r.combined_attack_recall:.0%} | |",
        "",
        "## Per attack type",
        "",
        "| Attack type | Attacks | Caught by rules | Caught by anomaly model |",
        "|---|---|---|---|",
    ]
    for row in r.per_type:
        lines.append(
            f"| {row['attack_type']} | {row['attacks']} | {row['detected_by_rules']} "
            f"| {row['detected_by_anomaly']} |"
        )
    lines += ["", "## Per rule (alert precision)", "", "| Rule | Alerts | True positive | False positive | Precision |", "|---|---|---|---|---|"]
    for row in r.rule_precision:
        prec = "-" if row["precision"] is None else f"{row['precision']:.0%}"
        lines.append(
            f"| {row['rule_id']} | {row['alerts']} | {row['true_positive_alerts']} "
            f"| {row['false_positive_alerts']} | {prec} |"
        )
    lines += ["", "## Isolation Forest: contamination trade-off", "", "| contamination | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    for row in r.contamination_sweep:
        lines.append(
            f"| {row['contamination']} | {row['tp']} | {row['fp']} | {row['fn']} "
            f"| {row['precision']:.0%} | {row['recall']:.0%} | {row['f1']:.2f} |"
        )
    lines += ["", "## Every attack", "", "| ID | Type | Source | Expected rule(s) | Rules fired | Anomaly |", "|---|---|---|---|---|---|"]
    for row in r.attack_rows:
        fired = ", ".join(row["rules_fired"]) or "**none**"
        lines.append(
            f"| {row['attack_id']} | {row['attack_type']} | {row['src_ip']} "
            f"| {', '.join(row['expected_rules'])} | {fired} | {'yes' if row['detected_by_anomaly'] else 'no'} |"
        )
    if r.notes:
        lines += ["", "## Misses", ""] + [f"- {n}" for n in r.notes]
    return "\n".join(lines) + "\n"


def save(result: EvaluationResult, md_path: Path, json_path: Path, command: str) -> None:
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(to_markdown(result, command))
    json_path.write_text(json.dumps(asdict(result), indent=2, default=str))
