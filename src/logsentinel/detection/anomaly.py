"""Behavioural anomaly detection with scikit-learn's Isolation Forest.

Rules catch attacks we already know how to describe. The anomaly detector is a
safety net for behaviour that is merely *unusual*: we summarise each source IP's
activity per hour into a few numbers (features) and ask Isolation Forest which
IP-hours look least like the rest.

How Isolation Forest works, in one paragraph: it builds many random trees, each
splitting the data on a random feature at a random value. Unusual points are
easy to separate, so they end up alone after only a few splits (a short path
from the root). The average path length across all trees becomes the anomaly
score - shorter path, more anomalous. It needs no labels, which suits security
data where labelled attacks are rare.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from logsentinel.detection.base import Detection

RULE_ID = "ANOM-001"
RULE_NAME = "Anomalous behaviour (Isolation Forest)"

FEATURES = [
    "log_events",  # how much activity (log-scaled)
    "log_peak_per_min",  # busiest minute (log-scaled request/attempt rate)
    "error_ratio",  # share of web requests answered 4xx/5xx
    "log_distinct_paths",  # how many different URLs (log-scaled)
    "failed_login_ratio",  # failed / all SSH login attempts
    "log_distinct_users",  # how many different usernames tried (log-scaled)
    "hour_sin",  # hour of day on a circle, so 23:00 is close to 00:00
    "hour_cos",
]


def build_features(events: pd.DataFrame, bucket: str = "1h") -> pd.DataFrame:
    """Aggregate events into one row per (source IP, time bucket) with numeric features."""
    df = events[events["src_ip"].notna()].copy()
    if df.empty:
        return pd.DataFrame(columns=["src_ip", "bucket", *FEATURES, "events"])
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    df["bucket"] = df["ts"].dt.floor(bucket)
    df["minute"] = df["ts"].dt.floor("1min")
    is_web = df["source"] == "web"
    status = pd.to_numeric(df["status"], errors="coerce")
    df["web"] = is_web.astype(int)
    df["web_error"] = (is_web & (status >= 400)).astype(int)
    df["failed"] = (df["action"] == "login_failed").astype(int)
    df["login_attempt"] = df["action"].isin(["login_failed", "login_success"]).astype(int)

    grouped = df.groupby(["src_ip", "bucket"])
    feats = grouped.agg(
        events=("id", "size"),
        web=("web", "sum"),
        web_error=("web_error", "sum"),
        failed=("failed", "sum"),
        login_attempt=("login_attempt", "sum"),
        distinct_paths=("path", "nunique"),
        distinct_users=("username", "nunique"),
    ).reset_index()
    peak = (
        df.groupby(["src_ip", "bucket", "minute"]).size().groupby(["src_ip", "bucket"]).max()
    )
    feats["peak_per_min"] = peak.to_numpy()

    feats["error_ratio"] = (feats["web_error"] / feats["web"].replace(0, np.nan)).fillna(0.0)
    feats["failed_login_ratio"] = (
        feats["failed"] / feats["login_attempt"].replace(0, np.nan)
    ).fillna(0.0)
    for col in ["events", "peak_per_min", "distinct_paths", "distinct_users"]:
        feats[f"log_{col}"] = np.log1p(feats[col].astype(float))
    hour = feats["bucket"].dt.hour
    feats["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    feats["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    return feats


@dataclass
class AnomalyResult:
    features: pd.DataFrame  # one row per (ip, bucket) with "score" and "is_anomaly"
    detections: list[Detection]


def detect_anomalies(
    events: pd.DataFrame,
    contamination: float = 0.02,
    random_state: int = 42,
    min_rows: int = 20,
) -> AnomalyResult:
    """Score every (IP, hour) and turn the most anomalous ones into detections.

    ``contamination`` is our guess of the share of anomalous rows; Isolation
    Forest flags roughly that fraction. It is the main tuning knob: higher
    catches more attacks but raises more false positives.
    """
    feats = build_features(events)
    if len(feats) < min_rows:  # too little data to say what "normal" looks like
        feats["score"] = 0.0
        feats["is_anomaly"] = False
        return AnomalyResult(feats, [])

    model = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=random_state
    )
    matrix = feats[FEATURES].to_numpy()
    model.fit(matrix)
    # score_samples: higher = more normal. Negate so higher = more anomalous.
    feats["score"] = -model.score_samples(matrix)
    feats["is_anomaly"] = model.predict(matrix) == -1

    detections = []
    p95 = feats[FEATURES].quantile(0.95)
    df = events.copy()
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    for row in feats[feats["is_anomaly"]].itertuples(index=False):
        start = row.bucket
        end = start + pd.Timedelta(hours=1)
        mask = (df["src_ip"] == row.src_ip) & (df["ts"] >= start) & (df["ts"] < end)
        window_events = df[mask].sort_values("ts")
        unusual = [
            f for f in FEATURES[:6] if getattr(row, f) > p95[f] and getattr(row, f) > 0
        ]
        reason = ", ".join(_FEATURE_LABELS[f] for f in unusual) or "unusual mix of behaviour"
        detections.append(
            Detection(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity="medium",
                entity=str(row.src_ip),
                entity_type="ip",
                description=(
                    f"{row.src_ip} behaved unlike other sources between "
                    f"{start:%Y-%m-%d %H:%M} and {end:%H:%M} UTC ({row.events} events). "
                    f"Stands out on: {reason}."
                ),
                first_ts=window_events["ts"].iloc[0].to_pydatetime(),
                last_ts=window_events["ts"].iloc[-1].to_pydatetime(),
                event_ids=[int(i) for i in window_events["id"].head(200)],
                event_count=len(window_events),
                score=round(float(row.score), 4),
                details={
                    "features": {f: round(float(getattr(row, f)), 3) for f in FEATURES},
                    "unusual_features": unusual,
                    "contamination": contamination,
                },
            )
        )
    return AnomalyResult(feats, detections)


_FEATURE_LABELS = {
    "log_events": "high volume",
    "log_peak_per_min": "high request rate",
    "error_ratio": "high error ratio",
    "log_distinct_paths": "many distinct URLs",
    "failed_login_ratio": "high failed-login ratio",
    "log_distinct_users": "many usernames",
}
