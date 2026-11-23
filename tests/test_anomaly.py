import random

import numpy as np

from conftest import frame, ssh, web
from logsentinel.detection.anomaly import FEATURES, build_features, detect_anomalies


def normal_traffic(n_ips: int = 60, seed: int = 1) -> list[dict]:
    """Many ordinary visitors: a few page views each, almost no errors."""
    rng = random.Random(seed)
    rows = []
    for i in range(n_ips):
        ip = f"100.64.0.{i + 1}"
        start = rng.uniform(0, 20 * 3600)
        for j in range(rng.randint(3, 10)):
            rows.append(web(start + j * 20, path=rng.choice(["/", "/a", "/b"]), status=200, ip=ip))
    return rows


def test_build_features_one_row_per_ip_hour():
    rows = [
        web(0, path="/a", status=200, ip="1.1.1.1"),
        web(10, path="/b", status=404, ip="1.1.1.1"),
        ssh(20, "login_failed", ip="2.2.2.2", user="root"),
        ssh(30, "login_success", ip="2.2.2.2", user="root"),
        ssh(4000, "login_failed", ip="2.2.2.2", user="admin"),  # next hour
    ]
    feats = build_features(frame(rows)).set_index(["src_ip", "bucket"]).sort_index()
    assert len(feats) == 3
    first_web = feats.loc["1.1.1.1"].iloc[0]
    assert first_web["error_ratio"] == 0.5
    assert first_web["distinct_paths"] == 2
    first_ssh = feats.loc["2.2.2.2"].iloc[0]
    assert first_ssh["failed_login_ratio"] == 0.5
    assert first_ssh["events"] == 2
    assert set(FEATURES) <= set(feats.columns)
    assert np.isclose(first_web["hour_sin"] ** 2 + first_web["hour_cos"] ** 2, 1)


def test_scanner_is_flagged_and_normal_visitors_mostly_not():
    rows = normal_traffic()
    rows += [
        web(3600 + i * 0.5, path=f"/admin{i}", status=404, ip="203.0.113.66") for i in range(400)
    ]
    result = detect_anomalies(frame(rows), contamination=0.02)
    flagged = {d.entity for d in result.detections}
    assert "203.0.113.66" in flagged
    assert len(flagged) <= 3
    det = next(d for d in result.detections if d.entity == "203.0.113.66")
    assert det.rule_id == "ANOM-001"
    assert det.score is not None and det.score > 0
    assert "high error ratio" in det.description or "many distinct URLs" in det.description


def test_too_little_data_returns_no_detections():
    result = detect_anomalies(frame(normal_traffic(n_ips=3)))
    assert result.detections == []


def test_deterministic_with_fixed_seed():
    rows = frame(normal_traffic())
    a = detect_anomalies(rows).features["score"].tolist()
    b = detect_anomalies(rows).features["score"].tolist()
    assert a == b


def test_empty_events():
    assert build_features(frame([])).empty
