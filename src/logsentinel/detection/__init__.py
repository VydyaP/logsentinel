"""Detection engine: YAML rules plus an Isolation Forest anomaly detector."""

from logsentinel.detection.anomaly import detect_anomalies
from logsentinel.detection.base import Detection
from logsentinel.detection.rules import Rule, load_rules, run_rules

__all__ = ["Detection", "Rule", "detect_anomalies", "load_rules", "run_rules"]
