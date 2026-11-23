"""Types shared by the rule engine and the anomaly detector."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pandas as pd

# Columns of the event DataFrame that detectors work on.
EVENT_COLUMNS = [
    "id",
    "ts",
    "source",
    "host",
    "src_ip",
    "username",
    "action",
    "method",
    "path",
    "status",
    "user_agent",
    "raw",
]


@dataclass
class Detection:
    """A detector's finding, before it is stored as an :class:`~logsentinel.models.Alert`."""

    rule_id: str
    rule_name: str
    severity: str
    entity: str
    entity_type: str  # "ip" or "user"
    description: str
    first_ts: datetime
    last_ts: datetime
    event_ids: list[int]
    event_count: int
    mitre_technique: str | None = None
    mitre_name: str | None = None
    mitre_tactic: str | None = None
    score: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Same rule + same entity + same start time = same alert (used to dedupe)."""
        key = f"{self.rule_id}|{self.entity}|{self.first_ts.isoformat()}"
        return hashlib.sha256(key.encode()).hexdigest()


def empty_events_frame() -> pd.DataFrame:
    df = pd.DataFrame({col: pd.Series(dtype="object") for col in EVENT_COLUMNS})
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df
