"""The end-to-end detection run: events -> detections -> alerts/incidents -> notify/ticket."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from logsentinel.alerts import save_detections
from logsentinel.config import get_settings
from logsentinel.detection import detect_anomalies, load_rules, run_rules
from logsentinel.detection.base import EVENT_COLUMNS, Detection
from logsentinel.models import Alert, Event, Incident
from logsentinel.notify import notify
from logsentinel.ticketing import TicketingProvider, get_provider

log = logging.getLogger(__name__)


@dataclass
class DetectionRun:
    events_scanned: int = 0
    detections: int = 0
    new_alerts: list[Alert] = field(default_factory=list)
    notified: int = 0


def load_events(session: Session, since: datetime | None = None) -> pd.DataFrame:
    """Read events (optionally only newer than ``since``) into a DataFrame."""
    columns = [getattr(Event, c) for c in EVENT_COLUMNS]
    query = select(*columns).order_by(Event.ts)
    if since is not None:
        query = query.where(Event.ts >= since)
    rows = session.execute(query).all()
    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df


def run_detection(
    session: Session,
    *,
    rules_dir: Path | None = None,
    lookback: timedelta | None = None,
    use_anomaly: bool = True,
    contamination: float = 0.02,
    provider: TicketingProvider | None = None,
    send_notifications: bool = True,
    created_at: datetime | None = None,
) -> DetectionRun:
    """Run all rules (and the anomaly model) and store any new alerts.

    ``lookback`` limits detection to events within that period before the newest
    event (log time, not wall-clock time, so old log files still work).
    """
    settings = get_settings()
    rules = load_rules(rules_dir or settings.rules_dir)
    since = None
    if lookback is not None:
        newest = session.scalar(select(func.max(Event.ts)))
        since = newest - lookback if newest else None
    events = load_events(session, since)
    run = DetectionRun(events_scanned=len(events))
    if events.empty:
        return run

    detections: list[Detection] = run_rules(rules, events)
    if use_anomaly:
        detections += detect_anomalies(events, contamination=contamination).detections
    run.detections = len(detections)

    known_incidents = set(session.scalars(select(Incident.id)))
    run.new_alerts = save_detections(
        session,
        detections,
        incident_window=timedelta(hours=settings.incident_window_hours),
        created_at=created_at,
    )

    provider = provider or get_provider()
    for incident in {a.incident for a in run.new_alerts if a.incident is not None}:
        if incident.id not in known_incidents and incident.external_ref is None:
            incident.external_ref = provider.create_incident(incident).ticket_id
        else:
            provider.update_incident(incident, comment="New alerts added")

    if send_notifications:
        run.notified = notify(run.new_alerts, settings)
    session.flush()
    log.info(
        "Scanned %d events: %d detections, %d new alerts",
        run.events_scanned,
        run.detections,
        len(run.new_alerts),
    )
    return run
