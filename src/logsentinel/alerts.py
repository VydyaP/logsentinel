"""Alert storage, incident grouping, triage workflow and SLA metrics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from logsentinel.detection.base import Detection
from logsentinel.models import (
    SEVERITY_ORDER,
    Alert,
    AlertNote,
    AlertStatus,
    Event,
    Incident,
    Severity,
    utcnow,
)

# SLA targets per severity: (time to acknowledge, time to resolve).
# Loosely modelled on common managed-SOC contracts; adjust to your own.
SLA_TARGETS: dict[str, tuple[timedelta, timedelta]] = {
    "critical": (timedelta(minutes=15), timedelta(hours=4)),
    "high": (timedelta(minutes=30), timedelta(hours=8)),
    "medium": (timedelta(hours=4), timedelta(hours=24)),
    "low": (timedelta(hours=24), timedelta(hours=72)),
}


def max_severity(values: list[str]) -> str:
    return max((Severity(v) for v in values), key=lambda s: s.rank).value


# --------------------------------------------------------------------------- creating alerts


def save_detections(
    session: Session,
    detections: list[Detection],
    incident_window: timedelta = timedelta(hours=24),
    created_at: datetime | None = None,
) -> list[Alert]:
    """Store new detections as alerts and attach each to an incident.

    Detections whose fingerprint already exists are skipped, so running
    detection repeatedly over the same events never creates duplicates.
    Returns only the newly created alerts.
    """
    if not detections:
        return []
    fingerprints = [d.fingerprint for d in detections]
    existing = set(
        session.scalars(select(Alert.fingerprint).where(Alert.fingerprint.in_(fingerprints)))
    )
    new_alerts: list[Alert] = []
    seen: set[str] = set()
    for det in sorted(detections, key=lambda d: d.first_ts):
        if det.fingerprint in existing or det.fingerprint in seen:
            continue
        seen.add(det.fingerprint)
        events = list(session.scalars(select(Event).where(Event.id.in_(det.event_ids))))
        alert = Alert(
            fingerprint=det.fingerprint,
            rule_id=det.rule_id,
            rule_name=det.rule_name,
            severity=det.severity,
            mitre_technique=det.mitre_technique,
            mitre_name=det.mitre_name,
            mitre_tactic=det.mitre_tactic,
            entity=det.entity,
            entity_type=det.entity_type,
            description=det.description,
            event_count=det.event_count,
            first_event_at=det.first_ts,
            last_event_at=det.last_ts,
            score=det.score,
            details=det.details,
            status=AlertStatus.NEW.value,
            created_at=created_at or utcnow(),
            events=events,
        )
        session.add(alert)
        attach_to_incident(session, alert, incident_window)
        new_alerts.append(alert)
    session.flush()
    return new_alerts


def attach_to_incident(session: Session, alert: Alert, window: timedelta) -> Incident:
    """Put the alert into an open incident for the same entity, or open a new one.

    "Same entity" means the same source IP (or username for user-based rules).
    An incident stays joinable while it is not closed and its last activity is
    within ``window`` of the new alert. This turns 40 alerts from one attacker
    into one case for the analyst.
    """
    session.flush()
    candidates = session.scalars(
        select(Incident)
        .where(Incident.entity == alert.entity)
        .where(Incident.status.not_in([s.value for s in AlertStatus if s.is_closed]))
        .order_by(Incident.last_seen.desc())
    ).all()
    for incident in candidates:
        if alert.first_event_at - incident.last_seen <= window:
            incident.alerts.append(alert)
            incident.first_seen = min(incident.first_seen, alert.first_event_at)
            incident.last_seen = max(incident.last_seen, alert.last_event_at)
            incident.severity = max_severity([incident.severity, alert.severity])
            incident.title = _incident_title(incident)
            return incident
    incident = Incident(
        entity=alert.entity,
        entity_type=alert.entity_type,
        severity=alert.severity,
        status=AlertStatus.NEW.value,
        first_seen=alert.first_event_at,
        last_seen=alert.last_event_at,
        created_at=alert.created_at,
        title="",
    )
    incident.alerts.append(alert)
    incident.title = _incident_title(incident)
    session.add(incident)
    return incident


def _incident_title(incident: Incident) -> str:
    # Lead with the most severe rule; rule-based alerts before anomaly alerts on ties.
    ranked = sorted(
        incident.alerts,
        key=lambda a: (-Severity(a.severity).rank, a.rule_id.startswith("ANOM"), a.rule_id),
    )
    names = list(dict.fromkeys(a.rule_name for a in ranked))
    label = names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1} more)"
    return f"{label} from {incident.entity}"[:255]


# --------------------------------------------------------------------------- triage


def update_alert(
    session: Session,
    alert: Alert,
    *,
    status: str | None = None,
    assignee: str | None = None,
    note: str | None = None,
    author: str = "analyst",
    now: datetime | None = None,
) -> Alert:
    """Change an alert's status/assignee and/or add a note, keeping an audit trail.

    * The first move away from ``New`` sets ``acknowledged_at`` (time to acknowledge).
    * Moving to ``Resolved`` or ``False positive`` sets ``resolved_at`` (time to resolve).
    * Re-opening a closed alert clears ``resolved_at``.
    """
    now = now or utcnow()
    if status is not None and status != alert.status:
        new_status = AlertStatus(status)  # raises ValueError for unknown statuses
        old_status = alert.status
        alert.status = new_status.value
        if new_status != AlertStatus.NEW and alert.acknowledged_at is None:
            alert.acknowledged_at = now
        alert.resolved_at = now if new_status.is_closed else None
        alert.notes.append(
            AlertNote(author=author, body=f"Status: {old_status} -> {new_status.value}", created_at=now)
        )
    if assignee is not None and assignee != alert.assignee:
        alert.assignee = assignee or None
        if alert.acknowledged_at is None:
            alert.acknowledged_at = now
        alert.notes.append(
            AlertNote(author=author, body=f"Assigned to {assignee or 'nobody'}", created_at=now)
        )
    if note:
        alert.notes.append(AlertNote(author=author, body=note.strip(), created_at=now))
    if alert.incident is not None:
        refresh_incident_status(alert.incident)
    session.flush()
    return alert


def refresh_incident_status(incident: Incident) -> None:
    """Derive the incident status from its alerts.

    All alerts closed -> Resolved (or False positive if every one was a false
    positive); any alert being worked on -> Investigating; otherwise New.
    """
    statuses = [AlertStatus(a.status) for a in incident.alerts]
    if statuses and all(s.is_closed for s in statuses):
        if all(s == AlertStatus.FALSE_POSITIVE for s in statuses):
            incident.status = AlertStatus.FALSE_POSITIVE.value
        else:
            incident.status = AlertStatus.RESOLVED.value
    elif any(s != AlertStatus.NEW for s in statuses):
        incident.status = AlertStatus.INVESTIGATING.value
    else:
        incident.status = AlertStatus.NEW.value


# --------------------------------------------------------------------------- SLA metrics


@dataclass
class SlaRow:
    severity: str
    alerts: int
    open: int
    mtta_minutes: float | None
    mttr_minutes: float | None
    ack_target_minutes: float
    resolve_target_minutes: float
    ack_breaches: int
    resolve_breaches: int


def sla_report(session: Session, now: datetime | None = None) -> list[SlaRow]:
    """Mean time to acknowledge/resolve and SLA breaches, per severity.

    An open alert already past its target counts as a breach too, so
    ignoring an alert cannot make the numbers look better.
    """
    now = now or utcnow()
    rows = session.execute(
        select(Alert.severity, Alert.status, Alert.created_at, Alert.acknowledged_at, Alert.resolved_at)
    ).all()
    df = pd.DataFrame(rows, columns=["severity", "status", "created", "acked", "resolved"])
    for col in ("created", "acked", "resolved"):
        df[col] = pd.to_datetime(df[col], utc=True)
    now_ts = pd.Timestamp(now)
    report = []
    for severity in reversed(SEVERITY_ORDER):
        sev = severity.value
        part = df[df["severity"] == sev]
        ack_target, resolve_target = SLA_TARGETS[sev]
        tta = (part["acked"] - part["created"]).dropna()
        ttr = (part["resolved"] - part["created"]).dropna()
        ack_deadline = part["created"] + ack_target
        res_deadline = part["created"] + resolve_target
        acked_or_now = part["acked"].fillna(now_ts)
        resolved_or_now = part["resolved"].fillna(now_ts)
        report.append(
            SlaRow(
                severity=sev,
                alerts=len(part),
                open=int(part["resolved"].isna().sum()),
                mtta_minutes=_minutes(tta.mean()) if len(tta) else None,
                mttr_minutes=_minutes(ttr.mean()) if len(ttr) else None,
                ack_target_minutes=ack_target.total_seconds() / 60,
                resolve_target_minutes=resolve_target.total_seconds() / 60,
                ack_breaches=int((acked_or_now > ack_deadline).sum()),
                resolve_breaches=int((resolved_or_now > res_deadline).sum()),
            )
        )
    return report


def _minutes(value: pd.Timedelta) -> float:
    return round(value.total_seconds() / 60, 1)
