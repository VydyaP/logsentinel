"""Build a ready-to-explore demo database: synthetic logs, detections and simulated triage.

The triage history (who acknowledged what and when) is *simulated* so the SLA
view has something to show. It is clearly marked in each note.
"""

from __future__ import annotations

import random
import tempfile
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from logsentinel.alerts import SLA_TARGETS, update_alert
from logsentinel.ingest import ingest_file
from logsentinel.models import Alert, AlertNote, AlertStatus, Event, Incident, alert_events
from logsentinel.pipeline import run_detection

ANALYSTS = ["analyst-1", "analyst-2", "analyst-3"]


def reset(session: Session) -> None:
    """Delete all data (keeps the tables)."""
    for table in (AlertNote.__table__, alert_events, Alert.__table__, Incident.__table__, Event.__table__):
        session.execute(delete(table))
    session.flush()


def simulate_triage(session: Session, labelled_entities: set[str], seed: int = 7) -> int:
    """Give most alerts a realistic history: acknowledged, investigated, closed.

    Alerts on labelled attack IPs get resolved; alerts on benign sources become
    false positives. Some alerts are left open (or acknowledged late) so the SLA
    view shows breaches as well as successes.
    """
    rng = random.Random(seed)
    alerts = session.scalars(select(Alert).order_by(Alert.first_event_at)).all()
    for alert in alerts:
        # Detection runs within a couple of minutes of the last event.
        alert.created_at = alert.last_event_at + timedelta(seconds=rng.uniform(30, 180))
        roll = rng.random()
        if roll < 0.2:
            continue  # still New
        ack_target, resolve_target = SLA_TARGETS[alert.severity]
        # Most acknowledgements meet the SLA; about 1 in 6 is late.
        ack_factor = rng.uniform(0.1, 0.9) if rng.random() > 0.17 else rng.uniform(1.2, 3)
        ack_at = alert.created_at + ack_target * ack_factor
        analyst = rng.choice(ANALYSTS)
        update_alert(session, alert, status=AlertStatus.INVESTIGATING.value, assignee=analyst,
                     author=analyst, now=ack_at)  # fmt: skip
        update_alert(session, alert, note="[simulated triage] Reviewed raw log lines and source history.",
                     author=analyst, now=ack_at + timedelta(minutes=3))  # fmt: skip
        if roll < 0.35:
            continue  # still being investigated
        res_factor = rng.uniform(0.2, 0.9) if rng.random() > 0.15 else rng.uniform(1.1, 2)
        resolved_at = alert.created_at + resolve_target * res_factor
        if alert.entity in labelled_entities:
            status, note = AlertStatus.RESOLVED.value, "[simulated triage] Confirmed malicious; source blocked."
        else:
            status, note = AlertStatus.FALSE_POSITIVE.value, "[simulated triage] Benign: known internal tool / planned work."
        update_alert(session, alert, status=status, note=note, author=analyst, now=resolved_at)
    session.flush()
    return len(alerts)


def seed_demo(session: Session, days: int = 2, seed: int = 7, out_dir: Path | None = None) -> dict[str, int]:
    """Generate logs, ingest them, run detection and simulate triage."""
    from simulator.generate import generate

    with tempfile.TemporaryDirectory() as tmp:
        folder = out_dir or Path(tmp)
        generate(folder, days=days, seed=seed)
        events = 0
        for name in ("auth.log", "access.log"):
            events += ingest_file(session, folder / name).inserted
        # Attack sources (IPs and targeted usernames) from the ground-truth labels.
        labelled: set[str] = set()
        for line in (folder / "labels.csv").read_text().splitlines()[1:]:
            fields = line.split(",")
            labelled.update(f for f in (fields[2], fields[3]) if f)
        session.flush()
        run = run_detection(session, send_notifications=False)
        triaged = simulate_triage(session, labelled, seed)
    return {"events": events, "alerts": len(run.new_alerts), "triaged": triaged}
