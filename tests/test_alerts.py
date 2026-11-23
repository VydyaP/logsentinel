from datetime import timedelta

import pytest
from sqlalchemy import func, select

from conftest import T0
from logsentinel.alerts import save_detections, sla_report, update_alert
from logsentinel.detection.base import Detection
from logsentinel.models import Alert, AlertStatus, Incident


def det(
    rule="SSH-001", entity="203.0.113.10", minutes=0, severity="high", entity_type="ip"
) -> Detection:
    start = T0 + timedelta(minutes=minutes)
    return Detection(
        rule_id=rule,
        rule_name=f"Rule {rule}",
        severity=severity,
        entity=entity,
        entity_type=entity_type,
        description="test",
        first_ts=start,
        last_ts=start + timedelta(minutes=5),
        event_ids=[],
        event_count=10,
        mitre_technique="T1110",
    )


def test_duplicates_are_not_stored_twice(session):
    assert len(save_detections(session, [det()])) == 1
    assert save_detections(session, [det()]) == []
    assert session.scalar(select(func.count()).select_from(Alert)) == 1


def test_alerts_from_same_source_share_an_incident(session):
    alerts = save_detections(
        session,
        [
            det("SSH-001"),
            det("SSH-003", minutes=10, severity="critical"),
            det("SSH-001", entity="203.0.113.99"),
        ],
    )
    by_key = {(a.rule_id, a.entity): a for a in alerts}
    brute = by_key[("SSH-001", "203.0.113.10")]
    success = by_key[("SSH-003", "203.0.113.10")]
    other = by_key[("SSH-001", "203.0.113.99")]
    assert brute.incident_id == success.incident_id
    assert other.incident_id != brute.incident_id
    incident = session.get(Incident, brute.incident_id)
    assert incident.severity == "critical"  # highest of its alerts
    assert len(incident.alerts) == 2
    assert incident.title.startswith("Rule SSH-003")  # most severe rule leads the title


def test_new_incident_after_window_or_when_closed(session):
    [first] = save_detections(session, [det()])
    [later] = save_detections(session, [det(minutes=60 * 30)], incident_window=timedelta(hours=24))
    assert later.incident_id != first.incident_id

    update_alert(session, later, status="Resolved")
    [again] = save_detections(session, [det(minutes=60 * 31)])
    assert again.incident_id not in (first.incident_id, later.incident_id)


def test_triage_lifecycle_sets_sla_timestamps(session):
    [alert] = save_detections(session, [det()], created_at=T0)
    update_alert(
        session, alert, status="Investigating", assignee="sam", now=T0 + timedelta(minutes=10)
    )
    assert alert.acknowledged_at == T0 + timedelta(minutes=10)
    assert alert.resolved_at is None
    assert alert.incident.status == "Investigating"

    update_alert(
        session, alert, status="Resolved", note="Blocked at firewall", now=T0 + timedelta(hours=2)
    )
    assert alert.resolved_at == T0 + timedelta(hours=2)
    assert alert.acknowledged_at == T0 + timedelta(minutes=10)  # unchanged
    assert alert.incident.status == "Resolved"
    bodies = [n.body for n in alert.notes]
    assert "Status: New -> Investigating" in bodies
    assert "Assigned to sam" in bodies
    assert "Blocked at firewall" in bodies

    update_alert(session, alert, status="Investigating")  # re-open
    assert alert.resolved_at is None


def test_false_positive_incident(session):
    [alert] = save_detections(session, [det()])
    update_alert(session, alert, status=AlertStatus.FALSE_POSITIVE.value)
    assert alert.incident.status == "False positive"


def test_unknown_status_is_rejected(session):
    [alert] = save_detections(session, [det()])
    with pytest.raises(ValueError):
        update_alert(session, alert, status="Done")


def test_sla_report_counts_breaches_including_open_alerts(session):
    a, b, _c = save_detections(
        session,
        [det(entity="1.1.1.1"), det(entity="2.2.2.2"), det(entity="3.3.3.3")],
        created_at=T0,
    )
    # high: ack target 30 min, resolve target 8 h
    update_alert(session, a, status="Investigating", now=T0 + timedelta(minutes=10))
    update_alert(session, a, status="Resolved", now=T0 + timedelta(hours=1))
    update_alert(session, b, status="Investigating", now=T0 + timedelta(minutes=50))  # late ack
    # c is never touched
    rows = {r.severity: r for r in sla_report(session, now=T0 + timedelta(hours=10))}
    high = rows["high"]
    assert high.alerts == 3
    assert high.open == 2
    assert high.mtta_minutes == 30.0  # (10 + 50) / 2
    assert high.mttr_minutes == 60.0
    assert high.ack_breaches == 2  # b (late) and c (never acknowledged)
    assert high.resolve_breaches == 2  # b and c are open past 8 h
    assert rows["low"].alerts == 0


def test_sla_report_on_empty_database(session):
    assert all(r.alerts == 0 for r in sla_report(session))
