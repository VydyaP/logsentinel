"""Ticket lifecycle glue: open/update tickets after detection, and sync status back.

* :func:`push_tickets` runs after each detection pass. A High/Critical incident
  without a ticket gets one; an incident that already has a ticket gets a work
  note listing the new alerts. A failing ticketing call is logged and never
  breaks detection: the next run retries, and the correlation id stops the retry
  from opening a duplicate.
* :func:`sync_ticket_status` is the scheduled job (``logsentinel sync-tickets``).
  It reads every open ticket from the provider and, when one was resolved,
  closed or canceled there, closes the matching LogSentinel alerts with a note.

Status flows one way, ITSM -> LogSentinel: the ticket is where the incident is
worked, so it is the source of truth for "done".
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from logsentinel.alerts import update_alert
from logsentinel.config import Settings, get_settings
from logsentinel.models import Alert, AlertStatus, Incident, utcnow
from logsentinel.ticketing import TicketingProvider, TicketRef, should_ticket, work_note

log = logging.getLogger(__name__)

SYNC_AUTHOR = "servicenow-sync"
FINAL_TICKET_STATES = {"Closed", "Canceled"}
CREATE_FAILED = "Create failed"


@dataclass
class PushResult:
    created: list[int] = field(default_factory=list)  # incident ids that got a ticket
    updated: list[int] = field(default_factory=list)
    failed: list[int] = field(default_factory=list)


@dataclass
class SyncResult:
    checked: int = 0
    closed_incidents: list[int] = field(default_factory=list)
    closed_alerts: int = 0
    retried: list[int] = field(default_factory=list)  # failed creates that now have a ticket
    error: str | None = None


def apply_ref(incident: Incident, ref: TicketRef, provider_name: str) -> None:
    incident.external_ref = ref.ticket_id
    incident.ticket_provider = provider_name
    incident.ticket_number = ref.number
    incident.ticket_url = ref.url
    incident.ticket_state = ref.state
    incident.ticket_synced_at = utcnow()


def push_tickets(
    new_alerts: list[Alert],
    provider: TicketingProvider,
    settings: Settings | None = None,
) -> PushResult:
    """Open or update tickets for the incidents touched by ``new_alerts``."""
    settings = settings or get_settings()
    by_incident: dict[int, list[Alert]] = defaultdict(list)
    incidents: dict[int, Incident] = {}
    for alert in new_alerts:
        if alert.incident is not None:
            by_incident[alert.incident.id].append(alert)
            incidents[alert.incident.id] = alert.incident
    result = PushResult()
    for incident_id in sorted(incidents):
        incident = incidents[incident_id]
        try:
            if incident.external_ref is None:
                if should_ticket(incident, settings):
                    apply_ref(incident, provider.create_incident(incident), provider.name)
                    result.created.append(incident_id)
            elif incident.ticket_provider == provider.name:
                provider.update_incident(incident, comment=work_note(by_incident[incident_id]))
                result.updated.append(incident_id)
        except Exception as exc:
            # Never let the ITSM tool break detection. A failed create is marked so the
            # sync job retries it; the correlation id makes that retry duplicate-safe.
            log.error("ticketing (%s) failed for incident %s: %s", provider.name, incident_id, exc)
            if incident.external_ref is None:
                incident.ticket_provider = provider.name
                incident.ticket_state = CREATE_FAILED
            result.failed.append(incident_id)
    return result


def retry_failed_creates(session: Session, provider: TicketingProvider) -> list[int]:
    """Try again to open tickets whose creation failed earlier. Returns incident ids."""
    pending = session.scalars(
        select(Incident)
        .where(Incident.external_ref.is_(None))
        .where(Incident.ticket_provider == provider.name)
        .where(Incident.ticket_state == CREATE_FAILED)
        .where(Incident.status.not_in([s.value for s in AlertStatus if s.is_closed]))
    ).all()
    created = []
    for incident in pending:
        try:
            apply_ref(incident, provider.create_incident(incident), provider.name)
            created.append(incident.id)
        except Exception as exc:
            log.error("retrying ticket for incident %s failed: %s", incident.id, exc)
    return created


def sync_ticket_status(session: Session, provider: TicketingProvider) -> SyncResult:
    """Copy ticket state from the provider; close local alerts whose ticket is done.

    Also retries ticket creation for incidents whose first attempt failed.
    """
    retried = retry_failed_creates(session, provider)
    incidents = session.scalars(
        select(Incident)
        .where(Incident.external_ref.is_not(None))
        .where(Incident.ticket_provider == provider.name)
        .where(
            or_(
                Incident.ticket_state.is_(None),
                Incident.ticket_state.not_in(FINAL_TICKET_STATES),
            )
        )
    ).all()
    result = SyncResult(checked=len(incidents), retried=retried)
    if not incidents:
        return result
    try:
        statuses = provider.get_statuses([i.external_ref for i in incidents if i.external_ref])
    except Exception as exc:
        log.error("ticket status sync (%s) failed: %s", provider.name, exc)
        result.error = str(exc)
        return result

    now = utcnow()
    for incident in incidents:
        status = statuses.get(incident.external_ref or "")
        if status is None:
            continue  # deleted in the ITSM tool, or not visible to this user
        incident.ticket_state = status.state
        incident.ticket_number = status.number or incident.ticket_number
        incident.ticket_synced_at = now
        if not status.closed or AlertStatus(incident.status).is_closed:
            continue
        target = AlertStatus.FALSE_POSITIVE if status.canceled else AlertStatus.RESOLVED
        note = (
            f"Ticket {status.number or incident.external_ref} is {status.state} in {provider.name}"
        )
        if status.resolution:
            note += f": {status.resolution}"
        for alert in incident.alerts:
            if not AlertStatus(alert.status).is_closed:
                update_alert(session, alert, status=target.value, note=note, author=SYNC_AUTHOR)
                result.closed_alerts += 1
        result.closed_incidents.append(incident.id)
    session.flush()
    log.info(
        "ticket sync: checked %d, closed %d incident(s)",
        result.checked,
        len(result.closed_incidents),
    )
    return result
