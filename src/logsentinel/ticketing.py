"""Pushing incidents to an IT service management (ITSM) tool.

LogSentinel talks to every ticketing system through :class:`TicketingProvider`.
Two implementations ship:

* :class:`NoOpTicketingProvider` (default): nothing leaves the machine. Used in
  CI and by anyone who clones the repo without ServiceNow credentials.
* :class:`logsentinel.servicenow.ServiceNowProvider`: the ServiceNow REST Table API.

Pick one with ``TICKETING_PROVIDER=noop|servicenow``. Adding Jira, Freshservice
or PagerDuty means writing one class with these methods and registering it in
:func:`get_provider`; the pipeline, sync job and dashboard do not change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from logsentinel.config import Settings, get_settings
from logsentinel.models import Alert, Incident, Severity

log = logging.getLogger(__name__)

# How many raw log lines go into a ticket description.
SAMPLE_LINES = 5


class TicketingError(Exception):
    """A ticketing call failed. The message never contains credentials."""


class TicketingAuthError(TicketingError):
    """Credentials rejected (401) or the user lacks the needed roles (403)."""


@dataclass
class TicketRef:
    """What the external system gave back: its ticket id and a link for humans."""

    ticket_id: str  # stable machine id (ServiceNow: sys_id)
    url: str | None = None
    number: str | None = None  # human id (ServiceNow: INC0010001)
    state: str | None = None  # e.g. "New"


@dataclass
class TicketStatus:
    """A ticket's lifecycle state as read back from the external system."""

    ticket_id: str
    state: str  # provider label, e.g. "Resolved"
    number: str | None = None
    closed: bool = False  # resolved/closed/canceled: work on it has finished
    canceled: bool = False  # closed without fixing anything (maps to "False positive")
    resolution: str | None = None  # close code + notes, for the audit trail


@runtime_checkable
class TicketingProvider(Protocol):
    """Interface every ticketing integration implements."""

    name: str

    def create_incident(self, incident: Incident) -> TicketRef:
        """Open a ticket for a new incident and return its reference.

        Must be idempotent: calling it twice for the same incident returns the
        same ticket instead of opening a second one.
        """
        ...

    def update_incident(self, incident: Incident, comment: str | None = None) -> None:
        """Push severity/title changes (and optionally a work note) to the ticket."""
        ...

    def get_status(self, ticket_id: str) -> str:
        """Return the ticket's current state in the external system."""
        ...

    def get_statuses(self, ticket_ids: list[str]) -> dict[str, TicketStatus]:
        """Read many tickets at once (used by the status sync job)."""
        ...


class NoOpTicketingProvider:
    """Default provider: records nothing externally, just logs what it would do."""

    name = "noop"

    def create_incident(self, incident: Incident) -> TicketRef:
        log.debug("noop ticketing: would create ticket for incident %s", incident.id)
        return TicketRef(ticket_id=f"LOCAL-{incident.id}")

    def update_incident(self, incident: Incident, comment: str | None = None) -> None:
        log.debug("noop ticketing: would update incident %s (%s)", incident.id, incident.status)

    def get_status(self, ticket_id: str) -> str:
        return "unknown"

    def get_statuses(self, ticket_ids: list[str]) -> dict[str, TicketStatus]:
        return {}


def get_provider(name: str | None = None, settings: Settings | None = None) -> TicketingProvider:
    """Return the configured provider (``TICKETING_PROVIDER``, default ``noop``).

    If ServiceNow is selected but its URL or credentials are missing, log a
    warning and fall back to ``noop`` so detection and the dashboard keep working.
    """
    settings = settings or get_settings()
    name = (name or settings.ticketing_provider or "noop").lower()
    if name == "noop":
        return NoOpTicketingProvider()
    if name == "servicenow":
        from logsentinel.servicenow import ServiceNowProvider

        missing = [
            var
            for var, value in (
                ("SERVICENOW_INSTANCE_URL", settings.servicenow_instance_url),
                ("SERVICENOW_USERNAME", settings.servicenow_username),
                ("SERVICENOW_PASSWORD", settings.servicenow_password),
            )
            if not value
        ]
        if missing:
            log.warning(
                "TICKETING_PROVIDER=servicenow but %s not set; using the noop provider",
                ", ".join(missing),
            )
            return NoOpTicketingProvider()
        return ServiceNowProvider.from_settings(settings)
    raise ValueError(f"Unknown ticketing provider {name!r}; available: ['noop', 'servicenow']")


# --------------------------------------------------------------------------- shared helpers


def should_ticket(incident: Incident, settings: Settings | None = None) -> bool:
    """True if the incident is severe enough to open an external ticket."""
    settings = settings or get_settings()
    try:
        minimum = Severity(settings.ticket_min_severity)
    except ValueError:
        minimum = Severity.HIGH
    return Severity(incident.severity).rank >= minimum.rank


def correlation_id(incident: Incident) -> str:
    """Stable id that ties a LogSentinel incident to exactly one external ticket.

    The creation timestamp is included so that resetting the database (which
    restarts incident ids at 1) can never attach to an old ticket from a
    previous run. It never changes for the life of the incident.
    """
    return f"logsentinel-INC-{incident.id:05d}-{incident.created_at:%Y%m%dT%H%M%SZ}"


def incident_link(incident: Incident, dashboard_url: str) -> str:
    return f"{dashboard_url}/?page=Incidents&incident={incident.id}"


def describe_incident(incident: Incident, dashboard_url: str) -> str:
    """Plain-text ticket body: what fired, from where, when, and evidence."""
    alerts = sorted(incident.alerts, key=lambda a: a.first_event_at)
    lines = [
        f"LogSentinel incident INC-{incident.id:05d}: {incident.title}",
        "",
        f"Severity: {incident.severity}",
        f"Source {incident.entity_type}: {incident.entity}",
        f"First seen: {incident.first_seen:%Y-%m-%d %H:%M:%S} UTC",
        f"Last seen:  {incident.last_seen:%Y-%m-%d %H:%M:%S} UTC",
        f"Alerts: {len(alerts)}",
        "",
        "Detections:",
    ]
    lines += [f"- {alert_line(a)}" for a in alerts]
    samples = [e.raw for a in alerts for e in a.events][:SAMPLE_LINES]
    if samples:
        lines += ["", f"Sample log lines (first {len(samples)}):"]
        lines += [f"  {raw[:300]}" for raw in samples]
    lines += [
        "",
        f"Open in LogSentinel: {incident_link(incident, dashboard_url)}",
        f"Correlation ID: {correlation_id(incident)}",
    ]
    return "\n".join(lines)


def alert_line(alert: Alert) -> str:
    mitre = f"MITRE {alert.mitre_technique} {alert.mitre_name}" if alert.mitre_technique else ""
    return (
        f"{alert.rule_id} {alert.rule_name} [{alert.severity}] {mitre}".rstrip()
        + f": {alert.description} ({alert.event_count} events, "
        f"{alert.first_event_at:%H:%M:%S}-{alert.last_event_at:%H:%M:%S} UTC)"
    )


def work_note(new_alerts: list[Alert]) -> str:
    """Work note added to an existing ticket when more alerts join the incident."""
    lines = [f"LogSentinel: {len(new_alerts)} new related alert(s):"]
    lines += [f"- {alert_line(a)}" for a in sorted(new_alerts, key=lambda a: a.first_event_at)]
    return "\n".join(lines)
