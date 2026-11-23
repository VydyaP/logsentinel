"""Extension point for pushing incidents to an IT service management tool.

LogSentinel only calls the three methods of :class:`TicketingProvider`. To add
ServiceNow (or Jira, Freshservice, ...) later, write a class with those three
methods - for ServiceNow they map to the Table API on ``/api/now/table/incident``
(POST to create, PATCH to update, GET to read ``state``) - and return it from
:func:`get_provider`. Nothing else in the code base has to change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from logsentinel.models import Incident

log = logging.getLogger(__name__)


@dataclass
class TicketRef:
    """What the external system gave back: its ticket id and a link for humans."""

    ticket_id: str
    url: str | None = None


@runtime_checkable
class TicketingProvider(Protocol):
    """Interface every ticketing integration implements."""

    name: str

    def create_incident(self, incident: Incident) -> TicketRef:
        """Open a ticket for a new incident and return its reference."""
        ...

    def update_incident(self, incident: Incident, comment: str | None = None) -> None:
        """Push status/severity changes (and optionally a work note) to the ticket."""
        ...

    def get_status(self, ticket_id: str) -> str:
        """Return the ticket's current state in the external system."""
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


def get_provider(name: str = "noop") -> TicketingProvider:
    """Return the configured provider. Only "noop" exists today."""
    providers: dict[str, type] = {"noop": NoOpTicketingProvider}
    if name not in providers:
        raise ValueError(f"Unknown ticketing provider {name!r}; available: {sorted(providers)}")
    provider: TicketingProvider = providers[name]()
    return provider
