"""LIVE test against a real ServiceNow instance. Skipped unless credentials exist.

Never runs in CI (there are no ServiceNow secrets there). To run it locally,
put SERVICENOW_INSTANCE_URL / SERVICENOW_USERNAME / SERVICENOW_PASSWORD in .env
(or the environment) and run:

    pytest tests/live -m servicenow_live -v

It creates ONE test incident, proves the duplicate check and work notes work,
reads the state back, then cancels the incident so it does not clutter the queue.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from logsentinel.config import PROJECT_ROOT
from logsentinel.ingest import ingest_lines
from logsentinel.models import Incident
from logsentinel.pipeline import run_detection
from logsentinel.servicenow import ServiceNowProvider
from logsentinel.ticketing import NoOpTicketingProvider, correlation_id

KEYS = ("SERVICENOW_INSTANCE_URL", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD")


def _read_credentials() -> dict[str, str]:
    """Environment first, then .env. Read at import, before conftest clears the env."""
    values = {k: os.environ.get(k, "") for k in KEYS}
    env_file = PROJECT_ROOT / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() in KEYS and not values[key.strip()]:
                values[key.strip()] = value.strip().strip("\"'")
    return values


CREDS = _read_credentials()
pytestmark = [
    pytest.mark.servicenow_live,
    pytest.mark.skipif(not all(CREDS.values()), reason="no ServiceNow credentials (live test)"),
]


@pytest.fixture
def live_provider():
    provider = ServiceNowProvider(
        CREDS["SERVICENOW_INSTANCE_URL"],
        CREDS["SERVICENOW_USERNAME"],
        CREDS["SERVICENOW_PASSWORD"],
    )
    yield provider
    provider.close()


def test_live_create_dedupe_worknote_status(session, live_provider):
    now = datetime.now(UTC).replace(microsecond=0)
    lines = [
        f"{(now - timedelta(seconds=60 - i * 3)).isoformat()} live-test sshd[1]: "
        f"Failed password for root from 192.0.2.250 port {40000 + i} ssh2"
        for i in range(12)
    ]
    ingest_lines(session, lines, "ssh", source_file="live-test.log")
    run_detection(
        session, use_anomaly=False, provider=NoOpTicketingProvider(), send_notifications=False
    )
    incident = session.query(Incident).one()
    incident.title = f"[TEST] {incident.title}"

    ref = live_provider.create_incident(incident)
    assert ref.number and ref.number.startswith("INC")
    assert ref.state == "New"

    # Same correlation id -> same ticket, no duplicate.
    again = live_provider.create_incident(incident)
    assert again.ticket_id == ref.ticket_id
    assert live_provider.find_by_correlation_id(correlation_id(incident)) is not None

    incident.external_ref = ref.ticket_id
    live_provider.update_incident(incident, comment="LogSentinel live test: work note")
    statuses = live_provider.get_statuses([ref.ticket_id])
    assert statuses[ref.ticket_id].number == ref.number

    # Clean up: cancel the test ticket.
    live_provider._request(
        "PATCH",
        f"/api/now/table/incident/{ref.ticket_id}",
        json={"state": "8", "work_notes": "Automated LogSentinel live test - canceling."},
    )
    assert live_provider.get_status(ref.ticket_id) == "Canceled"
