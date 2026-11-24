"""ServiceNowProvider and the ticket lifecycle, with every HTTP call mocked (respx).

Nothing here touches a real instance; see tests/live/ for that.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from logsentinel.config import Settings
from logsentinel.ingest import ingest_lines
from logsentinel.models import Alert, AlertStatus, Incident
from logsentinel.pipeline import run_detection
from logsentinel.servicenow import (
    SEVERITY_TO_IMPACT_URGENCY,
    ServiceNowAuthError,
    ServiceNowError,
    ServiceNowProvider,
    ServiceNowUnavailableError,
)
from logsentinel.ticket_sync import CREATE_FAILED, push_tickets, sync_ticket_status
from logsentinel.ticketing import (
    NoOpTicketingProvider,
    TicketingProvider,
    correlation_id,
    get_provider,
)

BASE = "https://dev00000.service-now.com"
TABLE = f"{BASE}/api/now/table/incident"
SECRET = "s3cret-Passw0rd!"
SYS_ID = "a" * 32
NOW = datetime.now(UTC).replace(microsecond=0)


def record(state: str = "1", sys_id: str = SYS_ID, number: str = "INC0010001", **extra):
    return {"sys_id": sys_id, "number": number, "state": state, **extra}


def ok(result, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json={"result": result})


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def provider(sleeps):
    p = ServiceNowProvider(
        BASE,
        "logsentinel.integration",
        SECRET,
        dashboard_url="https://dash.example",
        max_retries=3,
        backoff_base=0.5,
        sleep=sleeps.append,
    )
    yield p
    p.close()


def brute_force(ip: str = "203.0.113.77", attempts: int = 12, success: bool = False, start=None):
    start = start or NOW - timedelta(minutes=5)
    lines = [
        f"{(start + timedelta(seconds=i * 3)).isoformat()} bastion sshd[1]: "
        f"Failed password for root from {ip} port {40000 + i} ssh2"
        for i in range(attempts)
    ]
    if success:
        lines.append(
            f"{(start + timedelta(seconds=attempts * 3 + 2)).isoformat()} bastion sshd[1]: "
            f"Accepted password for root from {ip} port 40999 ssh2"
        )
    return lines


def detect(session, provider, lines, name="a.log"):
    ingest_lines(session, lines, "ssh", source_file=name)
    return run_detection(session, use_anomaly=False, provider=provider, send_notifications=False)


@pytest.fixture
def incident(session) -> Incident:
    """A critical incident (brute force + successful login) with real alerts and events."""
    detect(session, NoOpTicketingProvider(), brute_force(success=True))
    inc = session.query(Incident).one()
    inc.external_ref = None  # as if never ticketed
    inc.ticket_provider = None
    return inc


# --------------------------------------------------------------------------- create


def test_provider_implements_interface(provider):
    assert isinstance(provider, TicketingProvider)
    assert SECRET not in repr(provider)


@respx.mock
def test_create_incident_sends_mapped_fields(provider, incident):
    lookup = respx.get(TABLE).mock(return_value=ok([]))
    create = respx.post(TABLE).mock(return_value=ok(record(), 201))

    ref = provider.create_incident(incident)

    assert ref.ticket_id == SYS_ID and ref.number == "INC0010001" and ref.state == "New"
    assert ref.url == f"{BASE}/incident.do?sys_id={SYS_ID}"
    assert lookup.calls.last.request.url.params["sysparm_query"] == (
        f"correlation_id={correlation_id(incident)}"
    )
    request = create.calls.last.request
    assert request.headers["Authorization"].startswith("Basic ")
    body = json.loads(request.content)
    assert body["impact"] == "1" and body["urgency"] == "1"  # critical -> P1
    assert body["correlation_id"] == correlation_id(incident)
    assert body["correlation_display"] == "LogSentinel"
    assert body["category"] == "network"
    assert body["short_description"].startswith("[LogSentinel][CRITICAL]")
    desc = body["description"]
    for expected in ["SSH-001", "SSH-003", "T1110.001", "T1078", "203.0.113.77",
                     "First seen:", "Last seen:", "Failed password for root",
                     f"https://dash.example/?page=Incidents&incident={incident.id}"]:  # fmt: skip
        assert expected in desc


def test_severity_mapping_is_documented_priority():
    # Default ServiceNow priority lookup: (1,1)=P1, (2,1)=P2, (2,2)=P3, (3,3)=P5
    assert SEVERITY_TO_IMPACT_URGENCY == {
        "critical": (1, 1),
        "high": (2, 1),
        "medium": (2, 2),
        "low": (3, 3),
    }


def test_correlation_id_is_stable_and_unique_per_db_lifetime(incident):
    cid = correlation_id(incident)
    assert cid == correlation_id(incident)
    assert cid.startswith(f"logsentinel-INC-{incident.id:05d}-")
    assert len(cid) <= 100  # ServiceNow correlation_id column length


# --------------------------------------------------------------------------- dedupe


@respx.mock
def test_existing_ticket_with_same_correlation_id_is_reused(provider, incident):
    respx.get(TABLE).mock(return_value=ok([record(state="2", number="INC0010042")]))
    create = respx.post(TABLE)

    ref = provider.create_incident(incident)

    assert ref.number == "INC0010042" and ref.state == "In Progress"
    assert not create.called


@respx.mock
def test_pipeline_creates_exactly_one_ticket_then_adds_work_notes(session, provider):
    respx.get(TABLE).mock(return_value=ok([]))
    create = respx.post(TABLE).mock(return_value=ok(record(), 201))
    patch = respx.patch(f"{TABLE}/{SYS_ID}").mock(return_value=ok(record(state="2")))

    run = detect(session, provider, brute_force(), "1.log")
    assert [a.rule_id for a in run.new_alerts] == ["SSH-001"]
    assert create.call_count == 1
    incident = session.query(Incident).one()
    assert incident.external_ref == SYS_ID and incident.ticket_number == "INC0010001"
    assert incident.ticket_provider == "servicenow" and incident.ticket_url.endswith(SYS_ID)
    assert json.loads(create.calls.last.request.content)["impact"] == "2"  # high -> P2

    # Detection again over the same events: nothing new, no HTTP at all.
    assert detect(session, provider, brute_force(), "1.log").new_alerts == []
    assert create.call_count == 1 and not patch.called

    # The attacker gets in: new critical alert joins the incident -> work note, escalation.
    later = NOW - timedelta(minutes=2)
    detect(session, provider, brute_force(start=later, success=True), "2.log")
    assert create.call_count == 1
    assert patch.call_count == 1
    body = json.loads(patch.calls.last.request.content)
    assert "SSH-003" in body["work_notes"] and "new related alert" in body["work_notes"]
    assert body["impact"] == "1" and body["urgency"] == "1"


@respx.mock
def test_medium_incident_does_not_open_a_ticket(session, provider):
    create = respx.post(TABLE)
    lines = [
        f"{(NOW - timedelta(days=1)).replace(hour=18).isoformat()} bastion sshd[1]: "
        "Accepted password for alice from 198.51.100.9 port 1 ssh2"
    ]  # 23:30 IST: SSH-004 off-hours login, medium
    run = detect(session, provider, lines)
    assert [a.severity for a in run.new_alerts] == ["medium"]
    assert not create.called
    assert session.query(Incident).one().external_ref is None


def test_threshold_is_configurable(session, incident):
    settings = Settings(ticket_min_severity="critical")
    incident.severity = "high"
    calls = []

    class Recorder(NoOpTicketingProvider):
        def create_incident(self, inc):
            calls.append(inc.id)
            return super().create_incident(inc)

    push_tickets(incident.alerts, Recorder(), settings)
    assert calls == []


# --------------------------------------------------------------------------- work notes


@respx.mock
def test_update_incident_adds_work_note(provider, incident):
    incident.external_ref = SYS_ID
    route = respx.patch(f"{TABLE}/{SYS_ID}").mock(return_value=ok(record(state="2")))
    provider.update_incident(incident, comment="2 new related alerts")
    body = json.loads(route.calls.last.request.content)
    assert body["work_notes"] == "2 new related alerts"
    assert body["short_description"].startswith("[LogSentinel]")


def test_update_without_ticket_is_an_error(provider, incident):
    with pytest.raises(ServiceNowError):
        provider.update_incident(incident, "x")


# --------------------------------------------------------------------------- status sync


def ticketed(incident: Incident) -> Incident:
    incident.external_ref = SYS_ID
    incident.ticket_provider = "servicenow"
    incident.ticket_number = "INC0010001"
    incident.ticket_state = "New"
    return incident


@respx.mock
def test_sync_resolves_alerts_when_ticket_resolved(session, provider, incident):
    ticketed(incident)
    route = respx.get(TABLE).mock(
        return_value=ok(
            [record(state="6", close_code="Solved (Permanently)", close_notes="IP blocked")]
        )
    )

    result = sync_ticket_status(session, provider)

    assert route.calls.last.request.url.params["sysparm_query"] == f"sys_idIN{SYS_ID}"
    assert result.closed_incidents == [incident.id] and result.closed_alerts == 2
    assert incident.status == AlertStatus.RESOLVED.value
    assert incident.ticket_state == "Resolved" and incident.ticket_synced_at is not None
    for alert in incident.alerts:
        assert alert.status == "Resolved" and alert.resolved_at is not None
        note = alert.notes[-1]
        assert note.author == "servicenow-sync"
        assert "INC0010001 is Resolved" in note.body and "IP blocked" in note.body


@respx.mock
def test_sync_maps_canceled_to_false_positive(session, provider, incident):
    ticketed(incident)
    respx.get(TABLE).mock(return_value=ok([record(state="8")]))
    sync_ticket_status(session, provider)
    assert incident.status == AlertStatus.FALSE_POSITIVE.value


@respx.mock
def test_sync_updates_state_but_leaves_open_ticket_open(session, provider, incident):
    ticketed(incident)
    respx.get(TABLE).mock(return_value=ok([record(state="2")]))
    result = sync_ticket_status(session, provider)
    assert result.closed_incidents == []
    assert incident.ticket_state == "In Progress" and incident.status == "New"


@respx.mock
def test_closed_tickets_are_not_polled_again(session, provider, incident):
    ticketed(incident).ticket_state = "Closed"
    route = respx.get(TABLE)
    assert sync_ticket_status(session, provider).checked == 0
    assert not route.called


@respx.mock
def test_sync_error_is_reported_not_raised(session, provider, incident):
    ticketed(incident)
    respx.get(TABLE).mock(return_value=httpx.Response(401))
    result = sync_ticket_status(session, provider)
    assert result.error and "401" in result.error
    assert incident.status == "New"


@respx.mock
def test_get_statuses_batches_and_paginates(provider):
    ids = [f"{i:032x}" for i in range(120)]  # 3 batches of <= 50

    def handler(request):
        query = request.url.params["sysparm_query"]
        chunk = query.removeprefix("sys_idIN").split(",")
        offset = int(request.url.params["sysparm_offset"])
        limit = int(request.url.params["sysparm_limit"])
        return ok([record(sys_id=s, state="6") for s in chunk[offset : offset + limit]])

    route = respx.get(TABLE).mock(side_effect=handler)
    statuses = provider.get_statuses(ids)
    assert len(statuses) == 120 and all(s.closed for s in statuses.values())
    assert route.call_count == 3


@respx.mock
def test_pagination_follows_offset_until_short_page(provider):
    pages = {"0": [record(sys_id=f"{i:032x}") for i in range(100)], "100": [record()]}
    route = respx.get(TABLE).mock(side_effect=lambda r: ok(pages[r.url.params["sysparm_offset"]]))
    records = list(provider._paginate("active=true"))
    assert len(records) == 101 and route.call_count == 2


# --------------------------------------------------------------------------- HTTP robustness


@respx.mock
def test_retries_5xx_with_exponential_backoff(provider, sleeps):
    route = respx.get(f"{TABLE}/{SYS_ID}").mock(
        side_effect=[httpx.Response(503), httpx.Response(502), ok(record(state="6"))]
    )
    assert provider.get_status(SYS_ID) == "Resolved"
    assert route.call_count == 3
    assert len(sleeps) == 2
    assert 0.5 <= sleeps[0] <= 1.0 and 1.0 <= sleeps[1] <= 1.5  # base*2^n + jitter


@respx.mock
def test_429_honours_retry_after(provider, sleeps):
    respx.get(f"{TABLE}/{SYS_ID}").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), ok(record())]
    )
    assert provider.get_status(SYS_ID) == "New"
    assert sleeps == [7.0]


@respx.mock
def test_gives_up_after_max_retries(provider, sleeps):
    route = respx.get(f"{TABLE}/{SYS_ID}").mock(return_value=httpx.Response(500))
    with pytest.raises(ServiceNowError, match="500"):
        provider.get_status(SYS_ID)
    assert route.call_count == 4 and len(sleeps) == 3  # 1 try + 3 retries


@respx.mock
def test_post_is_not_retried_when_it_may_have_succeeded(provider, incident):
    respx.get(TABLE).mock(return_value=ok([]))
    create = respx.post(TABLE).mock(return_value=httpx.Response(504))
    with pytest.raises(ServiceNowError):
        provider.create_incident(incident)
    assert create.call_count == 1


@respx.mock
def test_post_is_retried_on_connect_error_and_429(provider, incident, sleeps):
    respx.get(TABLE).mock(return_value=ok([]))
    create = respx.post(TABLE).mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(429), ok(record(), 201)]
    )
    assert provider.create_incident(incident).number == "INC0010001"
    assert create.call_count == 3 and len(sleeps) == 2


@respx.mock
def test_read_timeout_is_retried_for_get(provider, sleeps):
    respx.get(f"{TABLE}/{SYS_ID}").mock(
        side_effect=[httpx.ReadTimeout("slow"), ok(record(state="7"))]
    )
    assert provider.get_status(SYS_ID) == "Closed"


@respx.mock
def test_401_raises_clear_auth_error_without_retry(provider, sleeps):
    route = respx.get(f"{TABLE}/{SYS_ID}").mock(
        return_value=httpx.Response(401, json={"error": {"message": "User Not Authenticated"}})
    )
    with pytest.raises(ServiceNowAuthError, match="SERVICENOW_USERNAME") as err:
        provider.get_status(SYS_ID)
    assert SECRET not in str(err.value)
    assert route.call_count == 1 and sleeps == []


@respx.mock
def test_403_names_the_missing_role(provider):
    respx.post(TABLE).mock(
        return_value=httpx.Response(
            403, json={"error": {"message": "Operation Failed", "detail": "ACL"}}
        )
    )
    respx.get(TABLE).mock(return_value=ok([]))
    with pytest.raises(ServiceNowAuthError, match="itil"):
        provider._request("POST", "/api/now/table/incident", json={})


@respx.mock
def test_hibernating_instance_is_detected(provider):
    respx.get(f"{TABLE}/{SYS_ID}").mock(
        return_value=httpx.Response(200, html="<html>Your instance is hibernating</html>")
    )
    with pytest.raises(ServiceNowUnavailableError, match="hibernating"):
        provider.get_status(SYS_ID)


@respx.mock
def test_every_call_is_logged_without_secrets(provider, caplog):
    caplog.set_level(logging.INFO, logger="logsentinel.servicenow")
    respx.get(f"{TABLE}/{SYS_ID}").mock(side_effect=[httpx.Response(503), ok(record())])
    provider.get_status(SYS_ID)
    calls = [r for r in caplog.records if r.getMessage().startswith("servicenow_call")]
    assert len(calls) == 2
    assert calls[0].servicenow["status"] == 503 and calls[0].levelno == logging.WARNING
    assert calls[1].servicenow == {
        "provider": "servicenow",
        "method": "GET",
        "path": f"/api/now/table/incident/{SYS_ID}",
        "status": 200,
        "attempt": 2,
        "duration_ms": calls[1].servicenow["duration_ms"],
    }
    text = caplog.text
    assert SECRET not in text and "Authorization" not in text and "Basic " not in text


def test_instance_url_must_be_https():
    with pytest.raises(ValueError):
        ServiceNowProvider("http://dev1.service-now.com", "u", "p")


# --------------------------------------------------------------------------- failure handling


@respx.mock
def test_failed_create_never_breaks_detection_and_is_retried_by_sync(session, provider):
    respx.get(TABLE).mock(return_value=ok([]))
    create = respx.post(TABLE).mock(
        side_effect=[httpx.Response(401), ok(record(number="INC0010077"), 201)]
    )

    run = detect(session, provider, brute_force())
    assert len(run.new_alerts) == 1  # detection still stored the alert
    incident = session.query(Incident).one()
    assert incident.external_ref is None and incident.ticket_state == CREATE_FAILED

    result = sync_ticket_status(session, provider)
    assert result.retried == [incident.id]
    assert incident.ticket_number == "INC0010077" and create.call_count == 2


# --------------------------------------------------------------------------- configuration


def test_get_provider_selects_servicenow_from_settings():
    settings = Settings(
        ticketing_provider="servicenow",
        servicenow_instance_url=BASE,
        servicenow_username="u",
        servicenow_password=SECRET,
    )
    provider = get_provider(settings=settings)
    assert isinstance(provider, ServiceNowProvider)
    provider.close()
    assert SECRET not in repr(settings)


def test_servicenow_without_credentials_falls_back_to_noop(caplog):
    provider = get_provider(settings=Settings(ticketing_provider="servicenow"))
    assert provider.name == "noop"
    assert "SERVICENOW_PASSWORD" in caplog.text


def test_default_provider_is_noop():
    assert get_provider().name == "noop"


def test_noop_pipeline_still_tickets_locally(session):
    detect(session, None, brute_force(success=True))
    incident = session.query(Incident).one()
    assert incident.external_ref == f"LOCAL-{incident.id}"
    assert incident.ticket_provider == "noop"
    assert session.query(Alert).count() == 2
