from datetime import timedelta

import httpx
import pytest

from conftest import T0
from logsentinel.alerts import save_detections, update_alert
from logsentinel.config import Settings
from logsentinel.detection.base import Detection
from logsentinel.ingest import ingest_lines
from logsentinel.models import Event
from logsentinel.notify import format_text, notify, send_slack, should_notify
from logsentinel.report import generate_report, render_markdown
from logsentinel.ticketing import NoOpTicketingProvider, TicketingProvider, get_provider

LINES = [
    f"2026-11-20T03:14:{i:02d}+00:00 bastion sshd[1]: Failed password for deploy from 203.0.113.5 port 1 ssh2"
    for i in range(6)
] + [
    "2026-11-20T03:15:00+00:00 bastion sshd[1]: Accepted password for deploy from 203.0.113.5 port 1 ssh2"
]


@pytest.fixture
def incident_alert(session):
    ingest_lines(session, LINES, source_file="auth.log")
    ids = [e.id for e in session.query(Event).order_by(Event.ts)]
    detection = Detection(
        rule_id="SSH-003",
        rule_name="Successful SSH login after repeated failures",
        severity="critical",
        entity="203.0.113.5",
        entity_type="ip",
        description="203.0.113.5 logged in as 'deploy' after 6 failed attempts",
        first_ts=T0,
        last_ts=T0 + timedelta(minutes=1),
        event_ids=ids,
        event_count=len(ids),
        mitre_technique="T1078",
        mitre_name="Valid Accounts",
        mitre_tactic="Initial Access",
    )
    [alert] = save_detections(session, [detection])
    update_alert(session, alert, note="Called the deploy owner", author="sam")
    return alert


def test_markdown_report_has_all_sections(session, incident_alert):
    md = render_markdown(incident_alert.incident)
    for heading in ["Summary", "Timeline", "Affected assets", "Indicators of compromise",
                    "MITRE ATT&CK mapping", "Recommended actions", "Evidence", "Analyst notes"]:  # fmt: skip
        assert heading in md
    assert "T1078" in md
    assert "At least one login succeeded" in md and "deploy" in md
    assert "bastion" in md
    assert "Called the deploy owner" in md
    assert "Treat the account as compromised" in md  # response step from the YAML rule


def test_pdf_and_files_are_written(session, incident_alert, tmp_path):
    md, pdf, paths = generate_report(session, incident_alert.incident_id, tmp_path)
    assert pdf.startswith(b"%PDF")
    assert [p.suffix for p in paths] == [".md", ".pdf"]
    assert paths[0].read_text() == md


def test_report_for_missing_incident(session):
    with pytest.raises(LookupError):
        generate_report(session, 999)


# --------------------------------------------------------------------------- notifications


def test_notify_is_a_no_op_without_configuration(incident_alert):
    assert notify([incident_alert], Settings(slack_webhook_url="", smtp_host="")) == 0


def test_severity_threshold(incident_alert):
    assert should_notify(incident_alert, Settings(notify_min_severity="high"))
    incident_alert.severity = "medium"
    assert not should_notify(incident_alert, Settings(notify_min_severity="high"))
    assert should_notify(incident_alert, Settings(notify_min_severity="low"))


def test_slack_payload(incident_alert):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    send_slack(incident_alert, "https://hooks.slack.test/abc", client=client)
    assert seen["url"] == "https://hooks.slack.test/abc"
    assert "SSH-003" in seen["body"] and "203.0.113.5" in seen["body"]


def test_failed_notification_does_not_raise(incident_alert, monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr("logsentinel.notify.send_slack", boom)
    assert notify([incident_alert], Settings(slack_webhook_url="https://x.test")) == 0


def test_format_text_mentions_mitre(incident_alert):
    text = format_text(incident_alert)
    assert "T1078 Valid Accounts" in text
    assert "[CRITICAL]" in text


# --------------------------------------------------------------------------- ticketing


def test_noop_provider_implements_interface(incident_alert):
    provider = get_provider("noop")
    assert isinstance(provider, TicketingProvider)
    assert isinstance(provider, NoOpTicketingProvider)
    ref = provider.create_incident(incident_alert.incident)
    assert ref.ticket_id == f"LOCAL-{incident_alert.incident_id}"
    provider.update_incident(incident_alert.incident, "note")
    assert provider.get_status(ref.ticket_id) == "unknown"
    assert provider.get_statuses([ref.ticket_id]) == {}
    with pytest.raises(ValueError):
        get_provider("jira")
