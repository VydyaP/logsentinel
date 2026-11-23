from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from logsentinel.api import app, get_db

ROOT = Path(__file__).resolve().parents[1]
AUTH = (ROOT / "data/samples/auth.log").read_text().splitlines()[:600]
FAILS = [
    f"2026-11-20T03:14:{i:02d}+00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    for i in range(15)
]


@pytest.fixture
def client(engine, monkeypatch):
    def override():
        with Session(engine) as s:
            yield s
            s.commit()

    app.dependency_overrides[get_db] = override
    monkeypatch.delenv("API_KEY", raising=False)
    yield TestClient(app)
    app.dependency_overrides.clear()


def upload(client, lines, **headers):
    files = {"file": ("auth.log", "\n".join(lines).encode(), "text/plain")}
    return client.post("/ingest", files=files, data={"log_type": "auto"}, headers=headers)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_ingest_detect_list_update_report(client):
    resp = upload(client, AUTH + FAILS)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["log_type"] == "ssh"
    assert body["inserted"] > 0
    assert body["new_alerts"]

    alerts = client.get("/alerts", params={"rule_id": "SSH-001"}).json()
    assert alerts
    alert_id = alerts[0]["id"]

    detail = client.get(f"/alerts/{alert_id}").json()
    assert detail["raw_events"]
    assert detail["status"] == "New"

    patched = client.patch(
        f"/alerts/{alert_id}",
        json={"status": "Investigating", "assignee": "sam", "note": "looking"},
    ).json()
    assert patched["status"] == "Investigating"
    assert patched["acknowledged_at"] is not None
    assert any(n["body"] == "looking" for n in patched["notes"])

    metrics = client.get("/metrics").json()
    assert metrics["alerts_by_status"]["Investigating"] == 1
    assert len(metrics["sla"]) == 4

    incidents = client.get("/incidents").json()
    assert incidents and incidents[0]["alert_count"] >= 1
    md = client.get(f"/incidents/{detail['incident_id']}/report")
    assert md.status_code == 200 and "Incident Report" in md.text
    pdf = client.get(f"/incidents/{detail['incident_id']}/report", params={"format": "pdf"})
    assert pdf.content.startswith(b"%PDF")


def test_reingest_reports_duplicates(client):
    upload(client, FAILS)
    body = upload(client, FAILS).json()
    assert body["inserted"] == 0 and body["duplicates"] == 15


def test_validation_and_not_found(client):
    assert client.get("/alerts/12345").status_code == 404
    assert client.get("/incidents/12345/report").status_code == 404
    assert upload(client, ["not a log"]).status_code == 422
    resp = client.patch("/alerts/1", json={"status": "Done"})
    assert resp.status_code == 422


def test_api_key_protects_writes(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "s3cret")
    assert upload(client, FAILS).status_code == 401
    assert upload(client, FAILS, **{"X-API-Key": "wrong"}).status_code == 401
    assert upload(client, FAILS, **{"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/alerts").status_code == 200  # reads stay open
