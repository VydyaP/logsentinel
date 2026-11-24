"""Small REST API: health, metrics, ingest, detect, list/update alerts, incident reports.

Run locally with::

    uvicorn logsentinel.api:app --reload

Interactive docs are served at /docs. When the ``API_KEY`` environment variable
is set, every write endpoint requires an ``X-API-Key`` header with that value.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from logsentinel import __version__
from logsentinel.alerts import sla_report, update_alert
from logsentinel.config import get_settings
from logsentinel.db import get_sessionmaker
from logsentinel.ingest import ingest_lines
from logsentinel.models import Alert, AlertStatus, Incident
from logsentinel.pipeline import run_detection
from logsentinel.report import generate_report

MAX_UPLOAD_BYTES = 20 * 1024 * 1024

app = FastAPI(
    title="LogSentinel API",
    version=__version__,
    description="Ingest logs, run detections and triage alerts.",
)


def get_db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    """Reject write requests without the right key, if a key is configured."""
    expected = get_settings().api_key
    if expected and not (x_api_key and secrets.compare_digest(x_api_key, expected)):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")


DB = Annotated[Session, Depends(get_db)]
WriteAccess = Depends(require_api_key)


# --------------------------------------------------------------------------- schemas


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    author: str
    body: str
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_id: str
    rule_name: str
    severity: str
    status: str
    assignee: str | None
    entity: str
    entity_type: str
    description: str
    mitre_technique: str | None
    mitre_name: str | None
    mitre_tactic: str | None
    event_count: int
    first_event_at: datetime
    last_event_at: datetime
    created_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    score: float | None
    incident_id: int | None


class AlertDetail(AlertOut):
    raw_events: list[str]
    notes: list[NoteOut]
    details: dict[str, Any]


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assignee: str | None = None
    note: str | None = None
    author: str = "api"


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    entity: str
    entity_type: str
    severity: str
    status: str
    first_seen: datetime
    last_seen: datetime
    external_ref: str | None
    ticket_provider: str | None = None
    ticket_number: str | None = None
    ticket_url: str | None = None
    ticket_state: str | None = None
    alert_count: int


def _alert_detail(alert: Alert) -> AlertDetail:
    base = AlertOut.model_validate(alert).model_dump()
    return AlertDetail(
        **base,
        raw_events=[e.raw for e in alert.events],
        notes=[NoteOut.model_validate(n) for n in alert.notes],
        details=alert.details or {},
    )


# --------------------------------------------------------------------------- endpoints


@app.get("/health")
def health(db: DB) -> dict[str, str]:
    """Liveness + database check (used by Docker health checks and uptime monitors)."""
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ok", "version": __version__}


@app.get("/metrics")
def metrics(db: DB) -> dict[str, Any]:
    """Counts by status and severity, open incidents, and SLA figures per severity."""
    by_status = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    by_severity = dict(
        db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all()
    )
    closed = [s.value for s in AlertStatus if s.is_closed]
    open_incidents = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.status.not_in(closed))
    )
    return {
        "alerts_by_status": by_status,
        "alerts_by_severity": by_severity,
        "open_incidents": open_incidents,
        "sla": [vars(row) for row in sla_report(db)],
    }


@app.post("/ingest", dependencies=[WriteAccess])
async def ingest(
    db: DB,
    file: Annotated[UploadFile, File(description="auth.log or access.log")],
    log_type: Annotated[str, Form(pattern="^(auto|ssh|web)$")] = "auto",
    detect: Annotated[bool, Form()] = True,
) -> dict[str, Any]:
    """Upload a log file; events are stored and (by default) detection runs straight away."""
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File larger than 20 MB")
    lines = content.decode("utf-8", errors="replace").splitlines()
    stats = ingest_lines(db, lines, log_type, source_file=file.filename)
    if stats.log_type is None:
        raise HTTPException(status_code=422, detail="Could not recognise the log format")
    result: dict[str, Any] = {
        "log_type": stats.log_type,
        "parsed": stats.parsed,
        "inserted": stats.inserted,
        "duplicates": stats.duplicates,
        "skipped_lines": stats.skipped_lines,
    }
    if detect:
        run = run_detection(db)
        result["new_alerts"] = [a.id for a in run.new_alerts]
    return result


@app.post("/detect", dependencies=[WriteAccess])
def detect(db: DB, use_anomaly: bool = True) -> dict[str, Any]:
    run = run_detection(db, use_anomaly=use_anomaly)
    return {
        "events_scanned": run.events_scanned,
        "detections": run.detections,
        "new_alerts": [a.id for a in run.new_alerts],
    }


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    db: DB,
    status: AlertStatus | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Alert]:
    query = select(Alert).order_by(Alert.first_event_at.desc()).limit(limit).offset(offset)
    if status:
        query = query.where(Alert.status == status.value)
    if severity:
        query = query.where(Alert.severity == severity.lower())
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
    return list(db.scalars(query))


@app.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, db: DB) -> AlertDetail:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_detail(alert)


@app.patch("/alerts/{alert_id}", response_model=AlertDetail, dependencies=[WriteAccess])
def patch_alert(alert_id: int, body: AlertUpdate, db: DB) -> AlertDetail:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    update_alert(
        db,
        alert,
        status=body.status.value if body.status else None,
        assignee=body.assignee,
        note=body.note,
        author=body.author,
    )
    return _alert_detail(alert)


@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(db: DB, limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[IncidentOut]:
    incidents = db.scalars(select(Incident).order_by(Incident.last_seen.desc()).limit(limit))
    return [
        IncidentOut.model_validate({**i.__dict__, "alert_count": len(i.alerts)}) for i in incidents
    ]


@app.get("/incidents/{incident_id}/report", response_model=None)
def incident_report(incident_id: int, db: DB, format: str = "md") -> Response:
    """Download the incident report as Markdown (``format=md``) or PDF (``format=pdf``)."""
    try:
        md_text, pdf_bytes, _ = generate_report(db, incident_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    name = f"INC-{incident_id:05d}"
    if format == "pdf":
        return Response(
            pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'},
        )
    return PlainTextResponse(md_text, media_type="text/markdown")
