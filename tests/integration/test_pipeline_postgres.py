"""End-to-end pipeline against a real PostgreSQL database.

Skipped unless DATABASE_URL points at PostgreSQL (CI provides one as a service).
Runs the real Alembic migrations, so it also proves the schema is correct.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select, text

from logsentinel.config import PROJECT_ROOT, normalize_db_url
from logsentinel.db import make_engine
from logsentinel.ingest import ingest_file
from logsentinel.models import Alert, Event, Incident
from logsentinel.pipeline import run_detection
from logsentinel.report import generate_report
from simulator.generate import generate

DB_URL = normalize_db_url(os.environ.get("DATABASE_URL", ""))
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DB_URL.startswith("postgresql"), reason="needs PostgreSQL DATABASE_URL"),
]


@pytest.fixture(scope="module")
def pg_engine():
    from alembic import command
    from alembic.config import Config

    engine = make_engine(DB_URL)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    command.upgrade(cfg, "head")
    return engine


def test_full_pipeline_on_postgres(pg_engine, tmp_path: Path):
    from sqlalchemy.orm import Session

    generate(tmp_path, days=2, seed=7, start=datetime(2026, 11, 16, tzinfo=UTC))
    with Session(pg_engine) as session:
        for name in ("auth.log", "access.log"):
            ingest_file(session, tmp_path / name)
        session.commit()
        events = session.scalar(select(func.count()).select_from(Event))
        assert events > 15000

        # Re-ingesting uses ON CONFLICT DO NOTHING: no duplicates.
        assert ingest_file(session, tmp_path / "auth.log").inserted == 0

        run = run_detection(session, send_notifications=False)
        session.commit()
        rules_fired = {a.rule_id for a in run.new_alerts}
        assert {"SSH-001", "SSH-002", "SSH-003", "SSH-004", "WEB-001", "WEB-002",
                "WEB-003", "WEB-004", "WEB-005"} <= rules_fired  # fmt: skip

        # Running detection again creates nothing new.
        assert run_detection(session, send_notifications=False).new_alerts == []

        alert = session.scalars(select(Alert).where(Alert.rule_id == "SSH-003")).first()
        assert alert is not None and alert.events
        assert alert.first_event_at.tzinfo is not None  # timestamptz round-trip
        incident = session.get(Incident, alert.incident_id)
        assert incident is not None and incident.external_ref == f"LOCAL-{incident.id}"

        md, pdf, _ = generate_report(session, incident.id)
        assert "T1078" in md and pdf.startswith(b"%PDF")
