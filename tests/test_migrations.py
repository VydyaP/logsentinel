"""db.migrate(): fresh databases, legacy create_all databases and Alembic-managed ones."""

from __future__ import annotations

import sqlalchemy as sa

from logsentinel.db import make_engine, migrate

TICKET_COLUMNS = {"ticket_provider", "ticket_number", "ticket_url", "ticket_state"}


def columns(engine, table="incidents"):
    return {c["name"] for c in sa.inspect(engine).get_columns(table)}


def version(engine):
    with engine.connect() as conn:
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def test_fresh_database_gets_full_schema(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    migrate(engine)
    assert columns(engine) >= TICKET_COLUMNS
    assert version(engine) == "0002"
    migrate(engine)  # idempotent


def test_legacy_create_all_database_is_upgraded_in_place(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:  # the 0.1 schema, as create_all made it, with data
        conn.execute(
            sa.text(
                "CREATE TABLE incidents (id INTEGER PRIMARY KEY, entity VARCHAR(255), "
                "entity_type VARCHAR(32), title VARCHAR(255), severity VARCHAR(16), "
                "status VARCHAR(32), first_seen DATETIME, last_seen DATETIME, "
                "created_at DATETIME, updated_at DATETIME, external_ref VARCHAR(255))"
            )
        )
        conn.execute(sa.text("INSERT INTO incidents (id, title) VALUES (1, 'old')"))
    migrate(engine)
    assert columns(engine) >= TICKET_COLUMNS
    assert version(engine) == "0002"
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT title FROM incidents")).scalar() == "old"


def test_alembic_database_at_0001_is_upgraded(tmp_path):
    from alembic import command
    from alembic.config import Config

    from logsentinel.config import PROJECT_ROOT

    engine = make_engine(f"sqlite:///{tmp_path / 'v1.db'}")
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0001")
    assert not TICKET_COLUMNS & columns(engine)
    migrate(engine)
    assert columns(engine) >= TICKET_COLUMNS
