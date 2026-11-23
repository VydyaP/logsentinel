"""Database tables (SQLAlchemy 2.x ORM).

Four main tables:

* ``events``    - every parsed log line, normalised into one shape.
* ``alerts``    - one row per detection hit, with triage fields (status, assignee, SLA times).
* ``incidents`` - groups alerts from the same source (IP or user) so an analyst
                  works one case instead of fifty duplicate alerts.
* ``alert_notes`` - analyst notes and an audit trail of status changes.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Dialect,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    TypeDecorator,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """A timestamp that is always timezone-aware UTC in Python.

    PostgreSQL stores ``timestamptz`` natively; SQLite has no timezone support,
    so we convert to UTC on the way in and re-attach UTC on the way out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)


SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class AlertStatus(str, enum.Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False positive"

    @property
    def is_closed(self) -> bool:
        return self in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)


class Event(Base):
    """One normalised log line from any source."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)  # "ssh" or "web"
    host: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    # ssh: login_failed / login_success / invalid_user / other; web: http_request
    action: Mapped[str] = mapped_column(String(32), index=True)
    method: Mapped[str | None] = mapped_column(String(16))
    path: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    bytes_sent: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text)
    source_file: Mapped[str | None] = mapped_column(String(255))
    # sha256 of (source, file, line, occurrence) - makes re-ingesting a file idempotent.
    line_hash: Mapped[str] = mapped_column(String(64), unique=True)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


alert_events = Table(
    "alert_events",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base):
    """A group of related alerts from the same source entity."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(32))  # "ip" or "user"
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), default=AlertStatus.NEW.value, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    # Reference returned by an external ticketing system (e.g. a ServiceNow sys_id).
    external_ref: Mapped[str | None] = mapped_column(String(255))

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident")


class Alert(Base):
    """One detection hit plus its triage state."""

    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_severity", "status", "severity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Stable hash of (rule, entity, first event time): re-running detection never duplicates.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(32))
    mitre_name: Mapped[str | None] = mapped_column(String(255))
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    event_count: Mapped[int] = mapped_column(Integer)
    first_event_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    last_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    score: Mapped[float | None] = mapped_column(Float)  # anomaly score, if any
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Triage fields
    status: Mapped[str] = mapped_column(String(32), default=AlertStatus.NEW.value)
    assignee: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")
    events: Mapped[list[Event]] = relationship(secondary=alert_events, order_by=Event.ts)
    notes: Mapped[list[AlertNote]] = relationship(
        back_populates="alert", order_by="AlertNote.created_at", cascade="all, delete-orphan"
    )


class AlertNote(Base):
    """A free-text analyst note, or an automatic record of a status change."""

    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    alert: Mapped[Alert] = relationship(back_populates="notes")
