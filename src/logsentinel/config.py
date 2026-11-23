"""Application settings, read from environment variables.

Every setting has a safe default so the tool runs locally with no configuration.
Secrets (webhook URLs, SMTP passwords, API keys) are only ever read from the
environment and are never written to logs or the database.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value else default


@dataclass(frozen=True)
class Settings:
    """All runtime configuration in one place."""

    database_url: str = field(
        default_factory=lambda: _env("DATABASE_URL", "sqlite:///logsentinel.db")
    )
    rules_dir: Path = field(
        default_factory=lambda: Path(_env("RULES_DIR", str(PROJECT_ROOT / "rules")))
    )
    # Optional API key protecting write endpoints of the REST API.
    api_key: str = field(default_factory=lambda: _env("API_KEY"))

    # Notifications (all optional; empty means "disabled").
    slack_webhook_url: str = field(default_factory=lambda: _env("SLACK_WEBHOOK_URL"))
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: _env("SMTP_USER"))
    smtp_password: str = field(default_factory=lambda: _env("SMTP_PASSWORD"))
    alert_email_from: str = field(default_factory=lambda: _env("ALERT_EMAIL_FROM"))
    alert_email_to: str = field(default_factory=lambda: _env("ALERT_EMAIL_TO"))
    notify_min_severity: str = field(
        default_factory=lambda: _env("NOTIFY_MIN_SEVERITY", "high").lower()
    )

    # Alerts from the same source within this many hours join one incident.
    incident_window_hours: int = field(
        default_factory=lambda: _env_int("INCIDENT_WINDOW_HOURS", 24)
    )
    # Dashboard: set READ_ONLY=1 to hide the triage buttons.
    read_only: bool = field(default_factory=lambda: _env("READ_ONLY") in {"1", "true", "yes"})


def get_settings() -> Settings:
    """Return a fresh Settings object (cheap; reads the environment each call)."""
    return Settings()


def normalize_db_url(url: str) -> str:
    """Make sure PostgreSQL URLs use the psycopg (v3) driver.

    Hosted providers such as Neon hand out ``postgres://`` or ``postgresql://``
    URLs; SQLAlchemy needs ``postgresql+psycopg://`` to pick the right driver.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url
