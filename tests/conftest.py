"""Shared test fixtures: an in-memory SQLite database and event-building helpers."""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from logsentinel.db import init_db, make_engine
from logsentinel.detection.base import EVENT_COLUMNS
from logsentinel.detection.rules import Rule, load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
T0 = datetime(2026, 11, 16, 6, 0, tzinfo=UTC)  # 11:30 IST, inside business hours
_ids = itertools.count(1)


@pytest.fixture
def engine() -> Engine:
    eng = make_engine("sqlite:///:memory:")
    init_db(eng)
    return eng


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as s:
        yield s


@pytest.fixture(scope="session")
def rules() -> dict[str, Rule]:
    return {r.id: r for r in load_rules(RULES_DIR)}


def ev(seconds: float = 0, **fields: Any) -> dict[str, Any]:
    """One event row for a detection DataFrame, ``seconds`` after T0."""
    row: dict[str, Any] = dict.fromkeys(EVENT_COLUMNS)
    row.update(id=next(_ids), ts=T0 + timedelta(seconds=seconds), raw="test line")
    row.update(fields)
    return row


def ssh(
    seconds: float, action: str, ip: str = "203.0.113.10", user: str = "root", **kw: Any
) -> dict[str, Any]:
    return ev(seconds, source="ssh", action=action, src_ip=ip, username=user, **kw)


def web(
    seconds: float,
    path: str = "/",
    status: int = 200,
    ip: str = "203.0.113.20",
    ua: str = "Mozilla/5.0",
    **kw: Any,
) -> dict[str, Any]:
    return ev(
        seconds,
        source="web",
        action="http_request",
        src_ip=ip,
        method="GET",
        path=path,
        status=status,
        user_agent=ua,
        **kw,
    )


def frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df
