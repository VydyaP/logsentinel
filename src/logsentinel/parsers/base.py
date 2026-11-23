"""Shared types for log parsers."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ParsedEvent:
    """A log line converted to LogSentinel's common event shape.

    Every parser (SSH, web, ...) returns this same structure, so the detection
    engine never needs to know which log format an event came from.
    """

    ts: datetime
    source: str  # "ssh" or "web"
    action: str
    raw: str
    host: str | None = None
    src_ip: str | None = None
    username: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    bytes_sent: int | None = None
    user_agent: str | None = None
    source_file: str | None = None
    line_no: int = 0
    # Position inside an expanded "message repeated N times" line.
    sub_index: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def line_hash(self) -> str:
        """Identity of this event, so ingesting the same file twice adds nothing."""
        key = f"{self.source}|{self.source_file}|{self.line_no}|{self.sub_index}|{self.raw}"
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()

    def to_row(self) -> dict[str, Any]:
        """Column values for the ``events`` table."""
        row = asdict(self)
        for key in ("line_no", "sub_index", "extra"):
            row.pop(key)
        row["line_hash"] = self.line_hash
        return row


@dataclass
class ParseResult:
    """Events plus a count of lines we could not (or chose not to) parse."""

    events: list[ParsedEvent] = field(default_factory=list)
    skipped: int = 0
