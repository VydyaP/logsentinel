"""Load parsed events into the database, from a file, an upload, or a watched folder."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import insert
from sqlalchemy.orm import Session

from logsentinel import parsers
from logsentinel.models import Event

log = logging.getLogger(__name__)

BATCH_SIZE = 2000


@dataclass
class IngestStats:
    log_type: str | None
    parsed: int = 0
    inserted: int = 0
    skipped_lines: int = 0

    @property
    def duplicates(self) -> int:
        return self.parsed - self.inserted


def _insert_ignore_duplicates(session: Session, rows: list[dict[str, Any]]) -> int:
    """Insert rows, silently skipping any whose ``line_hash`` already exists."""
    if not rows:
        return 0
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        stmt: Any = pg_insert(Event).on_conflict_do_nothing(index_elements=["line_hash"])
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        stmt = sqlite_insert(Event).on_conflict_do_nothing(index_elements=["line_hash"])
    else:  # pragma: no cover - other databases are not supported
        stmt = insert(Event)
    inserted = 0
    for start in range(0, len(rows), BATCH_SIZE):
        result = session.execute(stmt.returning(Event.id), rows[start : start + BATCH_SIZE])
        inserted += len(result.all())
    return inserted


def ingest_lines(
    session: Session,
    lines: Sequence[str],
    log_type: str = "auto",
    source_file: str | None = None,
    year: int | None = None,
    start_line: int = 1,
) -> IngestStats:
    """Parse ``lines`` and store the resulting events. Safe to call twice on the same data."""
    if log_type == "auto":
        log_type = parsers.detect_log_type(lines) or "auto"
    result = parsers.parse(lines, log_type, source_file, year=year, start_line=start_line)
    stats = IngestStats(log_type=None if log_type == "auto" else log_type)
    stats.parsed = len(result.events)
    stats.skipped_lines = result.skipped
    # Deduplicate inside the batch too (a file can contain the same line twice
    # only if line numbers differ, so this is just a safety net).
    unique_rows = {e.line_hash: e.to_row() for e in result.events}
    stats.inserted = _insert_ignore_duplicates(session, list(unique_rows.values()))
    session.flush()
    return stats


def ingest_file(
    session: Session, path: Path, log_type: str = "auto", year: int | None = None
) -> IngestStats:
    """Read a whole log file and ingest it."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return ingest_lines(session, text.splitlines(), log_type, source_file=path.name, year=year)


# --------------------------------------------------------------------------- watch mode


@dataclass
class _FileState:
    offset: int = 0  # bytes already read
    lines: int = 0  # lines already read (keeps line numbers stable for hashing)


class FolderWatcher:
    """Poll a folder and ingest new lines appended to ``*.log`` files (like ``tail -f``).

    Progress is kept in a small JSON state file, so restarting the watcher
    does not re-read old data. Polling is used instead of OS file events to
    keep things simple and portable across Windows, macOS and Linux.
    """

    def __init__(
        self,
        folder: Path,
        session_factory: Callable[[], Session],
        on_new_events: Callable[[Session], None] | None = None,
        state_file: Path | None = None,
        pattern: str = "*.log",
    ) -> None:
        self.folder = folder
        self.session_factory = session_factory
        self.on_new_events = on_new_events
        self.state_file = state_file or folder / ".logsentinel-state.json"
        self.pattern = pattern
        self.state: dict[str, _FileState] = self._load_state()

    def _load_state(self) -> dict[str, _FileState]:
        if not self.state_file.exists():
            return {}
        raw = json.loads(self.state_file.read_text())
        return {name: _FileState(**values) for name, values in raw.items()}

    def _save_state(self) -> None:
        data = {name: vars(state) for name, state in self.state.items()}
        self.state_file.write_text(json.dumps(data, indent=2))

    def poll_once(self) -> int:
        """Ingest any new complete lines. Returns the number of new events stored."""
        total = 0
        for path in sorted(self.folder.glob(self.pattern)):
            state = self.state.setdefault(path.name, _FileState())
            size = path.stat().st_size
            if size < state.offset:  # file was truncated or rotated
                state.offset, state.lines = 0, 0
            if size == state.offset:
                continue
            with path.open("rb") as fh:
                fh.seek(state.offset)
                chunk = fh.read()
            # Only consume complete lines; a half-written last line waits for the next poll.
            complete, _, _ = chunk.rpartition(b"\n")
            if not complete:
                continue
            lines = complete.decode("utf-8", errors="replace").split("\n")
            with self.session_factory() as session:
                stats = ingest_lines(
                    session, lines, source_file=path.name, start_line=state.lines + 1
                )
                if stats.inserted and self.on_new_events:
                    self.on_new_events(session)
                session.commit()
            state.offset += len(complete) + 1
            state.lines += len(lines)
            total += stats.inserted
            log.info("%s: +%d events", path.name, stats.inserted)
        self._save_state()
        return total

    def run(self, interval: float = 5.0) -> None:  # pragma: no cover - infinite loop
        log.info("Watching %s every %.0fs (Ctrl+C to stop)", self.folder, interval)
        while True:
            self.poll_once()
            time.sleep(interval)
