from sqlalchemy import func, select
from sqlalchemy.orm import Session

from logsentinel.ingest import FolderWatcher, ingest_file, ingest_lines
from logsentinel.models import Event

SSH_LINE = (
    "2026-11-20T03:14:{:02d}+00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
)
WEB_LINE = '203.0.113.7 - - [20/Nov/2026:03:14:15 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'


def count(session) -> int:
    return session.scalar(select(func.count()).select_from(Event))


def test_ingest_is_idempotent(session, tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(SSH_LINE.format(i) for i in range(5)) + "\nnoise\n")
    first = ingest_file(session, path)
    assert (first.log_type, first.parsed, first.inserted, first.skipped_lines) == ("ssh", 5, 5, 1)
    second = ingest_file(session, path)
    assert second.inserted == 0
    assert second.duplicates == 5
    assert count(session) == 5


def test_identical_lines_on_different_line_numbers_are_kept(session):
    stats = ingest_lines(session, [WEB_LINE, WEB_LINE], source_file="a.log")
    assert stats.inserted == 2


def test_unknown_format(session):
    stats = ingest_lines(session, ["hello", "world"])
    assert stats.log_type is None
    assert stats.inserted == 0


def test_watcher_reads_only_new_complete_lines(engine, tmp_path):
    log = tmp_path / "auth.log"
    calls = []
    watcher = FolderWatcher(
        tmp_path, lambda: Session(engine), on_new_events=lambda s: calls.append(1)
    )
    log.write_text(SSH_LINE.format(1) + "\n" + SSH_LINE.format(2))  # 2nd line incomplete
    assert watcher.poll_once() == 1
    with log.open("a") as fh:
        fh.write("\n" + SSH_LINE.format(3) + "\n")
    assert watcher.poll_once() == 2
    assert watcher.poll_once() == 0  # nothing new
    assert len(calls) == 2

    # State survives a restart.
    assert FolderWatcher(tmp_path, lambda: Session(engine)).poll_once() == 0

    # A truncated (rotated) file is read again from the start.
    log.write_text(SSH_LINE.format(9) + "\n")
    assert watcher.poll_once() == 1
    with Session(engine) as s:
        assert count(s) == 4
