"""Command-line interface: ``logsentinel <command>``.

Run ``logsentinel --help`` for the list of commands.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from logsentinel.config import PROJECT_ROOT, get_settings
from logsentinel.db import get_engine, get_sessionmaker, session_scope


def _duration(text: str) -> timedelta:
    from logsentinel.detection.rules import parse_window

    return parse_window(text).to_pytimedelta()


def cmd_init_db(args: argparse.Namespace) -> None:
    """Create or upgrade the database schema with Alembic."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    command.upgrade(cfg, "head")
    print("Database schema is up to date.")


def cmd_ingest(args: argparse.Namespace) -> None:
    from logsentinel.ingest import ingest_file
    from logsentinel.pipeline import run_detection

    with session_scope() as session:
        for path in args.files:
            stats = ingest_file(session, Path(path), args.type, year=args.year)
            print(
                f"{path}: type={stats.log_type} parsed={stats.parsed} new={stats.inserted} "
                f"duplicates={stats.duplicates} skipped_lines={stats.skipped_lines}"
            )
        if not args.no_detect:
            run = run_detection(session)
            print(f"Detection: {run.detections} detections, {len(run.new_alerts)} new alerts")


def cmd_watch(args: argparse.Namespace) -> None:
    from logsentinel.ingest import FolderWatcher
    from logsentinel.pipeline import run_detection

    watcher = FolderWatcher(
        Path(args.folder),
        get_sessionmaker(),
        on_new_events=lambda s: print(
            f"new alerts: {len(run_detection(s, lookback=_duration(args.lookback)).new_alerts)}"
        ),
    )
    watcher.run(args.interval)


def cmd_detect(args: argparse.Namespace) -> None:
    from logsentinel.pipeline import run_detection

    with session_scope() as session:
        run = run_detection(
            session,
            lookback=_duration(args.lookback) if args.lookback else None,
            use_anomaly=not args.no_anomaly,
            contamination=args.contamination,
        )
    print(
        f"Scanned {run.events_scanned} events: {run.detections} detections, "
        f"{len(run.new_alerts)} new alerts, {run.notified} notifications sent"
    )


def cmd_alerts(args: argparse.Namespace) -> None:
    from logsentinel.models import Alert

    with session_scope() as session:
        query = select(Alert).order_by(Alert.first_event_at.desc()).limit(args.limit)
        if args.status:
            query = query.where(Alert.status == args.status)
        for a in session.scalars(query):
            print(
                f"#{a.id:<5} {a.first_event_at:%Y-%m-%d %H:%M} {a.severity:<8} {a.rule_id:<8} "
                f"{a.status:<14} INC-{a.incident_id or 0:05d} {a.entity}"
            )


def cmd_report(args: argparse.Namespace) -> None:
    from logsentinel.report import generate_report

    with session_scope() as session:
        _, _, paths = generate_report(session, args.incident_id, Path(args.out))
    for p in paths:
        print(f"Wrote {p}")


def cmd_evaluate(args: argparse.Namespace) -> None:
    from logsentinel.evaluate import evaluate, save, to_markdown

    files = [Path(f) for f in args.logs]
    result = evaluate(files, Path(args.labels), get_settings().rules_dir, args.contamination)
    command = "logsentinel evaluate " + " ".join(sys.argv[2:])
    save(result, Path(args.out), Path(args.json), command)
    print(to_markdown(result, command))


def cmd_demo_seed(args: argparse.Namespace) -> None:
    from logsentinel.demo import reset, seed_demo

    with session_scope() as session:
        if args.reset:
            reset(session)
        counts = seed_demo(session, days=args.days, seed=args.seed)
    print(f"Demo data loaded: {counts}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logsentinel", description="SOC-style log monitoring")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-db", help="create/upgrade the database schema (Alembic)")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("ingest", help="ingest log files, then run detection")
    p.add_argument("files", nargs="+")
    p.add_argument("--type", choices=["auto", "ssh", "web"], default="auto")
    p.add_argument("--year", type=int, help="year for classic syslog timestamps (no year in file)")
    p.add_argument("--no-detect", action="store_true", help="only store events")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("watch", help="tail *.log files in a folder and detect continuously")
    p.add_argument("folder")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between polls")
    p.add_argument("--lookback", default="24h", help="detection window, e.g. 1h, 24h")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("detect", help="run rules + anomaly model over stored events")
    p.add_argument("--lookback", help="only events this close to the newest one, e.g. 24h")
    p.add_argument("--no-anomaly", action="store_true")
    p.add_argument("--contamination", type=float, default=0.02)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("alerts", help="list recent alerts")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("report", help="write Markdown + PDF incident report")
    p.add_argument("incident_id", type=int)
    p.add_argument("--out", default="reports")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("evaluate", help="score detections against simulator labels")
    p.add_argument(
        "--logs", nargs="+", default=["data/samples/auth.log", "data/samples/access.log"]
    )
    p.add_argument("--labels", default="data/samples/labels.csv")
    p.add_argument("--contamination", type=float, default=0.02)
    p.add_argument("--out", default="docs/EVALUATION.md")
    p.add_argument("--json", default="docs/evaluation.json")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("demo-seed", help="load synthetic demo data with simulated triage")
    p.add_argument("--days", type=int, default=2)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--reset", action="store_true", help="delete existing data first")
    p.set_defaults(func=cmd_demo_seed)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    get_engine()  # fail fast on a bad DATABASE_URL
    args.func(args)


if __name__ == "__main__":
    main()
