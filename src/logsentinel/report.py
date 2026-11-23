"""Incident report generation: Markdown (Jinja2 template) and PDF.

The Markdown is the single source of truth. The PDF is produced by converting
that Markdown to simple HTML and laying it out with fpdf2, which is pure Python
(no system libraries), so it works the same on Windows, macOS, Linux and Docker.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import markdown
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from sqlalchemy.orm import Session

from logsentinel.config import get_settings
from logsentinel.detection.rules import load_rules
from logsentinel.models import Incident, utcnow

TEMPLATES = Path(__file__).parent / "templates"
MAX_EVIDENCE_LINES = 25
# Relative PDF column widths (percent) by table header text.
PDF_COLUMN_WIDTHS = {
    "Field": 30,
    "Value": 70,
    "Time (UTC)": 18,
    "Alert": 10,
    "Severity": 9,
    "Status": 13,
    "What happened": 50,
    "Type": 20,
    "Technique": 14,
    "Name": 46,
    "Tactic": 25,
    "Alerts": 15,
}


def _dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


def _cell(value: str) -> str:
    """Make text safe inside a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        undefined=StrictUndefined,
        trim_blocks=False,
        autoescape=False,  # noqa: S701 - output is Markdown, not served as HTML
    )
    env.filters["dt"] = _dt
    env.filters["cell"] = _cell
    return env


def build_context(incident: Incident, rules_dir: Path | None = None) -> dict[str, Any]:
    """Collect everything the report template needs from an incident and its alerts."""
    alerts = sorted(incident.alerts, key=lambda a: a.first_event_at)
    events = {e.id: e for a in alerts for e in a.events}
    ordered_events = sorted(events.values(), key=lambda e: e.ts)

    usernames = Counter(e.username for e in ordered_events if e.username)
    compromised = sorted(
        {e.username for e in ordered_events if e.action == "login_success" and e.username}
        if any(a.rule_id == "SSH-003" for a in alerts)
        else set()
    )
    attack_rules = {"WEB-002", "WEB-003", "WEB-004"}
    successful_web = sum(
        1
        for a in alerts
        if a.rule_id in attack_rules
        for e in a.events
        if e.status is not None and 200 <= e.status < 300
    )

    mitre: dict[str, dict[str, Any]] = {}
    for a in alerts:
        key = a.mitre_technique or "n/a"
        entry = mitre.setdefault(
            key,
            {
                "technique": key,
                "name": a.mitre_name or "Behavioural anomaly (no single technique)",
                "tactic": a.mitre_tactic or "-",
                "count": 0,
            },
        )
        entry["count"] += 1

    rules = {r.id: r for r in load_rules(rules_dir or get_settings().rules_dir)}
    actions: list[str] = []
    for rule_id in dict.fromkeys(a.rule_id for a in alerts):
        rule = rules.get(rule_id)
        for step in rule.response if rule else []:
            if step not in actions:
                actions.append(step)
    if not actions:
        actions.append("Review the evidence below and decide whether to escalate or close.")
    actions.append("Record the outcome in the analyst notes and close the incident.")

    notes = sorted((n for a in alerts for n in a.notes), key=lambda n: n.created_at)
    return {
        "incident": incident,
        "alerts": alerts,
        "total_events": sum(a.event_count for a in alerts),
        "rule_names": sorted({f"{a.rule_id} {a.rule_name}" for a in alerts}),
        "compromised_users": compromised,
        "successful_web": successful_web,
        "hosts": sorted({e.host for e in ordered_events if e.host}),
        "usernames": [u for u, _ in usernames.most_common(15)],
        "more_usernames": max(0, len(usernames) - 15),
        "paths": list(dict.fromkeys(e.path for e in ordered_events if e.path))[:10],
        "other_ips": sorted(
            {e.src_ip for e in ordered_events if e.src_ip and e.src_ip != incident.entity}
        )[:10],
        "user_agents": list(dict.fromkeys(e.user_agent for e in ordered_events if e.user_agent))[
            :5
        ],
        "mitre": list(mitre.values()),
        "actions": actions,
        "evidence": [e.raw for e in ordered_events[:MAX_EVIDENCE_LINES]],
        "notes": notes,
        "generated_at": utcnow(),
    }


def render_markdown(incident: Incident, rules_dir: Path | None = None) -> str:
    template = _env().get_template("incident_report.md.j2")
    return template.render(**build_context(incident, rules_dir))


def _latin1(text: str) -> str:
    """fpdf2's built-in fonts only cover Latin-1; replace anything else."""
    return text.encode("latin-1", "replace").decode("latin-1")


def markdown_to_pdf(md_text: str) -> bytes:
    """Render report Markdown into a PDF document and return its bytes."""
    html = markdown.markdown(_latin1(md_text), extensions=["tables", "fenced_code"])
    # fpdf2's HTML renderer handles tables best with explicit borders and widths.
    html = html.replace("<table>", '<table border="1" width="100%">')
    for header, width in PDF_COLUMN_WIDTHS.items():
        html = html.replace(f"<th>{header}</th>", f'<th width="{width}%">{header}</th>')
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=9)
    pdf.write_html(html, font_family="Helvetica")
    return bytes(pdf.output())


def generate_report(
    session: Session, incident_id: int, out_dir: Path | None = None
) -> tuple[str, bytes, list[Path]]:
    """Build the Markdown and PDF for one incident; optionally write both to ``out_dir``."""
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise LookupError(f"Incident {incident_id} not found")
    md_text = render_markdown(incident)
    pdf_bytes = markdown_to_pdf(md_text)
    written: list[Path] = []
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"INC-{incident.id:05d}"
        md_path, pdf_path = out_dir / f"{stem}.md", out_dir / f"{stem}.pdf"
        md_path.write_text(md_text, encoding="utf-8")
        pdf_path.write_bytes(pdf_bytes)
        written = [md_path, pdf_path]
    return md_text, pdf_bytes, written
