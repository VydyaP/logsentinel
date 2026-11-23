"""Optional Slack and e-mail notifications for high-severity alerts.

Both channels are switched on purely by environment variables. If nothing is
configured, notifications are silently skipped, so the tool works out of the box.
A failing notifier logs an error but never breaks detection.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx

from logsentinel.config import Settings, get_settings
from logsentinel.models import Alert, Severity, utcnow

log = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":white_circle:",
}


def should_notify(alert: Alert, settings: Settings) -> bool:
    try:
        minimum = Severity(settings.notify_min_severity)
    except ValueError:
        minimum = Severity.HIGH
    return Severity(alert.severity).rank >= minimum.rank


def format_text(alert: Alert) -> str:
    """Plain-text summary used for both Slack and e-mail."""
    mitre = f"{alert.mitre_technique} {alert.mitre_name}" if alert.mitre_technique else "n/a"
    return (
        f"[{alert.severity.upper()}] {alert.rule_id} {alert.rule_name}\n"
        f"Source: {alert.entity}\n"
        f"When: {alert.first_event_at:%Y-%m-%d %H:%M:%S} - {alert.last_event_at:%H:%M:%S} UTC\n"
        f"MITRE ATT&CK: {mitre}\n"
        f"{alert.description}\n"
        f"Alert #{alert.id}, incident #{alert.incident_id}"
    )


def send_slack(alert: Alert, webhook_url: str, client: httpx.Client | None = None) -> None:
    """Post to a Slack incoming webhook."""
    emoji = SEVERITY_EMOJI.get(alert.severity, "")
    payload = {"text": f"{emoji} LogSentinel alert\n```{format_text(alert)}```"}
    http = client or httpx.Client(timeout=10)
    try:
        response = http.post(webhook_url, json=payload)
        response.raise_for_status()
    finally:
        if client is None:
            http.close()


def send_email(alert: Alert, settings: Settings) -> None:
    """Send the alert by SMTP (STARTTLS)."""
    msg = EmailMessage()
    msg["Subject"] = (
        f"[LogSentinel][{alert.severity.upper()}] {alert.rule_name} from {alert.entity}"
    )
    msg["From"] = settings.alert_email_from or settings.smtp_user
    msg["To"] = settings.alert_email_to
    msg.set_content(format_text(alert))
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)


def notify(alerts: list[Alert], settings: Settings | None = None) -> int:
    """Send every alert at or above the configured severity. Returns how many were sent."""
    settings = settings or get_settings()
    slack_on = bool(settings.slack_webhook_url)
    email_on = bool(settings.smtp_host and settings.alert_email_to)
    if not (slack_on or email_on):
        return 0
    sent = 0
    for alert in alerts:
        if not should_notify(alert, settings):
            continue
        delivered = False
        if slack_on:
            try:
                send_slack(alert, settings.slack_webhook_url)
                delivered = True
            except Exception as exc:
                log.error("Slack notification failed for alert %s: %s", alert.id, exc)
        if email_on:
            try:
                send_email(alert, settings)
                delivered = True
            except Exception as exc:
                log.error("E-mail notification failed for alert %s: %s", alert.id, exc)
        if delivered:
            alert.notified_at = utcnow()
            sent += 1
    return sent
