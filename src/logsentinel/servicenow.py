"""ServiceNow ticketing provider (REST Table API, ``/api/now/table/incident``).

What it does:

* **create** - ``POST`` a new incident with short/long description, category,
  impact and urgency mapped from severity, and a ``correlation_id``. Before
  posting it looks the correlation id up, so the same LogSentinel incident can
  never open two tickets, even if a previous run crashed after creating one.
* **update** - ``PATCH`` impact/urgency/short description and add a work note
  when more alerts join the incident.
* **status** - ``GET`` tickets in batches (paginated) so a scheduled job can copy
  "Resolved"/"Closed" back into LogSentinel.

HTTP is defensive: connect/read timeouts, retries with exponential backoff and
jitter on 429 and 5xx (honouring ``Retry-After``), clear errors for 401/403 and
for a hibernating developer instance, and one structured log line per call.
Credentials are only ever passed to httpx's auth handler; they are never logged.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from logsentinel.config import Settings
from logsentinel.models import Incident
from logsentinel.ticketing import (
    TicketingAuthError,
    TicketingError,
    TicketRef,
    TicketStatus,
    correlation_id,
    describe_incident,
)

log = logging.getLogger(__name__)

TABLE_PATH = "/api/now/table/incident"
FIELDS = "sys_id,number,state,close_code,close_notes,correlation_id"

# Severity -> (impact, urgency). With ServiceNow's default priority lookup this
# gives critical=P1, high=P2, medium=P3, low=P5. 1 = High, 2 = Medium, 3 = Low.
SEVERITY_TO_IMPACT_URGENCY: dict[str, tuple[int, int]] = {
    "critical": (1, 1),
    "high": (2, 1),
    "medium": (2, 2),
    "low": (3, 3),
}

# Incident "state" choice values in a default instance.
STATE_LABELS = {
    "1": "New",
    "2": "In Progress",
    "3": "On Hold",
    "6": "Resolved",
    "7": "Closed",
    "8": "Canceled",
}
CLOSED_STATES = {"6", "7", "8"}
CANCELED_STATE = "8"

RETRY_STATUSES = {429, 500, 502, 503, 504}
# For POST we only retry when the request certainly was not processed;
# a 500/502/504 or read timeout might have created the ticket already.
SAFE_POST_RETRY_STATUSES = {429, 503}
BATCH_SIZE = 50  # sys_ids per query (keeps URLs short)
PAGE_SIZE = 100


class ServiceNowError(TicketingError):
    """Any ServiceNow failure other than authentication."""


class ServiceNowAuthError(TicketingAuthError, ServiceNowError):
    """401 or 403 from ServiceNow."""


class ServiceNowUnavailableError(ServiceNowError):
    """The instance answered with something that is not the REST API (hibernating?)."""


class ServiceNowProvider:
    """``TicketingProvider`` backed by a ServiceNow instance."""

    name = "servicenow"

    def __init__(
        self,
        instance_url: str,
        username: str,
        password: str,
        *,
        category: str = "network",
        assignment_group: str = "",
        dashboard_url: str = "http://localhost:8501",
        timeout: float = 15.0,
        max_retries: int = 4,
        backoff_base: float = 1.0,
        backoff_cap: float = 30.0,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not instance_url.startswith("https://"):
            raise ValueError("SERVICENOW_INSTANCE_URL must start with https://")
        self.instance_url = instance_url.rstrip("/")
        self.category = category
        self.assignment_group = assignment_group
        self.dashboard_url = dashboard_url.rstrip("/")
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self._sleep = sleep
        self._client = client or httpx.Client(
            base_url=self.instance_url,
            auth=httpx.BasicAuth(username, password),
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            follow_redirects=False,
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> ServiceNowProvider:
        return cls(
            settings.servicenow_instance_url,
            settings.servicenow_username,
            settings.servicenow_password,
            category=settings.servicenow_category,
            assignment_group=settings.servicenow_assignment_group,
            dashboard_url=settings.dashboard_url,
            timeout=settings.servicenow_timeout,
            max_retries=settings.servicenow_max_retries,
        )

    def close(self) -> None:
        self._client.close()

    def __repr__(self) -> str:  # never show credentials
        return f"ServiceNowProvider({self.instance_url!r})"

    # ----------------------------------------------------------------- interface

    def create_incident(self, incident: Incident) -> TicketRef:
        cid = correlation_id(incident)
        existing = self.find_by_correlation_id(cid)
        if existing is not None:
            log.info("servicenow ticket %s already exists for %s", existing.number, cid)
            return existing
        impact, urgency = SEVERITY_TO_IMPACT_URGENCY[incident.severity]
        body: dict[str, Any] = {
            "short_description": short_description(incident),
            "description": describe_incident(incident, self.dashboard_url),
            "category": self.category,
            "impact": str(impact),
            "urgency": str(urgency),
            "correlation_id": cid,
            "correlation_display": "LogSentinel",
        }
        if self.assignment_group:
            body["assignment_group"] = self.assignment_group
        record = self._request("POST", TABLE_PATH, params={"sysparm_fields": FIELDS}, json=body)
        return self._ref(record)

    def update_incident(self, incident: Incident, comment: str | None = None) -> None:
        if not incident.external_ref:
            raise ServiceNowError(f"incident {incident.id} has no ServiceNow ticket")
        impact, urgency = SEVERITY_TO_IMPACT_URGENCY[incident.severity]
        body: dict[str, Any] = {
            "short_description": short_description(incident),
            "impact": str(impact),
            "urgency": str(urgency),
        }
        if comment:
            body["work_notes"] = comment
        self._request(
            "PATCH",
            f"{TABLE_PATH}/{incident.external_ref}",
            params={"sysparm_fields": FIELDS},
            json=body,
        )

    def get_status(self, ticket_id: str) -> str:
        record = self._request(
            "GET", f"{TABLE_PATH}/{ticket_id}", params={"sysparm_fields": FIELDS}
        )
        return _state_label(record.get("state"))

    def get_statuses(self, ticket_ids: list[str]) -> dict[str, TicketStatus]:
        result: dict[str, TicketStatus] = {}
        for start in range(0, len(ticket_ids), BATCH_SIZE):
            chunk = ticket_ids[start : start + BATCH_SIZE]
            query = "sys_idIN" + ",".join(chunk)
            for record in self._paginate(query):
                status = _status(record)
                result[status.ticket_id] = status
        return result

    # ----------------------------------------------------------------- helpers

    def find_by_correlation_id(self, cid: str) -> TicketRef | None:
        records = list(self._paginate(f"correlation_id={cid}", limit=1, max_pages=1))
        return self._ref(records[0]) if records else None

    def ticket_url(self, sys_id: str) -> str:
        return f"{self.instance_url}/incident.do?sys_id={sys_id}"

    def _ref(self, record: dict[str, Any]) -> TicketRef:
        sys_id = str(record["sys_id"])
        return TicketRef(
            ticket_id=sys_id,
            url=self.ticket_url(sys_id),
            number=record.get("number"),
            state=_state_label(record.get("state")),
        )

    def _paginate(
        self, query: str, limit: int = PAGE_SIZE, max_pages: int = 1000
    ) -> Iterator[dict[str, Any]]:
        """Yield records page by page using sysparm_limit/sysparm_offset."""
        offset = 0
        for _ in range(max_pages):
            page = self._request(
                "GET",
                TABLE_PATH,
                params={
                    "sysparm_query": query,
                    "sysparm_fields": FIELDS,
                    "sysparm_limit": str(limit),
                    "sysparm_offset": str(offset),
                    "sysparm_exclude_reference_link": "true",
                },
            )
            records = page if isinstance(page, list) else []
            yield from records
            if len(records) < limit:
                return
            offset += limit

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        """One API call with retries; returns the ``result`` member of the JSON body."""
        retry_statuses = SAFE_POST_RETRY_STATUSES if method == "POST" else RETRY_STATUSES
        attempt = 0
        while True:
            attempt += 1
            started = time.monotonic()
            try:
                response = self._client.request(method, path, params=params, json=json)
            except httpx.TransportError as exc:
                elapsed = _ms(started)
                # A connect failure means the request never arrived: always safe to retry.
                # Anything later (read timeout) is only safe for non-POST calls.
                safe = method != "POST" or isinstance(
                    exc, httpx.ConnectError | httpx.ConnectTimeout
                )
                self._log(method, path, None, attempt, elapsed, error=type(exc).__name__)
                if safe and attempt <= self.max_retries:
                    self._sleep(self._backoff(attempt, None))
                    continue
                raise ServiceNowError(
                    f"{method} {path} failed: {type(exc).__name__} after {attempt} attempt(s)"
                ) from exc

            elapsed = _ms(started)
            status = response.status_code
            self._log(method, path, status, attempt, elapsed)
            if status in retry_statuses and attempt <= self.max_retries:
                self._sleep(self._backoff(attempt, response.headers.get("Retry-After")))
                continue
            return self._parse(method, path, response)

    def _parse(self, method: str, path: str, response: httpx.Response) -> Any:
        status = response.status_code
        if status == 401:
            raise ServiceNowAuthError(
                "ServiceNow returned 401 Unauthorized: check SERVICENOW_USERNAME and "
                "SERVICENOW_PASSWORD, and that the integration user is active and not locked out."
            )
        if status == 403:
            raise ServiceNowAuthError(
                f"ServiceNow returned 403 Forbidden for {method} {path}: the user logged in but "
                "lacks access. Give the integration user the 'itil' role "
                f"({_error_message(response)})."
            )
        if 300 <= status < 400 or "json" not in response.headers.get("content-type", ""):
            raise ServiceNowUnavailableError(
                f"ServiceNow answered {status} with non-JSON content for {method} {path}. "
                "A developer instance that is hibernating does this: wake it at "
                "developer.servicenow.com, or check SERVICENOW_INSTANCE_URL."
            )
        if status >= 400:
            raise ServiceNowError(
                f"ServiceNow returned {status} for {method} {path}: {_error_message(response)}"
            )
        try:
            return response.json().get("result")
        except ValueError as exc:
            raise ServiceNowUnavailableError(f"invalid JSON from {method} {path}") from exc

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 60.0)
        delay = min(self.backoff_cap, self.backoff_base * 2 ** (attempt - 1))
        return delay + random.uniform(0, self.backoff_base)  # jitter: avoid thundering herd

    def _log(
        self,
        method: str,
        path: str,
        status: int | None,
        attempt: int,
        duration_ms: int,
        error: str | None = None,
    ) -> None:
        fields = {
            "provider": "servicenow",
            "method": method,
            "path": path,
            "status": status,
            "attempt": attempt,
            "duration_ms": duration_ms,
        }
        if error:
            fields["error"] = error
        ok = status is not None and status < 400
        level = logging.INFO if ok else logging.WARNING
        log.log(
            level,
            "servicenow_call %s",
            " ".join(f"{k}={v}" for k, v in fields.items()),
            extra={"servicenow": fields},
        )


def short_description(incident: Incident) -> str:
    return f"[LogSentinel][{incident.severity.upper()}] {incident.title}"[:160]


def _state_label(value: Any) -> str:
    key = str(value) if value is not None else ""
    return STATE_LABELS.get(key, f"state {key}" if key else "unknown")


def _status(record: dict[str, Any]) -> TicketStatus:
    state = str(record.get("state", ""))
    resolution = " - ".join(x for x in (record.get("close_code"), record.get("close_notes")) if x)
    return TicketStatus(
        ticket_id=str(record["sys_id"]),
        number=record.get("number"),
        state=_state_label(state),
        closed=state in CLOSED_STATES,
        canceled=state == CANCELED_STATE,
        resolution=resolution or None,
    )


def _error_message(response: httpx.Response) -> str:
    try:
        error = response.json().get("error") or {}
        return str(error.get("message") or error.get("detail") or "no detail")[:300]
    except ValueError:
        return "no detail"


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
