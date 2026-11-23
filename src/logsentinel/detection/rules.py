"""YAML-driven rule engine.

A rule is a small YAML document. Three rule types cover every detection we ship,
so new detections are added by writing YAML, not Python:

``threshold``
    At least ``threshold`` matching events from the same ``group_by`` value within
    ``window``. Example: 10 failed SSH logins from one IP within 5 minutes.
    With ``threshold: 1`` it fires on any single matching event (e.g. one SQL
    injection attempt), and nearby hits are merged into one alert.

``distinct``
    At least ``threshold`` *different* values of ``distinct_field`` within ``window``.
    Example: one IP trying 8 different usernames in 30 minutes (password spraying).

``sequence``
    At least ``threshold`` events matching ``where`` followed by one event matching
    ``then``, from the same group, within ``window``.
    Example: 5 failed logins and then a successful one (a guessed password).

Events are filtered with ``where`` conditions; see :func:`condition_mask`.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote_plus

import pandas as pd
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from logsentinel.detection.base import Detection

MAX_EVIDENCE = 200  # raw events linked to one alert; the count still reflects all of them

_WINDOW = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_window(text: str) -> pd.Timedelta:
    """Turn '30s', '5m', '1h' or '2d' into a Timedelta."""
    match = _WINDOW.match(text.strip())
    if not match:
        raise ValueError(f"Invalid window {text!r}; use e.g. '30s', '5m', '1h', '1d'")
    return pd.Timedelta(**{_UNITS[match[2]]: int(match[1])})


class Mitre(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str


class Rule(BaseModel):
    """One detection rule, validated when the YAML is loaded."""

    id: str = Field(pattern=r"^[A-Z]+-\d{3}$")
    name: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    type: Literal["threshold", "distinct", "sequence"]
    window: str
    threshold: int = Field(default=1, ge=1)
    group_by: Literal["src_ip", "username"] = "src_ip"
    where: dict[str, Any] = Field(default_factory=dict)
    distinct_field: str | None = None
    then: dict[str, Any] | None = None
    timezone: str = "UTC"
    mitre: Mitre
    message: str = "{count} matching events from {entity} within {window}"
    runbook: str | None = None
    # Recommended containment/response steps, shown in incident reports.
    response: list[str] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("window")
    @classmethod
    def _check_window(cls, value: str) -> str:
        parse_window(value)
        return value

    @model_validator(mode="after")
    def _check_type_fields(self) -> Rule:
        if self.type == "distinct" and not self.distinct_field:
            raise ValueError(f"{self.id}: 'distinct' rules need distinct_field")
        if self.type == "sequence" and not self.then:
            raise ValueError(f"{self.id}: 'sequence' rules need a 'then' condition")
        return self

    @property
    def window_td(self) -> pd.Timedelta:
        return parse_window(self.window)


def load_rules(path: Path) -> list[Rule]:
    """Load every rule from a YAML file or a folder of ``*.yaml`` files."""
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    rules: list[Rule] = []
    for file in files:
        data = yaml.safe_load(file.read_text()) or {}
        for raw in data.get("rules", []):
            rules.append(Rule.model_validate(raw))
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise ValueError(f"Duplicate rule ids: {sorted(duplicates)}")
    return rules


# --------------------------------------------------------------------------- conditions


def prepare_events(df: pd.DataFrame) -> pd.DataFrame:
    """Add helper columns used by conditions (decoded URL path)."""
    df = df.copy()
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    # Attackers URL-encode payloads (often twice) to dodge filters, so decode before matching.
    df["path_decoded"] = df["path"].fillna("").map(lambda p: unquote_plus(unquote_plus(p)))
    return df.sort_values("ts", kind="stable").reset_index(drop=True)


def condition_mask(df: pd.DataFrame, where: dict[str, Any], timezone: str = "UTC") -> pd.Series:
    """Return a boolean Series: which events satisfy every condition in ``where``.

    Supported forms for each ``field: spec`` pair:

    * ``action: login_failed``             - equals
    * ``action: [login_failed, x]``        - one of
    * ``path_decoded: {regex: "..."}``     - case-insensitive regex search
    * ``status: {gte: 400, lte: 499}``     - numeric range
    * ``user_agent: {not_regex: "..."}``   / ``{not_in: [...]}``
    * ``hour: {outside: [7, 20]}``         - event hour (in the rule's timezone)
      is before 07:00 or at/after 20:00
    """
    mask = pd.Series(True, index=df.index)
    for field, spec in where.items():
        if field == "hour":
            column = df["ts"].dt.tz_convert(timezone).dt.hour
        elif field in df.columns:
            column = df[field]
        else:
            raise ValueError(f"Unknown field in rule condition: {field!r}")
        mask &= _match(column, spec)
    return mask


def _regex_mask(column: pd.Series, pattern: str) -> pd.Series:
    regex = re.compile(pattern, re.IGNORECASE)
    return column.fillna("").astype(str).map(lambda text: regex.search(text) is not None)


def _match(column: pd.Series, spec: Any) -> pd.Series:
    if isinstance(spec, list):
        return column.isin(spec)
    if not isinstance(spec, dict):
        return column == spec
    mask = pd.Series(True, index=column.index)
    for op, value in spec.items():
        if op == "regex":
            mask &= _regex_mask(column, value)
        elif op == "not_regex":
            mask &= ~_regex_mask(column, value)
        elif op == "in":
            mask &= column.isin(value)
        elif op == "not_in":
            mask &= ~column.isin(value)
        elif op == "gte":
            mask &= pd.to_numeric(column, errors="coerce") >= value
        elif op == "lte":
            mask &= pd.to_numeric(column, errors="coerce") <= value
        elif op == "outside":
            start, end = value
            mask &= (column < start) | (column >= end)
        else:
            raise ValueError(f"Unknown condition operator: {op!r}")
    return mask


# --------------------------------------------------------------------------- evaluation


def _bursts(times: list[pd.Timestamp], window: pd.Timedelta) -> Iterable[tuple[int, int]]:
    """Split sorted timestamps into bursts: runs where each gap is at most ``window``.

    Yields (start_index, end_index_exclusive). One burst becomes at most one alert,
    so a 2-hour brute-force attack gives one alert, not hundreds.
    """
    start = 0
    for i in range(1, len(times)):
        if times[i] - times[i - 1] > window:
            yield start, i
            start = i
    if times:
        yield start, len(times)


def _peak_in_window(
    times: list[pd.Timestamp], window: pd.Timedelta, values: list[Any] | None = None
) -> int:
    """Largest number of events (or distinct ``values``) inside any sliding ``window``."""
    best = 0
    left = 0
    seen: Counter[Any] = Counter()
    for right in range(len(times)):
        if values is not None:
            seen[values[right]] += 1
        while times[right] - times[left] > window:
            if values is not None:
                seen[values[left]] -= 1
                if seen[values[left]] == 0:
                    del seen[values[left]]
            left += 1
        best = max(best, len(seen) if values is not None else right - left + 1)
    return best


def _make_detection(rule: Rule, entity: str, group: pd.DataFrame, peak: int) -> Detection:
    users = group["username"].dropna()
    paths = group["path"].dropna()
    context = {
        "count": len(group),
        "peak": peak,
        "entity": entity,
        "window": rule.window,
        "distinct_users": users.nunique(),
        "users": ", ".join(users.value_counts().index[:5]),
        "last_user": users.iloc[-1] if not users.empty else "-",
        "paths": ", ".join(paths.head(3)),
        "ips": ", ".join(group["src_ip"].dropna().unique()[:5]),
    }
    return Detection(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        entity=entity,
        entity_type="ip" if rule.group_by == "src_ip" else "user",
        description=rule.message.format(**context),
        first_ts=group["ts"].iloc[0].to_pydatetime(),
        last_ts=group["ts"].iloc[-1].to_pydatetime(),
        event_ids=[int(i) for i in group["id"].head(MAX_EVIDENCE)],
        event_count=len(group),
        mitre_technique=rule.mitre.technique_id,
        mitre_name=rule.mitre.technique_name,
        mitre_tactic=rule.mitre.tactic,
        details={
            "peak_in_window": peak,
            "threshold": rule.threshold,
            "window": rule.window,
            "top_usernames": users.value_counts().head(10).to_dict(),
            "sample_paths": paths.head(10).tolist(),
        },
    )


def _run_count_rule(rule: Rule, df: pd.DataFrame) -> list[Detection]:
    """Evaluate a ``threshold`` or ``distinct`` rule."""
    matched = df[condition_mask(df, rule.where, rule.timezone)]
    matched = matched[matched[rule.group_by].notna()]
    detections = []
    for entity, group in matched.groupby(rule.group_by, sort=True):
        times = group["ts"].tolist()
        for start, end in _bursts(times, rule.window_td):
            burst = group.iloc[start:end]
            burst_times = times[start:end]
            if rule.type == "distinct":
                assert rule.distinct_field is not None
                values = burst[rule.distinct_field].tolist()
                peak = _peak_in_window(burst_times, rule.window_td, values)
            else:
                peak = _peak_in_window(burst_times, rule.window_td)
            if peak >= rule.threshold:
                detections.append(_make_detection(rule, str(entity), burst, peak))
    return detections


def _run_sequence_rule(rule: Rule, df: pd.DataFrame) -> list[Detection]:
    """Evaluate a ``sequence`` rule: N 'where' events, then one 'then' event."""
    assert rule.then is not None
    is_first = condition_mask(df, rule.where, rule.timezone)
    is_then = condition_mask(df, rule.then, rule.timezone)
    relevant = df[(is_first | is_then) & df[rule.group_by].notna()].copy()
    relevant["_is_then"] = is_then[relevant.index]
    detections = []
    for entity, group in relevant.groupby(rule.group_by, sort=True):
        recent: deque[int] = deque()  # positions of recent 'where' events
        rows = group.reset_index(drop=True)
        for pos in range(len(rows)):
            ts = rows.at[pos, "ts"]
            while recent and ts - rows.at[recent[0], "ts"] > rule.window_td:
                recent.popleft()
            if not rows.at[pos, "_is_then"]:
                recent.append(pos)
                continue
            if len(recent) >= rule.threshold:
                evidence = rows.loc[[*recent, pos]]
                detection = _make_detection(rule, str(entity), evidence, len(recent))
                detection.details["successful_user"] = rows.at[pos, "username"]
                detections.append(detection)
            recent.clear()
    return detections


def run_rules(rules: list[Rule], events: pd.DataFrame) -> list[Detection]:
    """Run every enabled rule over an events DataFrame and return all detections."""
    if events.empty:
        return []
    df = prepare_events(events)
    detections: list[Detection] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.type == "sequence":
            detections.extend(_run_sequence_rule(rule, df))
        else:
            detections.extend(_run_count_rule(rule, df))
    return detections
