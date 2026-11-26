"""Deterministic, explainable risk score for one Boundary session.

This is the part that decides what is risky. The LLM only reviews sessions
that score at or above the threshold, and can't change the score.

Every point added is recorded as a factor, so the report shows exactly why a
session scored what it did.
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from .guard import instruction_markers

LAB_TZ = ZoneInfo("America/Vancouver")

# Business hours, local time: [start, end).
WORK_START, WORK_END = 7, 19

POINTS = {
    "target_risk": 10,          # per risk level (1-5)
    "off_hours": 15,
    "weekend": 10,
    "department_mismatch": 20,
    "no_department": 10,
    "local_account": 20,
    "first_access": 10,
    "new_client_ip": 10,
    "long_session": 10,
    "large_transfer": 10,
    "concurrent_sessions": 5,
    "instruction_like_identity": 15,
}

LONG_SESSION_SECONDS = 60 * 60
LARGE_TRANSFER_BYTES = 50 * 1024 * 1024
DEFAULT_THRESHOLD = 60

BANDS = [(80, "critical"), (60, "high"), (30, "medium"), (0, "low")]


def band(score):
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "low"


def parse_time(value):
    """Parse Boundary's RFC 3339 timestamps (UTC, 'Z' suffix, microseconds)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def score_session(facts, threshold=DEFAULT_THRESHOLD):
    """Score a session-facts dict (see collect.py). Returns the score result."""
    factors = []

    def add(name, detail, points=None):
        factors.append({"factor": name, "points": POINTS[name] if points is None else points,
                        "detail": detail})

    target = facts.get("target") or {}
    user = facts.get("user") or {}
    history = facts.get("history") or {}

    risk = target.get("risk")
    if risk:
        add("target_risk", f"{target.get('name')} is risk {risk}/5 ({target.get('tier')}): "
            f"{target.get('data_classification')}", POINTS["target_risk"] * risk)

    start = parse_time(facts.get("start"))
    if start:
        local = start.astimezone(LAB_TZ)
        if not WORK_START <= local.hour < WORK_END:
            add("off_hours", f"started {local:%H:%M} local, outside {WORK_START:02d}:00-{WORK_END:02d}:00")
        if local.weekday() >= 5:
            add("weekend", f"started on a {local:%A}")

    departments = user.get("departments") or []
    owners = target.get("owners") or []
    if user.get("auth_method") == "password":
        add("local_account", f"'{user.get('login_name')}' is a local Boundary account, not an SSO user")
    elif not departments:
        add("no_department", "user has no department in their identity claims")
    elif owners and not set(departments) & set(owners):
        add("department_mismatch", f"user's department ({', '.join(departments)}) is not one of "
            f"{target.get('name')}'s owners ({', '.join(owners)})")

    if history.get("first_access"):
        add("first_access", f"first time this user has connected to {target.get('name')}")
    if history.get("new_client_ip"):
        add("new_client_ip", f"connected from an address not seen for this user before "
            f"({', '.join(facts.get('client_addresses') or [])})")

    duration = facts.get("duration_seconds")
    if duration and duration > LONG_SESSION_SECONDS:
        add("long_session", f"session lasted {duration // 60} minutes")

    transferred = (facts.get("bytes_up") or 0) + (facts.get("bytes_down") or 0)
    if transferred > LARGE_TRANSFER_BYTES:
        add("large_transfer", f"{transferred / 1024 / 1024:.0f} MiB transferred")

    # Identity data that reads like instructions to an AI is suspicious in its
    # own right (and a prompt-injection attempt): a deterministic factor, so
    # the rules flag it whatever the model makes of it.
    markers = instruction_markers(facts)
    if markers:
        add("instruction_like_identity", "instruction-like text in " + ", ".join(
            f"{m['field']} ({', '.join(m['patterns'])})" for m in markers))

    concurrent = facts.get("concurrent_targets") or []
    if concurrent:
        add("concurrent_sessions", f"also connected to {', '.join(concurrent)} at the same time")

    total = min(100, sum(f["points"] for f in factors))
    return {
        "score": total,
        "band": band(total),
        "threshold": threshold,
        "needs_review": total >= threshold,
        "factors": factors,
    }
