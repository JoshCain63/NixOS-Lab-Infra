"""pam-review's own login, as SOC events.

pam-review is itself a governed AI agent (svc-pam-review). If midPoint
disables its AD account (sponsor left, or expired), its Boundary login fails
and the review simply stops: a silent gap in monitoring unless someone is
told. So each change of login state is written to the findings log, which
goes to Wazuh:

    ok -> failed   pam_review.auth, status auth_failed  (alerts)
    failed -> ok   pam_review.auth, status auth_restored

Only transitions are written, so a disabled reviewer doesn't raise an alert
every two minutes. The last state is kept in a small JSON file.
"""

import json
import os
from datetime import datetime, timezone

from .report import append_finding

MAX_DETAIL = 300


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


def record(reports_dir, state_file, account, ok, stage=None, detail=None, now=None):
    """Record this run's login result. Returns the event written, or None."""
    now = now or datetime.now(timezone.utc)
    prev = _load(state_file)
    status = "ok" if ok else "failed"
    event = None
    if status != prev.get("status") and (status == "failed" or prev.get("status") == "failed"):
        event = {
            "event": "pam_review.auth",
            "time": now.isoformat(),
            "account": account,
            "status": "auth_failed" if status == "failed" else "auth_restored",
        }
        if not ok:
            event["stage"] = stage
            event["detail"] = (detail or "")[:MAX_DETAIL]
            event["since"] = now.isoformat()
        elif prev.get("since"):
            event["since"] = prev["since"]
        append_finding(reports_dir, event)
    state = {"status": status, "account": account, "checked": now.isoformat()}
    if not ok:
        state["stage"] = stage
        state["since"] = prev.get("since") if prev.get("status") == "failed" else now.isoformat()
    _save(state_file, state)
    return event
