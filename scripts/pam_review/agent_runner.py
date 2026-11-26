"""Review the ops agent's tasks (from ag01's ledger) and check its sessions.

Two kinds of finding:
- pam_review.agent_task: one per finished task, scored by agent_score.py,
  model-reviewed when it scores at or above the threshold.
- pam_review.agent_unaccounted: a Boundary session by the agent account that
  no ledger entry explains. That means a tampered ledger, or the agent's
  credentials used outside the orchestrator. Scored critical-ish on its own.
"""

from datetime import datetime, timedelta, timezone

from ops_agent.ledger import read_tasks

from . import report
from .agent_score import headline, score_task, summarize, task_view
from .score import band

UNACCOUNTED_GRACE = timedelta(minutes=10)
UNACCOUNTED_POINTS = 50


def _now():
    return datetime.now(timezone.utc)


def run_agent(ledger_path, store, ollama, reports_dir, threshold, risk_by_host, log=print, budget=5, now=_now):
    tasks = read_tasks(ledger_path)
    emitted = 0
    ledger_sessions = set()

    for task_id, events in tasks.items():
        for e in events:
            if e.get("session_id"):
                ledger_sessions.add(e["session_id"])
        if not any(e.get("kind") == "task_end" for e in events):
            continue  # still running
        prev = store.get_agent_task(task_id)
        if prev and (prev["reviewed"] or (prev["score"] or 0) < threshold):
            continue

        task = summarize(events)
        result = score_task(task, risk_by_host, threshold)
        view = task_view(task)
        review = None
        if result["needs_review"]:
            if budget > 0:
                budget -= 1
                review = ollama.review(view, result, kind="agent_task")
                if review["status"] != "ok" and prev is not None:
                    review = None  # retry next run, no duplicate finding
            elif prev is None:
                review = {"status": "deferred", "error": "over the review budget for this run"}
        store.save_agent_task(task_id, result["score"], bool(review and review.get("status") == "ok"))

        if prev is None or review:
            report.append_finding(reports_dir, {
                "event": "pam_review.agent_task",
                "task_id": task_id,
                "account": task.get("account"),
                "hosts": task["hosts"],
                "status": task.get("status"),
                "headline": headline(task, result),
                "task": view,
                "evaluated_at": now().isoformat(timespec="seconds"),
                "score": result,
                "llm": review or {"status": "not_required"},
            })
            emitted += 1
            log(f"agent task {task_id}: score {result['score']} ({result['band']})")

    # Agent sessions Boundary saw but no ledger entry explains.
    for s in store.unflagged_agent_sessions():
        if s["session_id"] in ledger_sessions:
            store.flag_agent_session(s["session_id"], 2)  # accounted for
            continue
        first_seen = datetime.fromisoformat(s["first_seen"])
        if now() - first_seen < UNACCOUNTED_GRACE:
            continue  # the ledger may not have caught up yet
        host = (s["target"] or "").removesuffix("-agent")
        risk = risk_by_host.get(host) or 0
        total = min(100, UNACCOUNTED_POINTS + 10 * risk)
        factors = [{"factor": "unaccounted_session", "points": UNACCOUNTED_POINTS,
                    "detail": "no ledger entry for this agent session"}]
        if risk:
            factors.append({"factor": "target_risk", "points": 10 * risk, "detail": f"{host} is risk {risk}/5"})
        result = {"score": total, "band": band(total), "threshold": threshold,
                  "needs_review": total >= threshold, "factors": factors}
        report.append_finding(reports_dir, {
            "event": "pam_review.agent_unaccounted",
            "session_id": s["session_id"], "account": s["login"], "hosts": [host],
            "headline": f"{s['login']} session {s['session_id']} on {host}: not in the agent's ledger",
            "evaluated_at": now().isoformat(timespec="seconds"),
            "score": result, "llm": {"status": "not_required"},
        })
        store.flag_agent_session(s["session_id"], 1)
        emitted += 1
        log(f"unaccounted agent session {s['session_id']} on {host}")
    return emitted
