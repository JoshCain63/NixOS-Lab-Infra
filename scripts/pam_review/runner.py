"""One review cycle: collect sessions, score them, LLM-review the risky ones."""

from datetime import datetime, timezone

from . import report
from .score import score_session

# A finished session is reviewed again only if its score rose this much
# since the review at start (e.g. it turned into a long, heavy session).
RESCORE_DELTA = 10

# Most model reviews per run. A flood of sessions (deliberate or not) can't
# monopolise the GPU; the rest wait for the next run (OWASP LLM: unbounded
# consumption). Scores and findings are never delayed, only the model review.
MAX_REVIEWS_PER_RUN = 10


def public(facts):
    """Facts without internal bookkeeping (keys starting with '_')."""
    return {k: v for k, v in facts.items() if not k.startswith("_")}


def run_once(collector, store, ollama, reports_dir, threshold, log=print,
             max_reviews=MAX_REVIEWS_PER_RUN, agent_accounts=(), agent_ledger=None, risk_by_host=None):
    sessions = collector.list_sessions()
    emitted = 0
    budget = max_reviews
    for summary in sessions:
        sid, status = summary["id"], summary.get("status")
        if store.db.execute("SELECT 1 FROM agent_sessions WHERE session_id = ?", (sid,)).fetchone():
            continue  # the agent's own session: reviewed per task, from its ledger
        prev = store.get_session(sid)
        if prev and prev["status"] == "terminated" and (
                prev["reviewed"] or (prev["score"] or 0) < threshold):
            continue  # finished and settled (reviewed, or never needed review)

        facts = collector.facts(sid, sessions)
        user_id, target_id = facts["user"]["id"], facts["target"]["id"]

        # The ops agent's sessions (one per tool call) aren't scored like a
        # person's: they're checked against its task ledger instead.
        if facts["user"].get("login_name") in agent_accounts:
            store.record_agent_session(sid, facts["user"]["login_name"], facts["target"]["name"])
            continue

        # History is decided once per session (first access) or once per new
        # client address, and carried forward so rescoring stays stable.
        if prev:
            history = prev["facts"]["history"]
            checked = prev["facts"].get("_checked_ips", [])
        else:
            history = {"first_access": store.record_access(user_id, target_id), "new_client_ip": False}
            checked = []
        new_ips = [ip for ip in facts["client_addresses"] if ip not in checked]
        if new_ips:
            history["new_client_ip"] = store.record_ips(user_id, new_ips) or history["new_client_ip"]
            checked = checked + new_ips
        facts["history"] = history
        facts["_checked_ips"] = checked

        result = score_session(public(facts), threshold)
        phase = "final" if status == "terminated" else "start"
        store.save_session(sid, status, facts, result["score"])

        review = None
        if result["needs_review"]:
            first_review = prev is None or not prev["reviewed"]
            grew = (phase == "final" and prev and prev["reviewed"] == "start"
                    and result["score"] >= (prev["review_score"] or 0) + RESCORE_DELTA)
            if (first_review or grew) and budget <= 0:
                # Over budget: retried next run. Logged once, not every run.
                if prev is None:
                    review = {"status": "deferred", "error": f"over the {max_reviews}-review budget for this run"}
                log(f"deferred review of {sid}: run budget of {max_reviews} used")
            elif first_review or grew:
                budget -= 1
                review = ollama.review(public(facts), result)
                if review["status"] == "ok":
                    store.mark_reviewed(sid, phase, result["score"])
                elif prev is not None:
                    review = None  # still unavailable: retry next run without a duplicate finding
                if review:
                    log(f"reviewed {sid} ({facts['user']['login_name']} -> {facts['target']['name']}): "
                        f"score {result['score']}, llm {review.get('verdict', review['status'])}")

        became_final = phase == "final" and (prev is None or prev["status"] != "terminated")
        if prev is None or became_final or review:
            if review is None and prev and prev.get("reviewed"):
                review = {"status": "see_earlier_review", "phase": prev["reviewed"]}
            elif review is None and result["needs_review"]:
                review = {"status": "pending", "error": "model review not done yet; retried next run"}
            # "event" lets the SIEM (Wazuh on wz01) match findings by rule.
            finding = {"event": "pam_review.finding", **public(facts)}
            finding.update({
                "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "phase": phase,
                "score": result,
                "llm": review or {"status": "not_required"},
            })
            report.append_finding(reports_dir, finding)
            emitted += 1

    if agent_ledger:
        from .agent_runner import run_agent
        emitted += run_agent(agent_ledger, store, ollama, reports_dir, threshold, risk_by_host or {},
                             log=log, budget=max(budget, 0))

    if emitted or not sessions:
        report.write_report(reports_dir, threshold)
    return emitted
