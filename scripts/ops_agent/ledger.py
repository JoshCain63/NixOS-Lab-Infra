"""Append-only task ledger (JSON lines).

Written by the orchestrator (trusted code), never by the model. pam-review
scores tasks from it, and it's forwarded to Wazuh. Boundary's own event trail
and the targets' gate logs are independent copies of the same story, so a
tampered ledger shows up as sessions it doesn't account for.
"""

import json
import os
import time


class Ledger:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, task_id, kind, **fields):
        event = {"event": "ops_agent.ledger", "ts": round(time.time(), 3), "task_id": task_id,
                 "kind": kind, **fields}
        with open(self.path, "a") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
        return event


def read_tasks(path):
    """Group ledger events by task_id, in order."""
    tasks = {}
    if not os.path.exists(path):
        return tasks
    with open(path) as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            tasks.setdefault(e.get("task_id"), []).append(e)
    return tasks
