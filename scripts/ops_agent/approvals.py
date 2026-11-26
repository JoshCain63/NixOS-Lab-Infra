"""Proposals and approvals (files on ag01's state folder on the drive).

The agent writes proposals/<request_id>.json. A human on the host runs
`agent-approvals approve <id>`, which signs the exact action with Vault
transit (IT only) and writes approvals/<id>.json; or `deny <id>`, which
writes a denial. The target verifies the signature itself; this module only
moves files.
"""

import json
import os
import time
import uuid


def new_request_id():
    return "req-" + uuid.uuid4().hex[:16]


class Approvals:
    def __init__(self, proposals_dir, approvals_dir, ttl=1800):
        self.proposals = proposals_dir
        self.approvals = approvals_dir
        self.ttl = ttl
        os.makedirs(self.proposals, exist_ok=True)
        os.makedirs(self.approvals, exist_ok=True)

    def propose(self, task_id, host, tool, args, reason):
        rid = new_request_id()
        proposal = {"request_id": rid, "task_id": task_id, "host": host, "tool": tool, "args": args,
                    "reason": reason[:500], "created": int(time.time()),
                    "expires": int(time.time()) + self.ttl}
        tmp = os.path.join(self.proposals, f".{rid}.tmp")
        with open(tmp, "w") as f:
            json.dump(proposal, f, indent=2, sort_keys=True)
        os.replace(tmp, os.path.join(self.proposals, f"{rid}.json"))
        return proposal

    def wait(self, request_id, timeout, poll=5, sleep=time.sleep):
        """Return ("approved", approval) / ("denied", record) / ("timeout", None)."""
        path = os.path.join(self.approvals, f"{request_id}.json")
        deadline = time.time() + timeout
        while True:
            if os.path.exists(path):
                with open(path) as f:
                    record = json.load(f)
                return ("approved" if record.get("decision") == "approved" else "denied"), record
            if time.time() >= deadline:
                return "timeout", None
            sleep(poll)
