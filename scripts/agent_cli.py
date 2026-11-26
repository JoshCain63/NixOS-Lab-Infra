#!/usr/bin/env python3
"""Operator commands for the ops agent (run on the lab host).

    agent-task --host lt03 --question "Why is demo-app down?"
    agent-approvals list
    agent-approvals approve <request_id>
    agent-approvals deny <request_id>

Approving signs the exact proposed action {request_id, host, tool, args,
expires} with Vault transit key agent-approvals, using *your* Vault login
(OIDC, IT department). The target verifies that signature itself before
running anything, so this command can't be used to approve anything other
than what's on screen. Your name goes on the record either way.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_gate import approval_message  # noqa: E402  (same bytes the target verifies)

BASE = os.environ.get("AGENT_DIR", "/mnt/wd_blue/containers/ag01")
TASKS, PROPOSALS, APPROVALS = (os.path.join(BASE, d) for d in ("tasks", "proposals", "approvals"))
MAX_LIFETIME = 1800


def vault(*args):
    p = subprocess.run(["vault", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"vault {' '.join(args[:2])}: {p.stderr.strip() or p.stdout.strip()}\n"
                         "Log in first: vault login -method=oidc")
    return p.stdout.strip()


def whoami():
    """Who is approving: the Vault token's display name (e.g. oidc-dpatel)."""
    return json.loads(vault("token", "lookup", "-format=json"))["data"].get("display_name", "?")


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def load_proposal(rid):
    try:
        with open(os.path.join(PROPOSALS, f"{rid}.json")) as f:
            return json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"no proposal {rid}") from None


def cmd_task(a):
    task = {"task_id": "task-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6],
            "hosts": a.host, "question": a.question, "source": "manual",
            "expected_minutes": a.expected_minutes, "created": int(time.time()),
            "requested_by": os.environ.get("SUDO_USER") or os.environ.get("USER")}
    write_json(os.path.join(TASKS, f"{task['task_id']}.json"), task)
    print(f"queued {task['task_id']} for {', '.join(a.host)}")


def cmd_list(a):
    decided = {f[:-5] for f in os.listdir(APPROVALS) if f.endswith(".json")}
    pending = []
    for name in sorted(os.listdir(PROPOSALS)):
        if name.endswith(".json") and name[:-5] not in decided:
            with open(os.path.join(PROPOSALS, name)) as f:
                pending.append(json.load(f))
    if not pending:
        print("no pending proposals")
    # cmd_approve refuses anything already past its expiry, so showing an
    # expired proposal as "expires in 0 min" alongside live ones just wastes
    # the operator's time. Say so, and sort the still-approvable ones first.
    now = int(time.time())
    pending.sort(key=lambda p: (p["expires"] <= now, p["expires"]))
    for p in pending:
        left = p["expires"] - now
        when = f"expires in {left // 60} min" if left > 0 else "EXPIRED - can no longer be approved"
        print(f"{p['request_id']}  {p['host']}  {p['tool']} {json.dumps(p['args'])}\n"
              f"    reason: {p['reason']}\n    task: {p['task_id']}  {when}")


def cmd_approve(a):
    p = load_proposal(a.request_id)
    if os.path.exists(os.path.join(APPROVALS, f"{p['request_id']}.json")):
        raise SystemExit("already decided")
    expires = min(p["expires"], int(time.time()) + MAX_LIFETIME)
    if expires <= int(time.time()):
        raise SystemExit("proposal expired")
    print(f"Approving on {p['host']}: {p['tool']} {json.dumps(p['args'])}\n  reason: {p['reason']}")
    msg = approval_message(p["request_id"], p["host"], p["tool"], p["args"], expires)
    sig = vault("write", "-field=signature", "transit/sign/agent-approvals",
                f"input={base64.b64encode(msg).decode()}")
    write_json(os.path.join(APPROVALS, f"{p['request_id']}.json"), {
        "decision": "approved", "request_id": p["request_id"], "approver": whoami(),
        "expires": expires, "signature": sig, "decided_at": int(time.time())})
    print("approved: the agent will run it, and the target will verify your signature")


def cmd_deny(a):
    p = load_proposal(a.request_id)
    write_json(os.path.join(APPROVALS, f"{p['request_id']}.json"), {
        "decision": "denied", "request_id": p["request_id"], "approver": whoami(),
        "decided_at": int(time.time())})
    print("denied")


def main(argv=None):
    prog = os.path.basename(sys.argv[0])
    ap = argparse.ArgumentParser(prog=prog, description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("task", help="queue a task for the agent")
    t.add_argument("--host", action="append", required=True, help="host in scope (repeatable)")
    t.add_argument("--question", required=True)
    t.add_argument("--expected-minutes", type=int, default=5)
    sub.add_parser("list", help="pending proposals")
    for name in ("approve", "deny"):
        s = sub.add_parser(name)
        s.add_argument("request_id")
    a = ap.parse_args(argv)
    {"task": cmd_task, "list": cmd_list, "approve": cmd_approve, "deny": cmd_deny}[a.cmd](a)


if __name__ == "__main__":
    main()
