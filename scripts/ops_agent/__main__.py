"""ops-agent: governed ops assistant (ag01).

    python3 -m ops_agent run-queue   # run every task file waiting in the queue
    python3 -m ops_agent sweep       # queue a Tier 0 health check of each in-scope host

Configuration: /etc/ops-agent.json (non-secret) plus the Keycloak client
secret from $CREDENTIALS_DIRECTORY/client_secret (systemd LoadCredential).
"""

import json
import os
import sys
import time
import uuid

from .approvals import Approvals
from .executor import BoundaryExecutor
from .identity import AgentIdentity, IdentityError
from .ledger import Ledger
from .orchestrator import OllamaChat, run_task

CONFIG = os.environ.get("OPS_AGENT_CONFIG", "/etc/ops-agent.json")


def load_config():
    with open(CONFIG) as f:
        cfg = json.load(f)
    creds = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds:
        with open(os.path.join(creds, "client_secret")) as f:
            cfg["client_secret"] = f.read().strip()
    return cfg


def new_task(hosts, question, source, expected_minutes=5):
    return {"task_id": "task-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6],
            "hosts": hosts, "question": question, "source": source,
            "expected_minutes": expected_minutes, "created": int(time.time())}


def queue_task(cfg, task):
    path = os.path.join(cfg["tasks_dir"], f"{task['task_id']}.json")
    with open(path + ".tmp", "w") as f:
        json.dump(task, f, indent=2)
    os.replace(path + ".tmp", path)
    return path


def execute(cfg, task, ledger):
    ledger.write(task["task_id"], "task_start", hosts=task["hosts"], question=task["question"][:500],
                 source=task.get("source", "manual"), expected_minutes=task.get("expected_minutes", 5),
                 account=cfg["account"])
    ident = AgentIdentity(cfg)
    try:
        try:
            boundary = ident.establish()
        except IdentityError as e:
            # e.g. the AD account is disabled: sponsor left or the agent expired.
            ledger.write(task["task_id"], "task_end", status="auth_failed", stage=e.stage,
                         detail=e.detail[:300], calls=0, proposals=0, seconds=0, report="")
            return "auth_failed"
        status, _ = run_task(
            task,
            OllamaChat(cfg["ollama_url"], cfg["model"]),
            BoundaryExecutor(cfg, boundary.token),
            ledger,
            Approvals(cfg["proposals_dir"], cfg["approvals_dir"]),
            approval_timeout=cfg.get("approval_timeout", 1800),
        )
        return status
    finally:
        ident.close()


def main(argv):
    cfg = load_config()
    ledger = Ledger(cfg["ledger"])
    cmd = argv[1] if len(argv) > 1 else "run-queue"
    if cmd == "sweep":
        for host in cfg["sweep_hosts"]:
            queue_task(cfg, new_task([host], "Routine health check: disk, memory, services, time sync, "
                                     "listening ports and failed logins. Report anything unusual.",
                                     "schedule", expected_minutes=5))
        return 0
    if cmd == "run-queue":
        for name in sorted(os.listdir(cfg["tasks_dir"])):
            if not name.endswith(".json"):
                continue
            path = os.path.join(cfg["tasks_dir"], name)
            with open(path) as f:
                task = json.load(f)
            os.rename(path, path + ".running")
            status = execute(cfg, task, ledger)
            os.rename(path + ".running", os.path.join(cfg["tasks_dir"], f"{name}.{status}"))
            print(f"{task['task_id']}: {status}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
