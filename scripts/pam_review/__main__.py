"""pam-review: AI-assisted review of privileged sessions brokered by Boundary.

    python3 -m pam_review run     # one cycle: collect, score, review, report
    python3 -m pam_review report  # rebuild the HTML report from findings
    python3 -m pam_review eval    # labelled scenarios -> metrics JSON

Run with scripts/ on PYTHONPATH (the systemd unit on ai01 does this).
"""

import argparse
import json
import os
import sys

from boundary_api import Boundary, BoundaryError, read_password
from nhi_identity import AgentIdentity, IdentityError

from . import auth_status, report
from .collect import Collector
from .eval import evaluate, load_targets
from .llm import Ollama
from .runner import run_once
from .score import DEFAULT_THRESHOLD
from .store import Store
from .vault_cred import read_credential


def main(argv=None):
    p = argparse.ArgumentParser(prog="pam-review", description=__doc__.splitlines()[0])
    p.add_argument("command", choices=["run", "report", "eval"])
    p.add_argument("--boundary-addr", default=os.environ.get("BOUNDARY_ADDR", "https://hb01.lab.internal"))
    p.add_argument("--ca", default=os.environ.get("BOUNDARY_CACERT"))
    p.add_argument("--identity", default=os.environ.get("PAM_REVIEW_IDENTITY"),
                   help="JSON config for the governed NHI login (svc-pam-review: Keycloak -> Vault -> "
                        "Boundary LDAP); the Keycloak client secret comes from $CREDENTIALS_DIRECTORY/client_secret")
    p.add_argument("--auth-state", default="/var/lib/pam-review/auth-status.json",
                   help="last login result, so only changes are reported to the SOC")
    p.add_argument("--login", default="pam-reviewer")
    p.add_argument("--password-file", help="Boundary password file (instead of Vault)")
    p.add_argument("--vault-addr", default=os.environ.get("VAULT_ADDR"),
                   help="read the Boundary credential from Vault (AppRole) instead of a file")
    p.add_argument("--vault-cacert", default=os.environ.get("VAULT_CACERT"))
    p.add_argument("--vault-path", default="secret/data/boundary/pam-reviewer")
    p.add_argument("--role-id-file", help="default: $CREDENTIALS_DIRECTORY/role_id")
    p.add_argument("--secret-id-file", help="default: $CREDENTIALS_DIRECTORY/secret_id")
    p.add_argument("--ollama", default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    p.add_argument("--model", default=os.environ.get("PAM_REVIEW_MODEL", "lab-qwen2.5-3b"))
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    p.add_argument("--state", default="/var/lib/pam-review/state.db")
    p.add_argument("--reports", default="/var/lib/pam-review/reports")
    p.add_argument("--targets", default="/var/lib/boundary-export/target-risk.json",
                   help="eval: target risk export from hb01")
    p.add_argument("-o", "--output", help="eval: write results JSON here")
    p.add_argument("--agent-ledger", default=os.environ.get("PAM_REVIEW_AGENT_LEDGER"),
                   help="ops agent task ledger (ag01) to review")
    p.add_argument("--agent-accounts", default=os.environ.get("PAM_REVIEW_AGENT_ACCOUNTS", "svc-agent-ops"),
                   help="comma-separated Boundary logins that are agents, not people")
    args = p.parse_args(argv)

    os.makedirs(args.reports, exist_ok=True)
    ollama = Ollama(args.ollama, args.model)

    try:
        if args.command == "report":
            report.write_report(args.reports, args.threshold)
        elif args.command == "eval":
            doc = evaluate(ollama, load_targets(args.targets), args.threshold)
            print(json.dumps(doc["metrics"], indent=2))
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(doc, f, indent=2)
        else:
            ident = None
            if args.identity:
                ident = governed_login(args)
                if ident is None:
                    return 1
                client = ident.boundary
            else:
                client = legacy_login(args)
            store = Store(args.state)
            try:
                risk_by_host = {}
                if args.agent_ledger and os.path.exists(args.targets):
                    risk_by_host = {n: t["risk"] for n, t in load_targets(args.targets).items()
                                    if not n.endswith("-agent") and t.get("risk")}
                n = run_once(Collector(client), store, ollama, args.reports, args.threshold,
                             agent_accounts={a.strip() for a in args.agent_accounts.split(",") if a.strip()},
                             agent_ledger=args.agent_ledger, risk_by_host=risk_by_host)
            finally:
                store.close()
                if ident:
                    ident.close()
                else:
                    client.logout()
            print(f"pam-review: {n} new findings")
    except (BoundaryError, OSError, ValueError) as e:
        print(f"pam-review: {e}", file=sys.stderr)
        return 1
    return 0


def legacy_login(args):
    """Boundary-local pam-reviewer account (before the NHI is set up)."""
    if args.vault_addr and not args.password_file:
        creds = os.environ.get("CREDENTIALS_DIRECTORY", "")
        login, password = read_credential(
            args.vault_addr,
            args.role_id_file or os.path.join(creds, "role_id"),
            args.secret_id_file or os.path.join(creds, "secret_id"),
            args.vault_path, cafile=args.vault_cacert)
    else:
        login, password = args.login, read_password(args.password_file)
    client = Boundary(args.boundary_addr, cafile=args.ca)
    client.login(client.auth_method("password"), login, password)
    del password
    return client


def governed_login(args):
    """Log in as the governed NHI (svc-pam-review), the same chain as the ops
    agent. Returns the identity (logged in to Boundary) or None if it failed;
    a change in login state is written to the findings log for the SOC."""
    with open(args.identity) as f:
        cfg = json.load(f)  # a broken config is an OSError/ValueError, not a login failure
    creds = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds and "client_secret" not in cfg:
        with open(os.path.join(creds, "client_secret")) as f:
            cfg["client_secret"] = f.read().strip()
    ident = AgentIdentity(cfg)
    try:
        ident.establish()
    except IdentityError as e:
        ident.close()
        auth_status.record(args.reports, args.auth_state, cfg["account"], False, e.stage, e.detail)
        print(f"pam-review: login as {cfg['account']} failed at {e.stage}: {e.detail}", file=sys.stderr)
        return None
    ident.release_vault()  # only needed for the password
    auth_status.record(args.reports, args.auth_state, cfg["account"], True)
    return ident


if __name__ == "__main__":
    sys.exit(main())
