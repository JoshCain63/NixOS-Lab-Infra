"""Run one named-tool request on a target, through Boundary.

Each call is its own Boundary session with a fresh one-time password:
  1. authorize-session on <host>-agent (Boundary decides if the agent may
     reach that host at all; lt05 is denied),
  2. connect and send the request; the target's agent gate decides what runs.

Returns a CallResult with status:
  ok       the gate ran it
  refused  the gate refused it (not a permitted tool, bad args, approval...)
  denied   Boundary refused the session (out of scope / no grant)
  error    something else went wrong
"""

import json
import os
import subprocess
from dataclasses import dataclass, field


@dataclass
class CallResult:
    status: str
    output: str = ""
    reason: str = ""
    session_id: str = None
    gate: dict = field(default_factory=dict)


def _credentials(item):
    """Brokered username/password from an authorize-session response."""
    for cred in item.get("credentials") or []:
        c = cred.get("credential") or (cred.get("secret") or {}).get("decoded") or {}
        user, pw = c.get("username"), c.get("password") or c.get("key")
        if user and pw:
            return user, pw
    return None, None


class BoundaryExecutor:
    def __init__(self, cfg, token):
        self.cfg = cfg
        self.env = dict(os.environ, BOUNDARY_ADDR=cfg["boundary_addr"], BOUNDARY_TOKEN=token)
        if cfg.get("ca_file"):
            self.env["BOUNDARY_CACERT"] = cfg["ca_file"]

    def run(self, host, request):
        target = f"{host}-agent"
        p = subprocess.run(["boundary", "targets", "authorize-session", "-name", target,
                            "-scope-name", self.cfg["target_scope"], "-format", "json"],
                           capture_output=True, text=True, env=self.env, timeout=60)
        try:
            auth = json.loads(p.stdout or "{}")
        except json.JSONDecodeError:
            auth = {}
        item = auth.get("item") or {}
        if p.returncode != 0 or not item.get("authorization_token"):
            # Boundary said no: no grant (out of scope), unknown target, etc.
            detail = (p.stderr or p.stdout or "").strip().splitlines()
            return CallResult("denied", reason=(detail[-1] if detail else "authorize-session failed")[:300])

        user, otp = _credentials(item)
        if not user:
            return CallResult("error", reason="no brokered credential", session_id=item.get("session_id"))
        env = dict(self.env, SSHPASS=otp)
        cmd = ["boundary", "connect", "-authz-token", item["authorization_token"], "-exec", "sshpass", "--",
               "-e", "ssh", "-p", "{{boundary.port}}",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
               "-o", "PreferredAuthentications=keyboard-interactive",
               "-l", user, "{{boundary.ip}}", json.dumps(request, separators=(",", ":"))]
        c = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        del otp
        try:
            gate = json.loads(c.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return CallResult("error", reason=(c.stderr or "no response from gate")[:300],
                              session_id=item.get("session_id"))
        if gate.get("ok"):
            return CallResult("ok", output=str(gate.get("output", "")), session_id=item.get("session_id"), gate=gate)
        return CallResult("refused", reason=gate.get("refused", "refused"), output=gate.get("detail", ""),
                          session_id=item.get("session_id"), gate=gate)
