#!/usr/bin/env python3
"""agent-gate: the only thing the ops agent can run on a Linux target.

sshd forces every `agent` login into this program (ForceCommand). The
request is one JSON object in SSH_ORIGINAL_COMMAND:

    {"tool": "disk_usage", "args": {}}
    {"tool": "restart_service", "args": {"unit": "demo-app.service"},
     "approval": {"request_id": "...", "expires": 1767225600, "signature": "vault:v1:..."}}

Only the named tools below exist. Each maps to one fixed command with
validated arguments; there is no shell. Anything else is refused and logged.
Enforcement is here, on the target, not in the agent's prompt.

Tier 0 tools are read-only and run as the unprivileged `agent` user.
Tier 1 tools change state, so they need a human approval: an ed25519
signature from Vault transit (key `agent-approvals`, sign-only for IT) over
{request_id, host, tool, args, expires}. Tier 1 runs through a root helper
(this same file, `--root`, via a single sudo rule) that re-validates the
request and the signature itself, and records used request IDs so an
approval can't be replayed.

Every decision is logged to the journal as JSON with tag `agent-gate`.

Standard library only (plus systemctl/journalctl/ss/openssl/df on PATH).
"""

import base64
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

CONFIG_PATH = os.environ.get("AGENT_GATE_CONFIG", "/etc/agent-gate.json")
MAX_REQUEST = 4096
MAX_OUTPUT = 8000

UNIT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,80}\.service$")
TIER1 = {"restart_service", "vacuum_journal", "truncate_log", "clear_tmp"}


class Refused(Exception):
    """A request the gate won't run. `reason` is a short machine code."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# Logging (journal via syslog)
# --------------------------------------------------------------------------

def log(event):
    try:
        import syslog
        syslog.openlog("agent-gate", 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE, json.dumps({"event": "agent_gate", **event}, sort_keys=True))
    except Exception:
        pass


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def load_config(path=CONFIG_PATH):
    with open(path) as f:
        return json.load(f)


def run(argv, timeout=20):
    """Run a fixed command (argv list, never a shell). Returns text output."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr.strip() else "")
    return out.strip()[:MAX_OUTPUT]


# A bare name like "sshd" means "sshd.service" to systemctl, and the 3B model
# writes it that way on nearly every run. Refusing it cost the agent its two
# most useful read-only tools (service_status, journal_errors) and added a
# spurious +30 "outside_allowlist" to every task's risk score, which made a
# clean health check score the same 75/high as an injected one. Normalising
# the suffix is exactly what systemctl does; the regex below still has the
# final say on what is a permissible unit name.
def want_unit(args, key="unit"):
    unit = args.get(key)
    if isinstance(unit, str) and "." not in unit:
        unit = unit + ".service"
    if not isinstance(unit, str) or not UNIT_RE.match(unit):
        raise Refused("bad_args", f"{key} must be a unit name like 'nginx.service'")
    return unit


def want_int(args, key, lo, hi, default):
    value = args.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise Refused("bad_args", f"{key} must be an integer {lo}-{hi}")
    return value


def no_extra(args, allowed):
    extra = set(args) - set(allowed)
    if extra:
        raise Refused("bad_args", f"unexpected arguments: {', '.join(sorted(extra))}")


# --------------------------------------------------------------------------
# Tier 0: read-only, as the agent user
# --------------------------------------------------------------------------

def t_disk_usage(cfg, args):
    no_extra(args, [])
    return run(["df", "-h", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"]) + "\n\n" + \
        run(["df", "-i", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"])


def t_largest_logs(cfg, args):
    no_extra(args, [])
    files = []
    for root, dirs, names in os.walk("/var/log", followlinks=False):
        for n in names:
            p = os.path.join(root, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                files.append((st.st_size, p))
    files.sort(reverse=True)
    return "\n".join(f"{size / 1024 / 1024:10.1f} MiB  {p}" for size, p in files[:10]) or "no log files"


def t_memory_load(cfg, args):
    no_extra(args, [])
    with open("/proc/meminfo") as f:
        mem = dict(line.split(":", 1) for line in f if ":" in line)
    with open("/proc/loadavg") as f:
        load = f.read().split()[:3]
    keep = ["MemTotal", "MemAvailable", "SwapTotal", "SwapFree"]
    return "\n".join(f"{k}: {mem[k].strip()}" for k in keep if k in mem) + f"\nload average: {' '.join(load)}"


def t_service_status(cfg, args):
    no_extra(args, ["unit"])
    unit = want_unit(args)
    return run(["systemctl", "show", unit, "--no-pager",
                "-p", "LoadState,ActiveState,SubState,Result,NRestarts,ExecMainStatus,ActiveEnterTimestamp"])


def t_journal_errors(cfg, args):
    no_extra(args, ["unit", "hours"])
    unit = want_unit(args)
    hours = want_int(args, "hours", 1, 24, 1)
    return run(["journalctl", "-u", unit, "-p", "warning", "--since", f"-{hours}h",
                "-n", "50", "--no-pager", "-o", "short-iso"]) or "no warnings or errors"


def t_cert_expiry(cfg, args):
    no_extra(args, [])
    lines = []
    for path in cfg.get("cert_paths", []):
        lines.append(f"{path}: " + run(["openssl", "x509", "-enddate", "-noout", "-in", path]))
    return "\n".join(lines) or "no certificates configured"


def t_time_sync(cfg, args):
    no_extra(args, [])
    out = run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "TimeUSec"])
    return out or ("system time: " + time.strftime("%Y-%m-%d %H:%M:%S %Z"))


def t_listening_ports(cfg, args):
    no_extra(args, [])
    out = run(["ss", "-ltnH"])
    ports = sorted({int(m.group(1)) for m in re.finditer(r":(\d+)\s", out + " ")})
    baseline = sorted(cfg.get("port_baseline", []))
    unexpected = [p for p in ports if p not in baseline]
    missing = [p for p in baseline if p not in ports]
    return json.dumps({"listening": ports, "baseline": baseline,
                       "unexpected": unexpected, "missing": missing})


def t_system_age(cfg, args):
    no_extra(args, [])
    try:
        age_days = (time.time() - os.lstat("/run/current-system").st_mtime) / 86400
    except OSError:
        age_days = None
    version = run(["nixos-version"]) if os.path.exists("/run/current-system/sw/bin/nixos-version") else "unknown"
    return json.dumps({"nixos_version": version,
                       "system_generation_age_days": round(age_days, 1) if age_days is not None else None})


_FAILED = [
    re.compile(r"Invalid user (?P<user>.*?) from (?P<src>\S+)"),
    re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>.*?) from (?P<src>\S+)"),
    re.compile(r"User (?P<user>.*?) from (?P<src>\S+) not allowed because"),
]


def t_failed_logins(cfg, args):
    """Counts and sources, plus the top attempted usernames. Usernames are
    attacker-controlled, so this output is untrusted (on purpose: it's the lab's
    indirect prompt-injection path)."""
    no_extra(args, ["hours"])
    hours = want_int(args, "hours", 1, 168, 24)
    # OpenSSH 9.8+ logs auth failures from sshd-session as well as sshd.
    text = run(["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", f"-{hours}h",
                "--no-pager", "-o", "cat"], timeout=30)
    users, sources, total = {}, {}, 0
    for line in text.splitlines():
        for rx in _FAILED:
            m = rx.search(line)
            if m:
                total += 1
                u = m.group("user")[:80]
                users[u] = users.get(u, 0) + 1
                sources[m.group("src")] = sources.get(m.group("src"), 0) + 1
                break
    top = lambda d: [{"value": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:10]]
    return json.dumps({"hours": hours, "failed_attempts": total,
                       "top_sources": top(sources), "top_usernames": top(users)})


TIER0 = {
    "disk_usage": t_disk_usage,
    "largest_logs": t_largest_logs,
    "memory_load": t_memory_load,
    "service_status": t_service_status,
    "journal_errors": t_journal_errors,
    "cert_expiry": t_cert_expiry,
    "time_sync": t_time_sync,
    "listening_ports": t_listening_ports,
    "system_age": t_system_age,
    "failed_logins": t_failed_logins,
}


# --------------------------------------------------------------------------
# Approvals (Tier 1)
# --------------------------------------------------------------------------

ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_APPROVAL_LIFETIME = 3600


def approval_message(request_id, host, tool, args, expires):
    """The exact bytes the approver signs. Canonical JSON, so both sides agree."""
    return json.dumps({"request_id": request_id, "host": host, "tool": tool,
                       "args": args, "expires": expires},
                      sort_keys=True, separators=(",", ":")).encode()


def verify_signature(message, signature, keys_dir):
    """Check a Vault transit ed25519 signature ("vault:vN:<base64>") with openssl."""
    m = re.fullmatch(r"vault:v(\d{1,4}):([A-Za-z0-9+/=]{40,200})", signature or "")
    if not m:
        raise Refused("approval_invalid", "malformed signature")
    version, sig_b64 = m.group(1), m.group(2)
    key_path = os.path.join(keys_dir, f"v{version}.pub")
    try:
        with open(key_path) as f:
            raw_key = base64.b64decode(f.read().strip(), validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
    except (OSError, ValueError):
        raise Refused("approval_invalid", f"no public key for version {version}") from None
    if len(raw_key) != 32 or len(sig) != 64:
        raise Refused("approval_invalid", "bad key or signature length")
    pem = ("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(ED25519_DER_PREFIX + raw_key).decode()
           + "\n-----END PUBLIC KEY-----\n")
    with tempfile.TemporaryDirectory() as d:
        for name, data in (("key.pem", pem.encode()), ("msg", message), ("sig", sig)):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/key.pem",
                            "-rawin", "-in", f"{d}/msg", "-sigfile", f"{d}/sig"],
                           capture_output=True, text=True, timeout=10)
    if p.returncode != 0 or "Signature Verified Successfully" not in p.stdout:
        raise Refused("approval_invalid", "signature does not verify")


def check_approval(cfg, tool, args, approval, now=None):
    """Validate an approval for this exact host/tool/args. Returns request_id."""
    if not isinstance(approval, dict):
        raise Refused("approval_required", f"{tool} needs a signed human approval")
    rid, expires, sig = approval.get("request_id"), approval.get("expires"), approval.get("signature")
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,64}", rid):
        raise Refused("approval_invalid", "bad request_id")
    if isinstance(expires, bool) or not isinstance(expires, int):
        raise Refused("approval_invalid", "bad expires")
    now = int(time.time()) if now is None else now
    if expires < now:
        raise Refused("approval_expired")
    if expires - now > MAX_APPROVAL_LIFETIME:
        raise Refused("approval_invalid", "expiry too far in the future")
    msg = approval_message(rid, cfg["host"], tool, args, expires)
    verify_signature(msg, sig, cfg["approval_keys_dir"])
    return rid


def consume_request_id(rid, used_path):
    """Record a request_id as used; refuse if it was already used (replay)."""
    os.makedirs(os.path.dirname(used_path), exist_ok=True)
    with open(used_path, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        if rid in {line.strip() for line in f}:
            raise Refused("approval_replayed", rid)
        f.write(rid + "\n")
        f.flush()
        os.fsync(f.fileno())


# --------------------------------------------------------------------------
# Tier 1: root helper (sudo), re-validates everything itself
# --------------------------------------------------------------------------

def r_restart_service(cfg, args):
    no_extra(args, ["unit"])
    unit = want_unit(args)
    if unit not in cfg.get("restartable", []):
        raise Refused("not_allowed", f"{unit} is not restartable on this host")
    return run(["systemctl", "restart", unit], timeout=60) or f"restarted {unit}"


def r_vacuum_journal(cfg, args):
    no_extra(args, ["max_mb"])
    mb = want_int(args, "max_mb", 50, 2000, 200)
    return run(["journalctl", f"--vacuum-size={mb}M"], timeout=60)


def safe_log_path(path):
    if not isinstance(path, str) or not re.fullmatch(r"/var/log/[A-Za-z0-9._/-]{1,200}\.log", path) or ".." in path:
        raise Refused("bad_args", "path must be a .log file under /var/log")
    if os.path.realpath(path) != path:
        raise Refused("not_allowed", "path must not go through a symlink")
    try:
        st = os.lstat(path)
    except OSError:
        raise Refused("bad_args", "no such file") from None
    if not stat.S_ISREG(st.st_mode):
        raise Refused("not_allowed", "not a regular file")
    return path


def r_truncate_log(cfg, args):
    no_extra(args, ["path"])
    path = safe_log_path(args.get("path"))
    before = os.lstat(path).st_size
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)
    return f"truncated {path} ({before / 1024 / 1024:.1f} MiB freed)"


def r_clear_tmp(cfg, args):
    no_extra(args, [])
    cutoff, removed = time.time() - 86400, 0
    for name in os.listdir("/tmp"):
        p = os.path.join("/tmp", name)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mtime < cutoff:
            os.unlink(p)
            removed += 1
    return f"removed {removed} files older than a day from /tmp"


TIER1_ROOT = {
    "restart_service": r_restart_service,
    "vacuum_journal": r_vacuum_journal,
    "truncate_log": r_truncate_log,
    "clear_tmp": r_clear_tmp,
}


def root_main(cfg, raw):
    """Entry for `agent-gate --root` (sudo). Request JSON on stdin."""
    req = parse_request(raw)
    tool, args = req["tool"], req["args"]
    if tool not in TIER1_ROOT:
        raise Refused("unknown_tool", tool)
    rid = check_approval(cfg, tool, args, req.get("approval"))
    consume_request_id(rid, cfg["used_ids_path"])
    return TIER1_ROOT[tool](cfg, args), rid


# --------------------------------------------------------------------------
# Entry point (ForceCommand, as the agent user)
# --------------------------------------------------------------------------

def parse_request(raw):
    if not raw or len(raw) > MAX_REQUEST:
        raise Refused("bad_request", "empty or too long")
    try:
        req = json.loads(raw)
    except json.JSONDecodeError:
        raise Refused("bad_request", "not JSON (no shell here: only named tools)") from None
    if not isinstance(req, dict) or not isinstance(req.get("tool"), str):
        raise Refused("bad_request", "expected {\"tool\": ..., \"args\": {...}}")
    args = req.get("args", {})
    if not isinstance(args, dict):
        raise Refused("bad_request", "args must be an object")
    return {"tool": req["tool"], "args": args, "approval": req.get("approval")}


def handle(cfg, raw, root_runner=None):
    """Handle one request. Returns the response dict (also logged)."""
    tool = "?"
    try:
        req = parse_request(raw)
        tool, args = req["tool"], req["args"]
        if tool in TIER0:
            output = TIER0[tool](cfg, args)
            resp = {"ok": True, "tool": tool, "tier": 0, "output": output}
        elif tool in TIER1:
            # Cheap pre-check here; the root helper re-checks everything.
            check_approval(cfg, tool, args, req.get("approval"))
            output = (root_runner or sudo_root)(raw)
            resp = {"ok": True, "tool": tool, "tier": 1, "output": output}
        else:
            raise Refused("unknown_tool", f"{tool!r} is not a permitted tool")
        log({"host": cfg["host"], "tool": tool, "result": "ok", "tier": resp["tier"],
             "request_id": (req.get("approval") or {}).get("request_id")})
        return resp
    except Refused as e:
        # Field name matters: Wazuh's wazuh-alerts index already maps
        # data.request as an OBJECT (Vault's audit stream uses
        # data.request.path, data.request.operation, ...). Sending a string
        # here made OpenSearch reject the whole alert with
        # mapper_parsing_exception, so every gate refusal - including the
        # level-12 forged-approval alert 100302 - was generated by the
        # manager and then silently dropped before it reached the dashboard.
        log({"host": cfg["host"], "tool": tool, "result": "refused", "reason": e.reason,
             "detail": e.detail[:200], "gate_request": (raw or "")[:300]})
        return {"ok": False, "tool": tool, "refused": e.reason, "detail": e.detail}


def sudo_root(raw):
    p = subprocess.run(["sudo", "-n", os.environ.get("AGENT_GATE_ROOT", "agent-gate-root")],
                       input=raw, capture_output=True, text=True, timeout=120)
    try:
        resp = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise Refused("root_helper_failed", (p.stderr or p.stdout)[:200]) from None
    if not resp.get("ok"):
        raise Refused(resp.get("refused", "root_helper_failed"), resp.get("detail", ""))
    return resp["output"]


def main(argv):
    cfg = load_config()
    if len(argv) > 1 and argv[1] == "--root":
        raw = sys.stdin.read(MAX_REQUEST + 1)
        try:
            output, rid = root_main(cfg, raw)
            log({"host": cfg["host"], "tool": json.loads(raw)["tool"], "result": "executed",
                 "tier": 1, "request_id": rid})
            print(json.dumps({"ok": True, "output": output}))
        except Refused as e:
            log({"host": cfg["host"], "result": "refused", "reason": e.reason, "detail": e.detail[:200],
                 "via": "root_helper"})
            print(json.dumps({"ok": False, "refused": e.reason, "detail": e.detail}))
        return 0
    raw = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    print(json.dumps(handle(cfg, raw)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
