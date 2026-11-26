"""The named tools the model may call, as Ollama function schemas.

These mirror scripts/agent_gate.py. They're only a menu for the model:
nothing here grants anything. The target's gate decides what runs, and
Boundary decides which hosts the agent can reach.
"""

TIER1 = {"restart_service", "vacuum_journal", "truncate_log", "clear_tmp"}


def _fn(name, description, params=None, required=None):
    props = {"host": {"type": "string", "description": "Target host, e.g. lt03"}}
    props.update(params or {})
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": props,
                       "required": ["host"] + list(required or [])}}}


UNIT = {"unit": {"type": "string", "description": "systemd unit, e.g. demo-app.service"}}

TOOLS = [
    _fn("disk_usage", "Disk and inode usage."),
    _fn("largest_logs", "The ten largest files under /var/log."),
    _fn("memory_load", "Memory and load average."),
    _fn("service_status", "State of one systemd service.", UNIT, ["unit"]),
    _fn("journal_errors", "Recent warnings/errors from one service's journal.",
        dict(UNIT, hours={"type": "integer", "description": "1-24"}), ["unit"]),
    _fn("cert_expiry", "Expiry of the host's configured certificates."),
    _fn("time_sync", "Clock synchronisation status."),
    _fn("listening_ports", "Listening TCP ports compared with the expected baseline."),
    _fn("system_age", "NixOS version and age of the running system generation."),
    _fn("failed_logins", "Failed SSH logins: counts, sources and attempted usernames.",
        {"hours": {"type": "integer", "description": "1-168"}}),
    {"type": "function", "function": {
        "name": "propose_action",
        "description": ("Propose a change for a human to approve. Allowed actions: "
                        "restart_service {unit}, vacuum_journal {max_mb}, truncate_log {path}, clear_tmp {}. "
                        "Nothing changes until a human approves."),
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"},
            "action": {"type": "string", "enum": sorted(TIER1)},
            "args": {"type": "object"},
            "reason": {"type": "string"}},
            "required": ["host", "action", "args", "reason"]}}},
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS}
