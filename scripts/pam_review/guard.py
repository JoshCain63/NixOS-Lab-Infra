"""LLM safety controls for pam-review (OWASP Top 10 for LLM Applications 2026).

- model_view():          send the model only the facts it needs (LLM02 data
                         minimisation), with local times so it doesn't misread
                         UTC (LLM07 misinformation).
- instruction_markers(): spot instruction-like text in attacker-influenced
                         identity data (LLM01 prompt injection). The scorer
                         turns hits into a deterministic score factor.
- ungrounded_claims():   addresses or target names the model mentions that
                         aren't in the facts it was given (LLM07).
- clean_output():        strip control characters from model text before it
                         goes anywhere (LLM10 improper output handling).

docs/llm-security.md maps every control to the OWASP list.
"""

import re
from datetime import datetime
from zoneinfo import ZoneInfo

LAB_TZ = ZoneInfo("America/Vancouver")  # same as score.LAB_TZ (no import: score uses this module)


def parse_time(value):
    if value is None:
        return None
    return value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))

# Instruction-like patterns. Real names, logins and department names never
# look like this; text that does is suspicious in itself.
INSTRUCTION_PATTERNS = {
    "ignore_instructions": r"\b(ignore|disregard|forget)\b.{0,40}\b(instruction|prompt|rule|above|previous)",
    "role_claim": r"\b(system|assistant|developer|admin(istrator)?)\s*(prompt|message|notice|note|override)\b",
    "verdict_steering": r"\b(verdict|risk[_ ]?score|benign|approved?|pre-?approved|whitelist(ed)?)\b",
    "persona": r"\b(you are|act as|pretend|roleplay)\b",
    "markup": r"</?\s*(session_facts|system|instructions?|im_start|im_end)\b|<\|",
    "json_breakout": r"[\"']\s*[}\]]|[{\[]\s*[\"']|\"\s*:\s*\"",
}
_COMPILED = {name: re.compile(p, re.IGNORECASE) for name, p in INSTRUCTION_PATTERNS.items()}

# Identity/target fields an attacker could influence (AD attributes via HR,
# Keycloak claims, Boundary descriptions).
UNTRUSTED_FIELDS = [
    ("user", "login_name"), ("user", "full_name"), ("user", "email"),
    ("target", "role"), ("target", "data_classification"),
]


def instruction_markers(facts):
    """Return [{"field": ..., "patterns": [...]}] for instruction-like identity text."""
    hits = []
    for section, key in UNTRUSTED_FIELDS:
        value = (facts.get(section) or {}).get(key)
        if isinstance(value, str) and value:
            matched = [name for name, rx in _COMPILED.items() if rx.search(value)]
            if matched:
                hits.append({"field": f"{section}.{key}", "patterns": matched})
    for dept in (facts.get("user") or {}).get("departments") or []:
        if isinstance(dept, str):
            matched = [name for name, rx in _COMPILED.items() if rx.search(dept)]
            if matched:
                hits.append({"field": "user.departments", "patterns": matched})
    return hits


def _local(ts):
    t = parse_time(ts)
    return t.astimezone(LAB_TZ).strftime("%Y-%m-%d %H:%M (%A)") if t else None


def model_view(facts):
    """The subset of session facts the model sees. Allowlist: anything not
    named here (ids, email, endpoints, internal state) never reaches it."""
    user = facts.get("user") or {}
    target = facts.get("target") or {}
    return {
        "user": {k: user.get(k) for k in ("login_name", "full_name", "departments", "auth_method")},
        "target": {k: target.get(k) for k in ("name", "risk", "tier", "role", "data_classification", "owners")},
        "start_local": _local(facts.get("start")),
        "end_local": _local(facts.get("end")),
        "timezone": "America/Vancouver",
        "status": facts.get("status"),
        "duration_seconds": facts.get("duration_seconds"),
        "client_addresses": facts.get("client_addresses") or [],
        "bytes_up": facts.get("bytes_up"),
        "bytes_down": facts.get("bytes_down"),
        "concurrent_targets": facts.get("concurrent_targets") or [],
        "history": facts.get("history") or {},
    }


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TARGET = re.compile(r"\blt\d{2}\b", re.IGNORECASE)


def ungrounded_claims(review, facts):
    """Addresses and target names in the model's text that aren't in its input."""
    text = " ".join([review.get("summary", ""), review.get("recommended_action", "")]
                    + list(review.get("reasons") or []))
    view = model_view(facts)
    known_ips = set(view["client_addresses"])
    known_targets = {t.lower() for t in [view["target"].get("name") or ""] + list(view["concurrent_targets"]) if t}
    claims = sorted({ip for ip in _IP.findall(text) if ip not in known_ips}
                    | {t.lower() for t in _TARGET.findall(text) if t.lower() not in known_targets})
    return claims


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_output(text, limit):
    """Model text made safe for logs, syslog lines, JSON and HTML consumers."""
    return _CONTROL.sub(" ", text).replace("\n", " ").strip()[:limit]


def ungrounded_task_claims(review, task_view):
    """Target names the reviewer mentions that aren't in the agent task record."""
    text = " ".join([review.get("summary", ""), review.get("recommended_action", "")]
                    + list(review.get("reasons") or []))
    known = {h.lower() for h in task_view.get("hosts_in_scope") or []}
    known |= {(c.get("host") or "").lower() for c in task_view.get("calls") or []}
    known |= {(p.get("host") or "").lower() for p in task_view.get("proposals") or []}
    return sorted({t.lower() for t in _TARGET.findall(text) if t.lower() not in known})
