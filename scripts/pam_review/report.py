"""Findings log (NDJSON) and a static HTML report for the analyst."""

import html
import json
import os
import tempfile
from datetime import datetime

from .score import LAB_TZ, parse_time

FINDINGS = "findings.ndjson"
REPORT = "index.html"


def append_finding(reports_dir, finding):
    with open(os.path.join(reports_dir, FINDINGS), "a") as f:
        f.write(json.dumps(finding) + "\n")


def load_findings(reports_dir, limit=1000):
    path = os.path.join(reports_dir, FINDINGS)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = f.readlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def latest_per_session(findings):
    """Keep the newest finding for each session (start -> final), carrying the
    last LLM review forward when the newest finding didn't need a new one."""
    latest, last_review = {}, {}
    for f in findings:
        if f.get("event", "pam_review.finding") != "pam_review.finding":
            continue  # agent findings are listed separately
        sid = f["session_id"]
        if (f.get("llm") or {}).get("status") in ("ok", "unavailable"):
            last_review[sid] = f["llm"]
        elif sid in last_review and (f.get("llm") or {}).get("status") == "see_earlier_review":
            f = dict(f, llm=last_review[sid])
        latest[sid] = f
    return sorted(latest.values(), key=lambda f: f.get("start") or "", reverse=True)


def _local(ts):
    t = parse_time(ts)
    return t.astimezone(LAB_TZ).strftime("%Y-%m-%d %H:%M %a") if t else "-"


def _e(value):
    return html.escape("" if value is None else str(value))


CSS = """
:root { --bg:#fff; --fg:#1b1f24; --muted:#5b6470; --line:#d8dde3; --card:#f6f8fa;
        --low:#2e7d32; --medium:#9a6700; --high:#c2410c; --critical:#b91c1c; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f1216; --fg:#e6e9ed; --muted:#9aa4af; --line:#2a313a; --card:#161b21;
          --low:#5fbf66; --medium:#d4a72c; --high:#f08c4a; --critical:#f26d6d; } }
body { background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,sans-serif; margin:0; padding:24px 16px; }
main { max-width:1100px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; } .muted { color:var(--muted); }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 16px; margin:12px 0; }
.head { display:flex; flex-wrap:wrap; gap:8px 16px; align-items:baseline; }
.badge { font-weight:600; border:1px solid currentColor; border-radius:999px; padding:0 8px; font-size:13px; }
.low{color:var(--low)} .medium{color:var(--medium)} .high{color:var(--high)} .critical{color:var(--critical)}
.cols { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:8px; }
@media (max-width:700px) { .cols { grid-template-columns:1fr; } }
ul { margin:4px 0; padding-left:18px; } h3 { font-size:14px; margin:6px 0 2px; }
table { border-collapse:collapse; width:100%; font-size:14px; } th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
.scroll { overflow-x:auto; }
"""


def _review_card(f):
    llm = f.get("llm") or {}
    sc = f["score"]
    user = f.get("user") or {}
    target = f.get("target") or {}
    factors = "".join(f"<li>+{_e(x['points'])} {_e(x['factor'])}: {_e(x['detail'])}</li>" for x in sc["factors"])
    if llm.get("status") == "ok":
        reasons = "".join(f"<li>{_e(r)}</li>" for r in llm["reasons"])
        flag = (" <span class='badge critical'>model cleared a critical session</span>"
                if llm.get("disagrees_with_score") else "")
        llm_html = (f"<h3>LLM verdict: <span class='badge'>{_e(llm['verdict'])}</span>{flag}</h3>"
                    f"<p>{_e(llm['summary'])}</p><ul>{reasons}</ul>"
                    f"<p><b>Recommended:</b> {_e(llm['recommended_action'])}</p>"
                    f"<p class='muted'>{_e(llm['model'])}, {_e(llm['latency_seconds'])}s</p>")
    else:
        llm_html = f"<h3>LLM review unavailable</h3><p class='muted'>{_e(llm.get('error'))}</p>"
    return f"""
<div class="card">
  <div class="head">
    <span class="badge {sc['band']}">{sc['score']} {sc['band']}</span>
    <b>{_e(user.get('login_name'))}</b>
    <span class="muted">{_e(', '.join(user.get('departments') or []) or user.get('auth_method'))}</span>
    <span>&rarr; <b>{_e(target.get('name'))}</b> <span class="muted">{_e(target.get('role'))}</span></span>
    <span class="muted">{_e(_local(f.get('start')))} &middot; {_e(f.get('status'))} &middot; {_e(f['session_id'])}</span>
  </div>
  <div class="cols">
    <div><h3>Why it scored {sc['score']}</h3><ul>{factors}</ul></div>
    <div>{llm_html}</div>
  </div>
</div>"""


def latest_agent_findings(findings):
    """Newest finding per agent task / unaccounted session, newest first."""
    latest = {}
    for f in findings:
        if f.get("event") in ("pam_review.agent_task", "pam_review.agent_unaccounted"):
            latest[f.get("task_id") or f.get("session_id")] = f
    return sorted(latest.values(), key=lambda f: f.get("evaluated_at") or "", reverse=True)


def _agent_card(f):
    sc, llm = f["score"], f.get("llm") or {}
    factors = "".join(f"<li>+{_e(x['points'])} {_e(x['factor'])}: {_e(x['detail'])}</li>" for x in sc["factors"])
    calls = "".join(
        f"<li>{_e(c.get('host'))}: {_e(c.get('tool'))} &rarr; <b>{_e(c.get('result'))}</b>"
        f"{(' (' + _e(c.get('reason')) + ')') if c.get('reason') else ''}</li>"
        for c in ((f.get("task") or {}).get("calls") or [])[:12])
    if llm.get("status") == "ok":
        review = (f"<h3>LLM verdict: <span class='badge'>{_e(llm['verdict'])}</span></h3><p>{_e(llm['summary'])}</p>"
                  + "<ul>" + "".join(f"<li>{_e(r)}</li>" for r in llm["reasons"]) + "</ul>")
    else:
        review = f"<p class='muted'>LLM review: {_e(llm.get('status'))}</p>"
    return f"""
<div class="card">
  <div class="head"><span class="badge {sc['band']}">{sc['score']} {sc['band']}</span>
    <b>{_e(f.get('headline'))}</b><span class="muted">{_e(f.get('status') or '')}</span></div>
  <div class="cols">
    <div><h3>Why it scored {sc['score']}</h3><ul>{factors or '<li>nothing unusual</li>'}</ul>
      {('<h3>Tool calls</h3><ul>' + calls + '</ul>') if calls else ''}</div>
    <div>{review}</div>
  </div>
</div>"""


def write_report(reports_dir, threshold):
    all_findings = load_findings(reports_dir)
    agent = latest_agent_findings(all_findings)
    agent_html = "".join(_agent_card(f) for f in agent[:30]) or "<p class='muted'>No agent tasks yet.</p>"
    sessions = latest_per_session(all_findings)
    reviewed = [f for f in sessions if f["score"]["score"] >= threshold]
    rows = "".join(
        f"<tr><td>{_e(_local(f.get('start')))}</td><td>{_e((f.get('user') or {}).get('login_name'))}</td>"
        f"<td>{_e(', '.join((f.get('user') or {}).get('departments') or []))}</td>"
        f"<td>{_e((f.get('target') or {}).get('name'))}</td>"
        f"<td><span class='badge {f['score']['band']}'>{f['score']['score']}</span></td>"
        f"<td>{_e((f.get('llm') or {}).get('verdict', '-'))}</td><td>{_e(f.get('status'))}</td></tr>"
        for f in sessions)
    cards = "".join(_review_card(f) for f in reviewed) or "<p class='muted'>No sessions above the threshold.</p>"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PAM Session Review</title><style>{CSS}</style></head>
<body><main>
<h1>PAM session review</h1>
<p class="muted">Generated {_e(datetime.now(LAB_TZ).strftime('%Y-%m-%d %H:%M %Z'))}.
Sessions scoring {threshold}+ get a local LLM review. The score decides; the model explains.</p>
<h2>Needs attention ({len(reviewed)})</h2>
{cards}
<h2>AI ops agent ({len(agent)})</h2>
<p class="muted">Tasks run by the ops agent (non-human identity on ag01), scored from its task ledger.</p>
{agent_html}
<h2>All sessions ({len(sessions)})</h2>
<div class="scroll"><table><thead><tr><th>Start</th><th>User</th><th>Department</th><th>Target</th>
<th>Score</th><th>LLM</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>
</main></body></html>
"""
    fd, tmp = tempfile.mkstemp(dir=reports_dir, prefix=".report-")
    with os.fdopen(fd, "w") as f:
        f.write(page)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(reports_dir, REPORT))
