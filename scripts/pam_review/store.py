"""SQLite state for pam-review: what's been seen, scored and reviewed."""

import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    facts       TEXT NOT NULL,
    score       INTEGER,
    reviewed    TEXT,            -- phase of the last LLM review: start / final
    review_score INTEGER,        -- score at that review
    updated     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access (
    user_id     TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    PRIMARY KEY (user_id, target_id)
);
CREATE TABLE IF NOT EXISTS agent_tasks (
    task_id     TEXT PRIMARY KEY,
    score       INTEGER,
    reviewed    INTEGER NOT NULL DEFAULT 0,
    updated     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_sessions (
    session_id  TEXT PRIMARY KEY,
    login       TEXT,
    target      TEXT,
    first_seen  TEXT NOT NULL,
    flagged     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS client_ips (
    user_id     TEXT NOT NULL,
    ip          TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    PRIMARY KEY (user_id, ip)
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.commit()
        self.db.close()

    def get_session(self, session_id):
        row = self.db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["facts"] = json.loads(out["facts"])
        return out

    def save_session(self, session_id, status, facts, score=None):
        self.db.execute(
            """INSERT INTO sessions (id, status, facts, score, updated) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET status = excluded.status, facts = excluded.facts,
                 score = excluded.score, updated = excluded.updated""",
            (session_id, status, json.dumps(facts), score, now()),
        )
        self.db.commit()

    def mark_reviewed(self, session_id, phase, score):
        self.db.execute("UPDATE sessions SET reviewed = ?, review_score = ? WHERE id = ?",
                        (phase, score, session_id))
        self.db.commit()

    def record_access(self, user_id, target_id):
        """Record user->target. Returns True if it's the first time. Call once per session."""
        seen = self.db.execute("SELECT 1 FROM access WHERE user_id = ? AND target_id = ?",
                               (user_id, target_id)).fetchone()
        self.db.execute("INSERT OR IGNORE INTO access VALUES (?, ?, ?)", (user_id, target_id, now()))
        self.db.commit()
        return not seen

    def record_ips(self, user_id, ips):
        """Record client IPs. Returns True if any is new for a user who already has
        a baseline (a user's very first address doesn't count as new)."""
        c = self.db
        has_baseline = c.execute("SELECT 1 FROM client_ips WHERE user_id = ?", (user_id,)).fetchone()
        new_ip = False
        for ip in ips:
            if not c.execute("SELECT 1 FROM client_ips WHERE user_id = ? AND ip = ?",
                             (user_id, ip)).fetchone():
                new_ip = new_ip or bool(has_baseline)
                c.execute("INSERT INTO client_ips VALUES (?, ?, ?)", (user_id, ip, now()))
        c.commit()
        return new_ip

    # --- ops agent ---------------------------------------------------------
    def get_agent_task(self, task_id):
        row = self.db.execute("SELECT * FROM agent_tasks WHERE task_id = ?", (task_id,)).fetchone()
        return dict(row) if row else None

    def save_agent_task(self, task_id, score, reviewed):
        self.db.execute(
            """INSERT INTO agent_tasks (task_id, score, reviewed, updated) VALUES (?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET score = excluded.score,
                 reviewed = excluded.reviewed, updated = excluded.updated""",
            (task_id, score, int(reviewed), now()))
        self.db.commit()

    def record_agent_session(self, session_id, login, target):
        self.db.execute("INSERT OR IGNORE INTO agent_sessions (session_id, login, target, first_seen) "
                        "VALUES (?, ?, ?, ?)", (session_id, login, target, now()))
        self.db.commit()

    def unflagged_agent_sessions(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM agent_sessions WHERE flagged = 0")]

    def flag_agent_session(self, session_id, flagged=1):
        self.db.execute("UPDATE agent_sessions SET flagged = ? WHERE session_id = ?", (flagged, session_id))
        self.db.commit()
