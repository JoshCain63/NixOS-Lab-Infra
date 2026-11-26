"""In-process mock of the Boundary 0.21 API endpoints the lab scripts call.

Response shapes follow controller.swagger.json for v0.21.3 (sessions,
connections, users, accounts with OIDC token_claims, targets, host sets).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PASSWORD = "s3cret"


def lab_targets():
    rows = {
        "lt01": ("192.168.100.31", "General-purpose workstation | risk=1 | tier=low | data=public | "
                 "owners=Engineering,IT,HR,Finance,Operations"),
        "lt04": ("192.168.100.34", "HR file server | risk=4 | tier=high | data=confidential (employee PII) | owners=HR"),
        "lt05": ("192.168.100.35", "Finance database host | risk=5 | tier=critical | "
                 "data=restricted (financial records, credentials) | owners=Finance"),
    }
    return {f"ttcp_{n}": {"id": f"ttcp_{n}", "name": n, "type": "tcp", "description": d,
                          "scope": {"name": "linux-targets"}, "attributes": {"default_port": 22},
                          "host_sources": [{"id": f"hsst_{n}"}], "_ip": ip}
            for n, (ip, d) in rows.items()}


class State:
    def __init__(self):
        self.targets = lab_targets()
        self.users = {
            "u_eng": {"id": "u_eng", "login_name": "asmith", "full_name": "Alex Smith",
                      "primary_account_id": "acctoidc_eng"},
            "u_fin": {"id": "u_fin", "login_name": "cwong", "full_name": "Casey Wong",
                      "primary_account_id": "acctoidc_fin"},
        }
        self.accounts = {
            "acctoidc_eng": {"id": "acctoidc_eng", "type": "oidc",
                             "attributes": {"token_claims": {"groups": ["Engineering"],
                                                             "preferred_username": "asmith"}}},
            "acctoidc_fin": {"id": "acctoidc_fin", "type": "oidc",
                             "attributes": {"token_claims": {"groups": "Finance"}}},  # single-valued claim
        }
        self.sessions = {}
        self.deleted_tokens = []
        # LDAP (AD) logins for non-human identities; disabled = midPoint
        # disabled the AD account (sponsor left, or expired).
        self.ldap_accounts = {"svc-pam-review": "ad-pw"}
        self.ldap_disabled = set()

    def add_session(self, sid, user_id, target_id, created, status="active", ended=None,
                    connections=None):
        states = [{"status": "active", "start_time": created}]
        if status == "terminated":
            states.insert(0, {"status": "terminated", "start_time": ended})
        self.sessions[sid] = {
            "id": sid, "user_id": user_id, "target_id": target_id, "status": status,
            "created_time": created, "states": states, "type": "tcp",
            "endpoint": "tcp://" + self.targets[target_id]["_ip"] + ":22",
            "termination_reason": "closed by end-user" if status == "terminated" else "",
            "connections": connections or [],
        }


def serve(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if (self.path == "/v1/auth-methods/ampw_1:authenticate" and body.get("command") == "login"
                    and body["attributes"].get("password") == PASSWORD):
                return self.send(200, {"attributes": {"id": "at_1234", "token": "at_good"}})
            if self.path == "/v1/auth-methods/amldap_1:authenticate" and body.get("command") == "login":
                a = body["attributes"]
                if (a.get("login_name") not in state.ldap_disabled
                        and state.ldap_accounts.get(a.get("login_name")) == a.get("password")):
                    return self.send(200, {"attributes": {"id": "at_1234", "token": "at_good"}})
            self.send(401, {"message": "bad creds"})

        def do_DELETE(self):
            if self.headers.get("Authorization") == "Bearer at_good" and self.path == "/v1/auth-tokens/at_1234":
                state.deleted_tokens.append("at_1234")
                self.send_response(204)
                self.end_headers()
                return
            self.send(403, {"message": "forbidden"})

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/v1/auth-methods":
                # OIDC is primary; the password method must be found by type.
                return self.send(200, {"items": [
                    {"id": "amoidc_1", "type": "oidc", "is_primary": True},
                    {"id": "ampw_1", "type": "password", "is_primary": False},
                    {"id": "amldap_1", "type": "ldap", "is_primary": False}],
                    "response_type": "complete"})
            if self.headers.get("Authorization") != "Bearer at_good":
                return self.send(403, {"message": "forbidden"})
            kind, _, ident = u.path[len("/v1/"):].partition("/")
            if kind == "sessions" and not ident:
                assert q.get("include_terminated") == ["true"] and q.get("recursive") == ["true"]
                items = [{k: s[k] for k in ("id", "user_id", "target_id", "status", "created_time")}
                         for s in state.sessions.values()]
                return self.send(200, {"items": items, "response_type": "complete"})
            if kind == "targets" and not ident:
                ids = sorted(state.targets)
                if "list_token" not in q:
                    return self.send(200, {"items": [{"id": i} for i in ids[:1]],
                                           "response_type": "delta", "list_token": "t1"})
                return self.send(200, {"items": [{"id": i} for i in ids[1:]], "response_type": "complete"})
            table = {"sessions": state.sessions, "users": state.users, "accounts": state.accounts,
                     "targets": state.targets}.get(kind)
            if table is not None and ident in table:
                return self.send(200, {"item": {k: v for k, v in table[ident].items() if not k.startswith("_")}})
            if kind == "host-sets":
                return self.send(200, {"item": {"host_ids": ["hst_" + ident.split("_", 1)[1]]}})
            if kind == "hosts":
                return self.send(200, {"item": {"attributes": {
                    "address": state.targets["ttcp_" + ident.split("_", 1)[1]]["_ip"]}}})
            self.send(404, {"message": "not found"})

    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"
