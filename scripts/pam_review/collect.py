"""Turn Boundary sessions into the facts the scorer and the LLM see.

Source of truth is Boundary's sessions API (structured and documented):
user, target, start/end, client addresses and bytes per connection. The
users/accounts APIs add the person's name and their department from the
Keycloak token claims; the target's description adds its risk and owners.
"""

from boundary_api import target_metadata

from .score import parse_time


class Collector:
    def __init__(self, client):
        self.client = client
        self._users = {}
        self._targets = {}

    def list_sessions(self, scope_id="global"):
        return self.client.list_all("/v1/sessions", {
            "scope_id": scope_id, "recursive": "true", "include_terminated": "true",
        })

    def user(self, user_id):
        if user_id not in self._users:
            user = self.client.get(f"/v1/users/{user_id}")
            info = {
                "id": user_id,
                "login_name": user.get("login_name") or user.get("name"),
                "full_name": user.get("full_name"),
                "email": user.get("email"),
                "auth_method": None,
                "departments": [],
            }
            account_id = user.get("primary_account_id") or next(iter(user.get("account_ids") or []), None)
            if account_id:
                account = self.client.get(f"/v1/accounts/{account_id}")
                info["auth_method"] = account.get("type")
                attrs = account.get("attributes") or {}
                if account.get("type") == "password":
                    info["login_name"] = info["login_name"] or attrs.get("login_name")
                claims = attrs.get("token_claims") or {}
                groups = claims.get("groups") or []
                info["departments"] = [groups] if isinstance(groups, str) else list(groups)
                info["login_name"] = info["login_name"] or claims.get("preferred_username")
            self._users[user_id] = info
        return self._users[user_id]

    def target(self, target_id):
        if target_id not in self._targets:
            target = self.client.get(f"/v1/targets/{target_id}")
            info = {"id": target_id, "name": target.get("name"),
                    "scope": (target.get("scope") or {}).get("name")}
            info.update(target_metadata(target))
            self._targets[target_id] = info
        return self._targets[target_id]

    def facts(self, session_id, all_sessions=()):
        """Facts for one session. `all_sessions` (the list) finds concurrent ones."""
        s = self.client.get(f"/v1/sessions/{session_id}")
        connections = s.get("connections") or []

        start = parse_time(s.get("created_time"))
        end = None
        for state in s.get("states") or []:
            if state.get("status") == "terminated":
                end = parse_time(state.get("start_time"))
        duration = round((end - start).total_seconds()) if start and end else None

        user = self.user(s["user_id"])
        concurrent = []
        for other in all_sessions:
            if (other.get("id") != session_id and other.get("user_id") == s["user_id"]
                    and other.get("status") in ("active", "pending")
                    and other.get("target_id") != s.get("target_id")):
                concurrent.append(self.target(other["target_id"])["name"])

        return {
            "session_id": session_id,
            "status": s.get("status"),
            "termination_reason": s.get("termination_reason") or None,
            "user": user,
            "target": self.target(s["target_id"]),
            "endpoint": s.get("endpoint"),
            "start": start.isoformat() if start else None,
            "end": end.isoformat() if end else None,
            "duration_seconds": duration,
            "client_addresses": sorted({c["client_tcp_address"] for c in connections
                                        if c.get("client_tcp_address")}),
            "connections": len(connections),
            "bytes_up": sum(int(c.get("bytes_up") or 0) for c in connections),
            "bytes_down": sum(int(c.get("bytes_down") or 0) for c in connections),
            "concurrent_targets": sorted(set(concurrent)),
        }
