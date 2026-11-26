"""Small Boundary API client and the lab's target-metadata format.

Shared by boundary_risk_export.py and pam_review. Standard library only.

Lab targets carry their metadata in the Boundary description (set by
terraform/boundary), because Boundary targets have no custom fields:

    <role> | risk=<1-5> | tier=<tier> | data=<classification> | owners=<dept,...>
"""

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

RISK_MIN, RISK_MAX = 1, 5


class BoundaryError(Exception):
    pass


class Boundary:
    """Minimal client for the parts of the Boundary API the lab scripts use."""

    def __init__(self, addr, cafile=None, timeout=30):
        self.addr = addr.rstrip("/")
        self.timeout = timeout
        self.token = None
        self.ctx = ssl.create_default_context(cafile=cafile) if self.addr.startswith("https") else None

    def request(self, method, path, body=None, params=None):
        url = self.addr + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}  # e.g. 204 on DELETE
        except urllib.error.HTTPError as e:
            with e:
                detail = e.read().decode(errors="replace").strip()
            raise BoundaryError(f"{method} {path} -> HTTP {e.code}: {detail}") from None
        except urllib.error.URLError as e:
            raise BoundaryError(f"{method} {path} -> {e.reason}") from None

    def get(self, path):
        # Real Boundary 0.21.3 returns a single resource unwrapped; the test
        # double in tests/mock_boundary.py wraps it in {"item": ...}. Accept
        # both, so the exporter works against the live API and the mock.
        resource = self.request("GET", path)
        return resource.get("item", resource)

    def list_all(self, path, params):
        """List a collection, following Boundary's pagination (list_token)."""
        params = dict(params)
        items = []
        while True:
            page = self.request("GET", path, params=params)
            items.extend(page.get("items") or [])
            if page.get("response_type", "complete") == "complete" or not page.get("list_token"):
                return items
            params["list_token"] = page["list_token"]

    def auth_method(self, type_="password", scope_id="global"):
        """ID of the auth method of this type (the password one holds service accounts)."""
        methods = self.list_all("/v1/auth-methods", {"scope_id": scope_id})
        for am in methods:
            if am.get("type") == type_:
                return am["id"]
        raise BoundaryError(f"no {type_} auth method in scope {scope_id}; pass --auth-method-id")

    def login(self, auth_method_id, login_name, password):
        resp = self.request(
            "POST",
            f"/v1/auth-methods/{auth_method_id}:authenticate",
            {"command": "login", "attributes": {"login_name": login_name, "password": password}},
        )
        try:
            self.token = resp["attributes"]["token"]
        except (KeyError, TypeError):
            raise BoundaryError("login response had no token") from None
        self.token_id = resp["attributes"].get("id")

    def logout(self):
        """Delete this session's auth token so it can't be reused."""
        if self.token and getattr(self, "token_id", None):
            try:
                self.request("DELETE", f"/v1/auth-tokens/{self.token_id}")
            except BoundaryError:
                pass
        self.token = None


def parse_description(description):
    """Split '<role> | key=value | ...' into a dict with 'role' plus the keys."""
    parts = [p.strip() for p in (description or "").split("|")]
    meta = {"role": parts[0]}
    for part in parts[1:]:
        key, sep, value = part.partition("=")
        if sep:
            meta[key.strip()] = value.strip()
    return meta


def parse_risk(value):
    """Return (risk, error). Risk must be a whole number in the lab's scale."""
    if value is None:
        return None, "description has no risk=<n>"
    try:
        risk = int(value)
    except ValueError:
        return None, f"risk {value!r} is not a whole number"
    if not RISK_MIN <= risk <= RISK_MAX:
        return None, f"risk {risk} is outside {RISK_MIN}-{RISK_MAX}"
    return risk, None


def parse_owners(value):
    return [d.strip() for d in (value or "").split(",") if d.strip()]


def target_metadata(target):
    """Lab metadata for a Boundary target item."""
    meta = parse_description(target.get("description"))
    risk, error = parse_risk(meta.get("risk"))
    out = {
        "risk": risk,
        "tier": meta.get("tier"),
        "role": meta.get("role"),
        "data_classification": meta.get("data"),
        "owners": parse_owners(meta.get("owners")),
    }
    if error:
        out["error"] = error
    return out


def read_password(path):
    """Read a password file, defaulting to systemd's $CREDENTIALS_DIRECTORY/password."""
    if path is None:
        creds = os.environ.get("CREDENTIALS_DIRECTORY")
        if not creds:
            raise BoundaryError("no password: pass --password-file")
        path = os.path.join(creds, "password")
    with open(path) as f:
        return f.read().strip()
