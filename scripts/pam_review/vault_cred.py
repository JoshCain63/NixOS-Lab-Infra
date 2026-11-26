"""Fetch pam-reviewer's Boundary password from Vault for one run.

AppRole login (role_id/secret_id from systemd credentials) gives a token that
lives 5 minutes and only works from ai01's address. The password is read from
KV, kept in memory only, and the token is revoked straight away.
"""

import json
import ssl
import urllib.error
import urllib.request

from boundary_api import BoundaryError


class VaultError(BoundaryError):
    pass


def _call(addr, ctx, method, path, body=None, token=None):
    req = urllib.request.Request(addr.rstrip("/") + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("X-Vault-Token", token)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        e.close()
        raise VaultError(f"Vault {method} {path} -> HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise VaultError(f"Vault {method} {path} -> {e.reason}") from None


def read_credential(addr, role_id_file, secret_id_file, path, cafile=None):
    """Return (login_name, password) from a KV v2 path like secret/data/boundary/pam-reviewer."""
    ctx = ssl.create_default_context(cafile=cafile) if addr.startswith("https") else None
    with open(role_id_file) as f:
        role_id = f.read().strip()
    with open(secret_id_file) as f:
        secret_id = f.read().strip()
    token = _call(addr, ctx, "POST", "/v1/auth/approle/login",
                  {"role_id": role_id, "secret_id": secret_id})["auth"]["client_token"]
    try:
        data = _call(addr, ctx, "GET", f"/v1/{path}", token=token)["data"]["data"]
        return data.get("login_name", "pam-reviewer"), data["password"]
    except (KeyError, TypeError):
        raise VaultError(f"no password at {path} yet (hb01 rotates it in on boot)") from None
    finally:
        try:
            _call(addr, ctx, "POST", "/v1/auth/token/revoke-self", token=token)
        except VaultError:
            pass  # it expires in 5 minutes anyway
