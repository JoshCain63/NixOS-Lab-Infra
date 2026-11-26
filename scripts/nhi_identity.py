"""The credential chain every AI agent (non-human identity) logs in with.

Shared by the ops agent (ag01, svc-agent-ops) and pam-review (ai01,
svc-pam-review), run fresh for every task or review run:

    Keycloak client credentials (the agent's own client, 5-min token)
      -> Vault JWT login (the agent's role, 10-min token, can only read its
         own AD password)
      -> Vault: current AD password for the agent's account (Vault rotates it)
      -> Boundary login through the LDAP auth method (AD bind)

If midPoint has disabled the AD account (sponsor left, or expired), the last
step fails: that's the lifecycle control. Nothing is written to disk, and
the Vault and Boundary tokens are revoked at the end.
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from boundary_api import Boundary, BoundaryError


class IdentityError(Exception):
    """A step of the chain failed. `stage` says which (for the ledger)."""

    def __init__(self, stage, detail):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


def _post(url, data, ctx, headers=None, form=False):
    body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded" if form else "application/json", **(headers or {})})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def _get(url, ctx, headers):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), context=ctx, timeout=30) as r:
        return json.load(r)


class AgentIdentity:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file")) if cfg.get("ca_file") else None
        self.vault_token = None
        self.boundary = None

    def keycloak_token(self):
        try:
            resp = _post(self.cfg["keycloak_token_url"], {
                "grant_type": "client_credentials",
                "client_id": self.cfg["client_id"],
                "client_secret": self.cfg["client_secret"],
            }, self.ctx, form=True)
            return resp["access_token"]
        except (urllib.error.URLError, KeyError, ValueError) as e:
            raise IdentityError("keycloak", str(getattr(e, "reason", e))) from None

    def vault_login(self, jwt):
        try:
            resp = _post(self.cfg["vault_addr"] + f"/v1/auth/{self.cfg['vault_jwt_path']}/login",
                         {"role": self.cfg["vault_role"], "jwt": jwt}, self.ctx)
            self.vault_token = resp["auth"]["client_token"]
        except (urllib.error.URLError, KeyError, ValueError) as e:
            raise IdentityError("vault_login", str(getattr(e, "reason", e))) from None

    def ad_password(self):
        try:
            resp = _get(self.cfg["vault_addr"] + f"/v1/ldap/static-cred/{self.cfg['account']}",
                        self.ctx, {"X-Vault-Token": self.vault_token})
            return resp["data"]["password"]
        except (urllib.error.URLError, KeyError, ValueError) as e:
            raise IdentityError("vault_secret", str(getattr(e, "reason", e))) from None

    def ldap_auth_method_id(self, b):
        """Boundary's LDAP auth method id.

        Boundary does not return LDAP auth methods in the *anonymous*
        auth-method list, so discovery can't find it and the login fails with
        "no ldap auth method in scope global" - even though authenticating
        against it by id works fine. hb01 publishes the id from its Terraform
        output into the read-only boundary-export mount; fall back to
        discovery if the file isn't there yet.
        """
        path = self.cfg.get("auth_method_id_file")
        if path:
            try:
                with open(path) as f:
                    value = f.read().strip()
            except OSError:
                value = None
            if value:
                return value
        return b.auth_method("ldap")

    def boundary_login(self, password):
        b = Boundary(self.cfg["boundary_addr"], cafile=self.cfg.get("ca_file"))
        try:
            b.login(self.ldap_auth_method_id(b), self.cfg["account"], password)
        except BoundaryError as e:
            # Typically: the AD account is disabled (sponsor left / expired).
            raise IdentityError("boundary_login", str(e)) from None
        self.boundary = b
        return b

    def establish(self):
        """Run the whole chain. Returns a logged-in Boundary client."""
        self.vault_login(self.keycloak_token())
        password = self.ad_password()
        try:
            return self.boundary_login(password)
        finally:
            del password

    def release_vault(self):
        """Revoke the Vault token now (once the password has been used)."""
        if self.vault_token:
            try:
                _post(self.cfg["vault_addr"] + "/v1/auth/token/revoke-self", {}, self.ctx,
                      headers={"X-Vault-Token": self.vault_token})
            except urllib.error.URLError:
                pass  # expires in 10 minutes anyway
            self.vault_token = None

    def close(self):
        if self.boundary:
            self.boundary.logout()
            self.boundary = None
        self.release_vault()
