"""pam-review's governed login (svc-pam-review): the same NHI chain as the
ops agent, and its login state reported to the SOC on change only."""

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs

from nhi_identity import AgentIdentity, IdentityError
from pam_review.__main__ import governed_login

from mock_boundary import State, serve


class MockIdp(BaseHTTPRequestHandler):
    """Keycloak token endpoint + the Vault paths the chain uses."""
    revoked = []

    def log_message(self, *a):
        pass

    def send(self, code, obj=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/realms/lab/protocol/openid-connect/token":
            f = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            if f == {"grant_type": "client_credentials", "client_id": "pam-review", "client_secret": "cs"}:
                return self.send(200, {"access_token": "jwt-pam", "expires_in": 300})
            return self.send(401, {"error": "unauthorized_client"})
        body = json.loads(raw or b"{}")
        if self.path == "/v1/auth/jwt-keycloak/login":
            if body == {"role": "pam-review", "jwt": "jwt-pam"}:
                return self.send(200, {"auth": {"client_token": "hvs.pam", "lease_duration": 600}})
            return self.send(400, {"errors": ["role mismatch"]})
        if self.path == "/v1/auth/token/revoke-self":
            MockIdp.revoked.append(self.headers.get("X-Vault-Token"))
            return self.send(204)
        self.send(404)

    def do_GET(self):
        if self.headers.get("X-Vault-Token") != "hvs.pam":
            return self.send(403, {"errors": ["permission denied"]})
        if self.path == "/v1/ldap/static-cred/svc-pam-review":
            return self.send(200, {"data": {"username": "svc-pam-review", "password": "ad-pw"}})
        self.send(403, {"errors": ["permission denied"]})


class GovernedLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.idp = HTTPServer(("127.0.0.1", 0), MockIdp)
        threading.Thread(target=cls.idp.serve_forever, daemon=True).start()
        cls.idp_url = f"http://127.0.0.1:{cls.idp.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.idp.shutdown()
        cls.idp.server_close()

    def setUp(self):
        MockIdp.revoked = []
        self.state = State()
        self.boundary, self.boundary_url = serve(self.state)
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "keycloak_token_url": self.idp_url + "/realms/lab/protocol/openid-connect/token",
            "client_id": "pam-review",
            "client_secret": "cs",
            "vault_addr": self.idp_url,
            "vault_jwt_path": "jwt-keycloak",
            "vault_role": "pam-review",
            "account": "svc-pam-review",
            "boundary_addr": self.boundary_url,
        }
        self.write_cfg()
        self.args = SimpleNamespace(identity=os.path.join(self.tmp.name, "identity.json"),
                                    reports=self.tmp.name,
                                    auth_state=os.path.join(self.tmp.name, "auth-status.json"))

    def tearDown(self):
        self.boundary.shutdown()
        self.boundary.server_close()
        self.tmp.cleanup()

    def write_cfg(self):
        with open(os.path.join(self.tmp.name, "identity.json"), "w") as f:
            json.dump(self.cfg, f)

    def events(self):
        path = os.path.join(self.tmp.name, "findings.ndjson")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f]

    def test_logs_in_through_ldap_and_revokes_vault_token(self):
        ident = governed_login(self.args)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.boundary.token, "at_good")
        self.assertEqual(MockIdp.revoked, ["hvs.pam"])  # released straight after login
        ident.close()
        self.assertEqual(self.state.deleted_tokens, ["at_1234"])
        self.assertEqual(self.events(), [])  # healthy from the start: nothing to report

    def test_disabled_account_alerts_once_then_restores(self):
        self.state.ldap_disabled.add("svc-pam-review")  # sponsor left
        for _ in range(3):
            self.assertIsNone(governed_login(self.args))
        ev = self.events()
        self.assertEqual(len(ev), 1)  # transition only, not every run
        self.assertEqual(ev[0]["event"], "pam_review.auth")
        self.assertEqual(ev[0]["status"], "auth_failed")
        self.assertEqual(ev[0]["stage"], "boundary_login")
        self.assertEqual(ev[0]["account"], "svc-pam-review")
        self.assertIn("hvs.pam", MockIdp.revoked)  # Vault token revoked on failure too

        self.state.ldap_disabled.clear()  # new sponsor assigned
        ident = governed_login(self.args)
        self.assertIsNotNone(ident)
        ident.close()
        ev = self.events()
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[1]["status"], "auth_restored")
        self.assertEqual(ev[1]["since"], ev[0]["since"])

    def test_wrong_client_secret_fails_at_keycloak(self):
        self.cfg["client_secret"] = "stolen-but-rotated"
        self.write_cfg()
        self.assertIsNone(governed_login(self.args))
        self.assertEqual(self.events()[0]["stage"], "keycloak")

    def test_vault_role_only_reads_its_own_password(self):
        cfg = dict(self.cfg, account="svc-agent-ops")
        ident = AgentIdentity(cfg)
        ident.vault_login(ident.keycloak_token())
        with self.assertRaises(IdentityError) as cm:
            ident.ad_password()
        self.assertEqual(cm.exception.stage, "vault_secret")
        ident.close()


if __name__ == "__main__":
    unittest.main()
