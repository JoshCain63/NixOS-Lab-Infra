import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from boundary_api import Boundary
from pam_review.vault_cred import VaultError, read_credential

from mock_boundary import PASSWORD, State, serve


class MockVault(BaseHTTPRequestHandler):
    secret = {"login_name": "pam-reviewer", "password": "rotated-pw"}
    revoked = []

    def log_message(self, *a):
        pass

    def send(self, code, obj=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/v1/auth/approle/login":
            if body == {"role_id": "rid", "secret_id": "sid"}:
                return self.send(200, {"auth": {"client_token": "hvs.short", "lease_duration": 300}})
            return self.send(400, {"errors": ["invalid role or secret ID"]})
        if self.path == "/v1/auth/token/revoke-self":
            MockVault.revoked.append(self.headers.get("X-Vault-Token"))
            return self.send(204)
        self.send(404)

    def do_GET(self):
        if self.headers.get("X-Vault-Token") != "hvs.short":
            return self.send(403, {"errors": ["permission denied"]})
        if self.path == "/v1/secret/data/boundary/pam-reviewer" and MockVault.secret:
            return self.send(200, {"data": {"data": MockVault.secret, "metadata": {"version": 3}}})
        self.send(404, {"errors": []})


class VaultCredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockVault)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.addr = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.rid = os.path.join(self.tmp.name, "role_id")
        self.sid = os.path.join(self.tmp.name, "secret_id")
        with open(self.rid, "w") as f:
            f.write("rid\n")
        with open(self.sid, "w") as f:
            f.write("sid\n")
        MockVault.revoked = []
        MockVault.secret = {"login_name": "pam-reviewer", "password": "rotated-pw"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_password_and_revokes_token(self):
        login, pw = read_credential(self.addr, self.rid, self.sid, "secret/data/boundary/pam-reviewer")
        self.assertEqual((login, pw), ("pam-reviewer", "rotated-pw"))
        self.assertEqual(MockVault.revoked, ["hvs.short"])

    def test_missing_secret_still_revokes(self):
        MockVault.secret = None
        with self.assertRaises(VaultError):
            read_credential(self.addr, self.rid, self.sid, "secret/data/boundary/pam-reviewer")
        self.assertEqual(MockVault.revoked, ["hvs.short"])

    def test_bad_secret_id(self):
        with open(self.sid, "w") as f:
            f.write("stolen-elsewhere")
        with self.assertRaisesRegex(VaultError, "HTTP 400"):
            read_credential(self.addr, self.rid, self.sid, "secret/data/boundary/pam-reviewer")

    def test_boundary_logout_deletes_token(self):
        state = State()
        server, url = serve(state)
        try:
            client = Boundary(url)
            client.login(client.auth_method("password"), "pam-reviewer", PASSWORD)
            client.logout()
            self.assertEqual(state.deleted_tokens, ["at_1234"])
            self.assertIsNone(client.token)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
