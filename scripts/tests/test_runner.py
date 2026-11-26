import json
import os
import tempfile
import unittest

import boundary_risk_export
from boundary_api import Boundary
from pam_review import report
from pam_review.collect import Collector
from pam_review.runner import run_once
from pam_review.store import Store

from mock_boundary import PASSWORD, State, serve


class FakeOllama:
    model = "fake"

    def __init__(self):
        self.calls = []

    def review(self, facts, score):
        self.calls.append((facts, score))
        return {"status": "ok", "verdict": "escalate", "summary": "Looks risky.",
                "reasons": ["off hours"], "recommended_action": "Ask the user.",
                "model": "fake", "latency_seconds": 0.01}


def findings(d):
    with open(os.path.join(d, "findings.ndjson")) as f:
        return [json.loads(line) for line in f]


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.state = State()
        self.server, url = serve(self.state)
        self.client = Boundary(url)
        self.client.login(self.client.auth_method("password"), "pam-reviewer", PASSWORD)
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "state.db"))
        self.ollama = FakeOllama()

    def tearDown(self):
        self.store.close()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def cycle(self):
        return run_once(Collector(self.client), self.store, self.ollama, self.tmp.name, 60, log=lambda *_: None)

    def test_full_lifecycle(self):
        # Engineer on the finance DB, Saturday 03:30 Vancouver (10:30Z, UTC-7).
        self.state.add_session("s_risky", "u_eng", "ttcp_lt05", "2026-11-07T10:30:00.123456Z")
        # Finance user on lt01 on a Tuesday morning (11:00 local), already connected.
        self.state.add_session("s_normal", "u_fin", "ttcp_lt01", "2026-11-03T18:00:00Z",
                               connections=[{"client_tcp_address": "192.168.100.1", "bytes_up": "10",
                                             "bytes_down": "20"}])

        self.assertEqual(self.cycle(), 2)
        self.assertEqual(len(self.ollama.calls), 1)  # only the risky one
        facts, score = self.ollama.calls[0]
        self.assertEqual(facts["user"]["departments"], ["Engineering"])
        self.assertEqual(facts["target"]["owners"], ["Finance"])
        self.assertNotIn("_checked_ips", facts)
        self.assertEqual(score["band"], "critical")
        self.assertTrue({"off_hours", "weekend", "department_mismatch", "first_access"}
                        <= {f["factor"] for f in score["factors"]})

        self.assertTrue(all(f["event"] == "pam_review.finding" for f in findings(self.tmp.name)))
        by_id = {f["session_id"]: f for f in findings(self.tmp.name)}
        self.assertEqual(by_id["s_normal"]["llm"]["status"], "not_required")
        self.assertEqual(by_id["s_normal"]["user"]["departments"], ["Finance"])  # string claim -> list

        # Nothing changed: no new findings, no new LLM calls.
        self.assertEqual(self.cycle(), 0)
        self.assertEqual(len(self.ollama.calls), 1)

        # The risky session ends after 2 hours with a big download.
        self.state.add_session("s_risky", "u_eng", "ttcp_lt05", "2026-11-07T10:30:00.123456Z",
                               status="terminated", ended="2026-11-07T12:30:00Z",
                               connections=[{"client_tcp_address": "192.168.100.1", "bytes_up": "100",
                                             "bytes_down": str(200 * 1024 * 1024)}])
        self.assertEqual(self.cycle(), 1)
        final = findings(self.tmp.name)[-1]
        self.assertEqual(final["phase"], "final")
        self.assertEqual(final["duration_seconds"], 7200)
        # Already at the 100 cap, so no second LLM call; the report reuses the first review.
        self.assertEqual(len(self.ollama.calls), 1)
        self.assertEqual(final["llm"]["status"], "see_earlier_review")
        latest = {f["session_id"]: f for f in report.latest_per_session(findings(self.tmp.name))}
        self.assertEqual(latest["s_risky"]["llm"]["verdict"], "escalate")

        # Terminated sessions are skipped from now on.
        self.assertEqual(self.cycle(), 0)

    def test_second_access_is_not_first_and_new_ip_is_flagged(self):
        conn = [{"client_tcp_address": "192.168.100.1", "bytes_up": "1", "bytes_down": "1"}]
        self.state.add_session("s1", "u_fin", "ttcp_lt01", "2026-11-03T18:00:00Z", status="terminated",
                               ended="2026-11-03T18:10:00Z", connections=conn)
        self.cycle()
        self.state.add_session("s2", "u_fin", "ttcp_lt01", "2026-11-04T18:00:00Z",
                               connections=[{"client_tcp_address": "10.9.9.9", "bytes_up": "1", "bytes_down": "1"}])
        self.cycle()
        last = findings(self.tmp.name)[-1]
        self.assertEqual(last["session_id"], "s2")
        self.assertEqual(last["history"], {"first_access": False, "new_client_ip": True})

    def test_review_budget_defers_and_catches_up(self):
        for i in range(3):  # three risky sessions, budget of one review per run
            self.state.add_session(f"s{i}", "u_eng", "ttcp_lt05", f"2026-11-07T10:3{i}:00Z")
        run = lambda: run_once(Collector(self.client), self.store, self.ollama, self.tmp.name, 60,
                               log=lambda *_: None, max_reviews=1)
        self.assertEqual(run(), 3)                 # all scored and logged at once
        self.assertEqual(len(self.ollama.calls), 1)
        statuses = sorted(f["llm"]["status"] for f in findings(self.tmp.name))
        self.assertEqual(statuses, ["deferred", "deferred", "ok"])
        run()
        run()
        self.assertEqual(len(self.ollama.calls), 3)  # caught up, one per run
        self.assertEqual(run(), 0)
        self.assertEqual(len(self.ollama.calls), 3)

    def test_unavailable_review_is_retried_once_model_is_back(self):
        class Flaky(FakeOllama):
            down = True
            def review(self, facts, score):
                if self.down:
                    self.calls.append((facts, score))
                    return {"status": "unavailable", "error": "down", "model": "fake", "latency_seconds": 0}
                return super().review(facts, score)  # records the call itself
        self.ollama = Flaky()
        self.state.add_session("s1", "u_eng", "ttcp_lt05", "2026-11-07T10:30:00Z", status="terminated",
                               ended="2026-11-07T10:40:00Z")
        self.assertEqual(self.cycle(), 1)          # logged once, model down
        self.assertEqual(self.cycle(), 0)          # finished, unreviewed: retried quietly
        self.ollama.down = False
        self.assertEqual(self.cycle(), 1)          # reviewed now
        self.assertEqual(findings(self.tmp.name)[-1]["llm"]["verdict"], "escalate")
        self.assertEqual(self.cycle(), 0)          # settled
        self.assertEqual(len(self.ollama.calls), 3)

    def test_report_escapes_attacker_text(self):
        self.state.users["u_eng"]["login_name"] = "<script>alert(1)</script>"
        self.state.add_session("s_x", "u_eng", "ttcp_lt05", "2026-11-07T10:30:00Z")
        self.cycle()
        with open(os.path.join(self.tmp.name, "index.html")) as f:
            page = f.read()
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_risk_exporter_with_shared_client(self):
        doc = boundary_risk_export.export(self.client)
        self.assertEqual([t["name"] for t in doc["targets"]], ["lt05", "lt04", "lt01"])
        self.assertEqual(doc["targets"][0]["owners"], ["Finance"])
        self.assertEqual(doc["targets"][0]["addresses"], ["192.168.100.35"])


if __name__ == "__main__":
    unittest.main()
