import json
import os
import unittest

from pam_review.eval import SCENARIOS, USERS, build_facts
from pam_review.guard import clean_output, instruction_markers, model_view, ungrounded_claims
from pam_review.llm import build_messages
from pam_review.score import score_session

HERE = os.path.dirname(__file__)

TARGETS = {
    "lt01": {"name": "lt01", "risk": 1, "tier": "low", "role": "General-purpose workstation",
             "data_classification": "public", "owners": ["Engineering", "IT", "HR", "Finance", "Operations"]},
    "lt04": {"name": "lt04", "risk": 4, "tier": "high", "role": "HR file server",
             "data_classification": "confidential (employee PII)", "owners": ["HR"]},
    "lt05": {"name": "lt05", "risk": 5, "tier": "critical", "role": "Finance database host",
             "data_classification": "restricted (financial records, credentials)", "owners": ["Finance"]},
}
TARGETS.update({n: dict(TARGETS["lt01"], name=n) for n in ("lt02", "lt03")})


class GuardTests(unittest.TestCase):
    def test_no_false_positives_on_normal_lab_data(self):
        names = ["Alex Smith", "Blair Jones", "Casey O'Neil", "Dev Patel", "Zoë Ångström", "Jean-Luc Picard",
                 "Mary-Kate Olsen", "Bob Admin", "Sam Approvato"]
        for t in TARGETS.values():
            for n in names:
                facts = {"user": {"login_name": n.split()[0].lower(), "full_name": n,
                                  "email": "x@lab.internal", "departments": ["Engineering", "HR", "IT"]},
                         "target": t}
                self.assertEqual(instruction_markers(facts), [], (n, t["name"]))

    def test_every_injection_scenario_is_flagged_by_the_rules(self):
        for sc in SCENARIOS:
            facts = build_facts(sc, TARGETS)
            flagged = bool(instruction_markers(facts))
            self.assertEqual(flagged, bool(sc.get("injection")), sc["name"])
            if sc.get("injection"):
                factors = {f["factor"] for f in score_session(facts)["factors"]}
                self.assertIn("instruction_like_identity", factors, sc["name"])

    def test_model_view_is_an_allowlist(self):
        facts = build_facts(SCENARIOS[0], TARGETS)
        facts.update({"_checked_ips": ["10.0.0.1"], "endpoint": "tcp://192.168.100.31:22",
                      "session_id": "s_secret", "auth_token_id": "at_123"})
        facts["user"]["email"] = "asmith@lab.internal"
        view = json.dumps(model_view(facts))
        for leaked in ("s_secret", "at_123", "_checked_ips", "asmith@lab.internal", "tcp://", "u_eval"):
            self.assertNotIn(leaked, view)
        content = build_messages(facts, {"score": 10})[1]["content"]
        self.assertIn("start_local", content)
        self.assertIn("(Tuesday)", content)  # local time and weekday, not raw UTC

    def test_ungrounded_claims(self):
        facts = build_facts(SCENARIOS[0], TARGETS)  # lt01 from 192.168.100.1
        review = {"summary": "User reached lt01 from 192.168.100.1.", "reasons": ["also touched lt05 from 10.1.2.3"],
                  "recommended_action": "none"}
        self.assertEqual(ungrounded_claims(review, facts), ["10.1.2.3", "lt05"])

    def test_clean_output(self):
        self.assertEqual(clean_output("ok\nnext\x1b[31m\x00line", 100), "ok next [31m line")
        self.assertEqual(len(clean_output("x" * 999, 50)), 50)


if __name__ == "__main__":
    unittest.main()
