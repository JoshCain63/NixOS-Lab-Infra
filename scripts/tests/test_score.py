import unittest
from datetime import datetime, timezone

from pam_review.score import LAB_TZ, band, score_session


def utc(local):
    """'2026-11-03 10:00' Vancouver local time -> UTC ISO string (as Boundary reports it).
    Uses the tz database, so it follows BC's current rules (permanent UTC-7 from 2026)."""
    t = datetime.strptime(local, "%Y-%m-%d %H:%M").replace(tzinfo=LAB_TZ)
    return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

LT05 = {"id": "ttcp_lt05", "name": "lt05", "risk": 5, "tier": "critical",
        "data_classification": "restricted", "owners": ["Finance"]}
LT01 = {"id": "ttcp_lt01", "name": "lt01", "risk": 1, "tier": "low",
        "data_classification": "public", "owners": ["Engineering", "IT", "HR", "Finance", "Operations"]}


def facts(start, target=LT05, departments=("Finance",), auth="oidc", **kw):
    base = {
        "user": {"login_name": "u", "departments": list(departments), "auth_method": auth},
        "target": target, "start": start, "history": {}, "client_addresses": ["192.168.100.1"],
    }
    base.update(kw)
    return base


def names(result):
    return {f["factor"] for f in result["factors"]}


class ScoreTests(unittest.TestCase):
    def test_owner_on_lt01_during_work_hours_is_low(self):
        r = score_session(facts(utc("2026-11-03 10:00"), target=LT01, departments=["HR"]))
        self.assertEqual(r["score"], 10)
        self.assertEqual(r["band"], "low")
        self.assertFalse(r["needs_review"])

    def test_off_hours_uses_vancouver_time_not_utc(self):
        # 18:30 local is still business hours even though it's the next day in UTC.
        start = utc("2026-11-03 18:30")
        self.assertTrue(start.startswith("2026-11-04"))
        self.assertNotIn("off_hours", names(score_session(facts(start))))
        self.assertIn("off_hours", names(score_session(facts(utc("2026-11-03 19:00")))))

    def test_business_hours_edges(self):
        self.assertIn("off_hours", names(score_session(facts(utc("2026-07-01 06:59")))))
        self.assertNotIn("off_hours", names(score_session(facts(utc("2026-07-01 07:00")))))
        self.assertNotIn("off_hours", names(score_session(facts(utc("2026-12-01 18:59")))))

    def test_bc_permanent_daylight_time(self):
        # tzdata 2026e: BC stays on UTC-7 after March 2026 (no November fall-back).
        self.assertEqual(datetime(2026, 12, 1, 12, tzinfo=LAB_TZ).utcoffset().total_seconds(), -7 * 3600)

    def test_weekend(self):
        r = score_session(facts(utc("2026-11-07 12:00")))  # Saturday noon
        self.assertIn("weekend", names(r))
        self.assertNotIn("off_hours", names(r))

    def test_department_mismatch_on_critical_host_needs_review(self):
        r = score_session(facts(utc("2026-11-03 10:00"), departments=["Engineering"],
                                history={"first_access": True}))
        self.assertEqual(names(r), {"target_risk", "department_mismatch", "first_access"})
        self.assertEqual(r["score"], 80)
        self.assertEqual(r["band"], "critical")
        self.assertTrue(r["needs_review"])

    def test_local_account_replaces_department_checks(self):
        r = score_session(facts(utc("2026-11-03 10:00"), departments=[], auth="password"))
        self.assertIn("local_account", names(r))
        self.assertNotIn("no_department", names(r))
        self.assertNotIn("department_mismatch", names(r))

    def test_sso_user_without_department(self):
        self.assertIn("no_department", names(score_session(facts(utc("2026-11-03 10:00"), departments=[]))))

    def test_volume_duration_concurrency(self):
        r = score_session(facts(utc("2026-11-03 10:00"), duration_seconds=7200,
                                bytes_down=60 * 1024 * 1024, concurrent_targets=["lt02"]))
        self.assertTrue({"long_session", "large_transfer", "concurrent_sessions"} <= names(r))

    def test_score_is_capped_and_every_point_is_explained(self):
        r = score_session(facts(utc("2026-11-07 02:30"), departments=["Engineering"],  # Saturday
                                history={"first_access": True, "new_client_ip": True},
                                duration_seconds=9000, bytes_down=10**9, concurrent_targets=["lt02"]))
        self.assertEqual(r["score"], 100)
        self.assertGreater(sum(f["points"] for f in r["factors"]), 100)
        self.assertTrue(all(f["detail"] for f in r["factors"]))

    def test_bands(self):
        self.assertEqual([band(s) for s in (0, 29, 30, 59, 60, 79, 80, 100)],
                         ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])


if __name__ == "__main__":
    unittest.main()
