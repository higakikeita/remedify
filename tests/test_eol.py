"""endoflife.date integration — opt-in live EOL. Network is monkeypatched;
these tests never touch the real API. Key guarantee: any failure falls back
to the static table and never raises."""

import datetime
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

TODAY = datetime.date(2026, 7, 18)


class TestEolLive(unittest.TestCase):
    def setUp(self):
        # isolate the cache per test
        self._tmp = tempfile.mkdtemp()
        os.environ["REMEDIFY_CACHE_DIR"] = self._tmp
        self._orig = remedify._http_get_json

    def tearDown(self):
        remedify._http_get_json = self._orig
        os.environ.pop("REMEDIFY_CACHE_DIR", None)

    def _stub(self, cycles):
        remedify._http_get_json = lambda url, timeout=10: cycles

    def test_past_eol_flagged(self):
        self._stub([{"cycle": "18.04", "eol": "2023-05-31"}])
        note = remedify.detect_eol_live("ubuntu", "18.04", today=TODAY)
        self.assertIsNotNone(note)
        self.assertIn("end-of-life", note)
        self.assertIn("2023-05-31", note)

    def test_supported_not_flagged(self):
        self._stub([{"cycle": "22.04", "eol": "2027-04-01"}])
        self.assertIsNone(remedify.detect_eol_live("ubuntu", "22.04", today=TODAY))

    def test_eol_boolean_true(self):
        self._stub([{"cycle": "8", "eol": True}])
        self.assertIsNotNone(remedify.detect_eol_live("debian", "8", today=TODAY))

    def test_network_failure_falls_back_to_static(self):
        def boom(url, timeout=10):
            raise OSError("no network")
        remedify._http_get_json = boom
        # 18.04 is in the static table → still flagged despite network failure
        self.assertIsNotNone(remedify.detect_eol_live("ubuntu", "18.04", today=TODAY))
        # a supported version with no static entry → None, no crash
        self.assertIsNone(remedify.detect_eol_live("ubuntu", "24.04", today=TODAY))

    def test_malformed_api_response_is_safe(self):
        self._stub({"not": "a list"})
        # falls back to static; 18.04 still flagged
        self.assertIsNotNone(remedify.detect_eol_live("ubuntu", "18.04", today=TODAY))

    def test_cache_avoids_second_call(self):
        calls = []
        remedify._http_get_json = lambda url, timeout=10: (
            calls.append(url) or [{"cycle": "12", "eol": "2028-06-30"}])
        remedify.detect_eol_live("debian", "12", today=TODAY)
        remedify.detect_eol_live("debian", "12", today=TODAY)
        self.assertEqual(len(calls), 1)  # second read hit the cache

    def test_unknown_family_uses_static(self):
        self._stub([])
        # gentoo isn't mapped to an endoflife product → static (also None)
        self.assertIsNone(remedify.detect_eol_live("gentoo", "2.15", today=TODAY))

    def test_default_build_plan_is_offline(self):
        # build_plan without eol_fn must not call the network
        def boom(url, timeout=10):
            raise AssertionError("network called in offline default")
        remedify._http_get_json = boom
        data = {"ArtifactName": "x",
                "Metadata": {"OS": {"Family": "ubuntu", "Name": "18.04"}},
                "Results": []}
        plan = remedify.build_plan(remedify.parse_trivy(data))
        self.assertIn("ESM", plan["eol_warning"])  # from static table


if __name__ == "__main__":
    unittest.main()
