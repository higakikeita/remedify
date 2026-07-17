"""verify — closed-loop diff of before/after scans. All classification rides on
compare_versions (already property-tested vs. dpkg), so these tests focus on
the decision tree and scoring."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def load(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return json.load(f)


class TestVerifyClassification(unittest.TestCase):
    def setUp(self):
        self.v = remedify.verify(
            remedify.parse_trivy(load("verify-before.json")),
            remedify.parse_trivy(load("verify-after.json")))

    def _reason(self, cve):
        for r in self.v["remaining"] + self.v["anomalies"]:
            if r["cve"] == cve:
                return r["reason"]
        return None

    def test_resolved(self):
        cves = {r["cve"] for r in self.v["resolved"]}
        self.assertIn("CVE-RESOLVED-1", cves)   # curl gone
        self.assertIn("CVE-RESOLVED-2", cves)   # libc6 gone
        self.assertIn("CVE-REMOVED-1", cves)    # telnet package removed

    def test_upgraded_but_short(self):
        self.assertEqual(self._reason("CVE-SHORT-1"), "upgraded_but_short")

    def test_untouched(self):
        self.assertEqual(self._reason("CVE-UNTOUCHED-1"), "untouched")

    def test_regressed(self):
        self.assertEqual(self._reason("CVE-REGRESS-1"), "regressed")

    def test_no_fix(self):
        self.assertEqual(self._reason("CVE-NOFIX-1"), "no_fix")

    def test_now_fixable(self):
        self.assertEqual(self._reason("CVE-NOWFIX-1"), "now_fixable")

    def test_anomaly(self):
        # installed >= fix version but still reported
        self.assertEqual([a["cve"] for a in self.v["anomalies"]], ["CVE-ANOM-1"])

    def test_new(self):
        self.assertEqual([n["cve"] for n in self.v["new"]], ["CVE-NEW-1"])

    def test_score(self):
        s = self.v["score"]
        self.assertEqual(s["resolved"], 3)
        self.assertEqual(s["fixable"], 7)          # 3 resolved + 4 actionable
        self.assertEqual(s["unfixable_remaining"], 1)  # vim
        self.assertEqual(s["new"], 1)
        self.assertEqual(s["anomalies"], 1)

    def test_backport_note_on_short(self):
        short = next(r for r in self.v["remaining"] if r["cve"] == "CVE-SHORT-1")
        self.assertEqual(short["backport"], "Ubuntu")


class TestVerifyBehavior(unittest.TestCase):
    def test_same_scan_all_untouched(self):
        p = remedify.parse_trivy(load("verify-before.json"))
        v = remedify.verify(p, remedify.parse_trivy(load("verify-before.json")))
        self.assertEqual(v["score"]["resolved"], 0)
        self.assertEqual(v["new"], [])

    def test_cross_format_before_grype_after_trivy(self):
        # design goal: mix scanners across the two scans
        v = remedify.verify(
            remedify.parse_grype(load("grype-ubuntu.json")),
            remedify.parse_trivy(load("trivy-ubuntu.json")))
        self.assertIsInstance(v["score"]["rate"], float)  # no crash

    def test_exit_code_gate(self):
        v = self.v = remedify.verify(
            remedify.parse_trivy(load("verify-before.json")),
            remedify.parse_trivy(load("verify-after.json")))
        self.assertEqual(remedify.verify_exit_code(v, "CRITICAL"), 0)
        self.assertEqual(remedify.verify_exit_code(v, "HIGH"), 2)
        self.assertEqual(remedify.verify_exit_code(v, None), 0)

    def test_no_fix_never_trips_gate(self):
        # a lone unfixable remaining must not fail CI
        before = {"ArtifactName": "x", "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
                  "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
                      {"VulnerabilityID": "C1", "PkgName": "vim",
                       "InstalledVersion": "1", "FixedVersion": "", "Severity": "CRITICAL"}]}]}
        v = remedify.verify(remedify.parse_trivy(before), remedify.parse_trivy(before))
        self.assertEqual(remedify.verify_exit_code(v, "CRITICAL"), 0)


class TestVerifyCli(unittest.TestCase):
    def _run(self, *args):
        script = os.path.join(os.path.dirname(__file__), "..", "remedify.py")
        return subprocess.run([sys.executable, script, *args],
                              capture_output=True, text=True)

    def test_markdown_cli(self):
        r = self._run("--baseline", os.path.join(EXAMPLES, "verify-before.json"),
                      os.path.join(EXAMPLES, "verify-after.json"))
        self.assertEqual(r.returncode, 0)
        self.assertIn("Remediation verification", r.stdout)
        self.assertIn("Still vulnerable", r.stdout)

    def test_json_cli(self):
        r = self._run("--baseline", os.path.join(EXAMPLES, "verify-before.json"),
                      os.path.join(EXAMPLES, "verify-after.json"), "--format", "json")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["score"]["resolved"], 3)

    def test_baseline_without_after_errors(self):
        r = self._run("--baseline", os.path.join(EXAMPLES, "verify-before.json"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("two scans", r.stderr)


if __name__ == "__main__":
    unittest.main()
