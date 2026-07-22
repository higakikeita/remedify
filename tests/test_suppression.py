"""VEX / ignore-list suppression (#15, ADR-0009 "A").

A planner that re-surfaces already-judged findings gets abandoned as noise, so
remedify suppresses findings a team has triaged — but MECHANICALLY (from
OpenVEX / .remedifyignore, never an LLM) and WITHOUT dropping them: suppressed
findings leave the actionable plan and reappear in a Suppressed section with a
reason (same principle as never-silently-drop, #2).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402


def scan(*vulns):
    """vulns: (pkg, cve, fixed, severity) tuples -> a trivy ubuntu scan."""
    return {"ArtifactName": "img:v1",
            "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
            "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
                {"PkgName": p, "InstalledVersion": "1.0", "FixedVersion": fx,
                 "Severity": sv, "VulnerabilityID": c}
                for (p, c, fx, sv) in vulns]}]}


def plan_with(scan_data, vex=None, ignore=None):
    parsed = remedify.parse_trivy(scan_data)
    remedify.apply_suppressions(parsed, remedify.build_suppressor(vex, ignore))
    return remedify.build_plan(parsed)


def step_cves(plan):
    return {c for s in plan["steps"] for c in s["cves"]}


def step_pkgs(plan):
    return {p for s in plan["steps"] for p in s["packages"]}


def _tmp(text, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


class TestIgnoreList(unittest.TestCase):
    def test_cve_any_scope(self):
        ig = _tmp("CVE-1  # risk accepted\n", ".remedifyignore")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "CRITICAL"),
                                  ("curl", "CVE-2", "8.0", "HIGH")), ignore=[ig])
        finally:
            os.remove(ig)
        self.assertNotIn("CVE-1", step_cves(plan))       # gone from actionable plan
        self.assertNotIn("openssl", step_pkgs(plan))     # only had CVE-1 -> whole pkg out
        self.assertIn("curl", step_pkgs(plan))           # untouched
        sup = plan["suppressed"]
        self.assertEqual(len(sup), 1)
        self.assertEqual(sup[0]["cve"], "CVE-1")
        self.assertEqual(sup[0]["package"], "openssl")
        self.assertIn("risk accepted", sup[0]["reason"])
        self.assertEqual(sup[0]["source"], "ignore")

    def test_cve_package_scope_only_hits_that_package(self):
        # same CVE on two packages; scope the ignore to openssl only
        ig = _tmp("CVE-1 openssl\n", ".remedifyignore")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "HIGH"),
                                  ("curl", "CVE-1", "8.0", "HIGH")), ignore=[ig])
        finally:
            os.remove(ig)
        self.assertNotIn("openssl", step_pkgs(plan))
        self.assertIn("curl", step_pkgs(plan))            # curl's CVE-1 still actionable
        self.assertEqual([s["package"] for s in plan["suppressed"]], ["openssl"])

    def test_whole_package_scope(self):
        ig = _tmp("pkg:curl\n", ".remedifyignore")
        try:
            plan = plan_with(scan(("curl", "CVE-2", "8.0", "HIGH"),
                                  ("curl", "CVE-3", "8.0", "CRITICAL"),
                                  ("openssl", "CVE-1", "1.1", "HIGH")), ignore=[ig])
        finally:
            os.remove(ig)
        self.assertNotIn("curl", step_pkgs(plan))
        self.assertIn("openssl", step_pkgs(plan))
        self.assertEqual({s["cve"] for s in plan["suppressed"]}, {"CVE-2", "CVE-3"})

    def test_partial_suppression_recomputes_severity(self):
        # one CVE suppressed, one kept -> package stays, severity drops CRIT->HIGH
        ig = _tmp("CVE-1\n", ".remedifyignore")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "CRITICAL"),
                                  ("openssl", "CVE-2", "1.1", "HIGH")), ignore=[ig])
        finally:
            os.remove(ig)
        self.assertIn("openssl", step_pkgs(plan))
        step = next(s for s in plan["steps"] if "openssl" in s["packages"])
        self.assertEqual(step["severity"], "HIGH")        # not CRITICAL anymore
        self.assertEqual(step["cves"], ["CVE-2"])
        self.assertEqual([s["cve"] for s in plan["suppressed"]], ["CVE-1"])


class TestVex(unittest.TestCase):
    @staticmethod
    def _vex(status, cve="CVE-1", product="pkg:deb/ubuntu/openssl@1.0",
             justification="vulnerable_code_not_in_execute_path"):
        doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://x",
               "author": "team", "timestamp": "2026-01-01T00:00:00Z", "version": 1,
               "statements": [{"vulnerability": {"name": cve},
                               "products": [{"@id": product}],
                               "status": status, "justification": justification}]}
        return _tmp(json.dumps(doc), ".vex.json")

    def test_not_affected_is_suppressed(self):
        vex = self._vex("not_affected")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "CRITICAL")), vex=[vex])
        finally:
            os.remove(vex)
        self.assertNotIn("openssl", step_pkgs(plan))
        self.assertEqual(len(plan["suppressed"]), 1)
        self.assertEqual(plan["suppressed"][0]["source"], "vex")
        self.assertIn("not_affected", plan["suppressed"][0]["reason"])

    def test_affected_is_not_suppressed(self):
        vex = self._vex("affected")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "CRITICAL")), vex=[vex])
        finally:
            os.remove(vex)
        self.assertIn("openssl", step_pkgs(plan))         # still actionable
        self.assertEqual(plan["suppressed"], [])

    def test_product_scoping(self):
        # VEX clears CVE-1 on openssl; the same CVE on curl stays actionable
        vex = self._vex("not_affected")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "HIGH"),
                                  ("curl", "CVE-1", "8.0", "HIGH")), vex=[vex])
        finally:
            os.remove(vex)
        self.assertIn("curl", step_pkgs(plan))
        self.assertNotIn("openssl", step_pkgs(plan))


class TestSuppressionSurfacing(unittest.TestCase):
    def test_no_flags_no_suppressed(self):
        plan = plan_with(scan(("openssl", "CVE-1", "1.1", "HIGH")))
        self.assertEqual(plan["suppressed"], [])

    def test_markdown_lists_reason(self):
        ig = _tmp("CVE-1  # false positive per appsec\n", ".remedifyignore")
        try:
            plan = plan_with(scan(("openssl", "CVE-1", "1.1", "HIGH")), ignore=[ig])
        finally:
            os.remove(ig)
        md = remedify.render_markdown(plan)
        self.assertIn("Suppressed", md)
        self.assertIn("CVE-1", md)
        self.assertIn("false positive per appsec", md)

    def test_suppressed_critical_does_not_trip_fail_on(self):
        # a suppressed CRITICAL must not fail the CI gate (it's been judged)
        scan_data = scan(("openssl", "CVE-1", "1.1", "CRITICAL"))
        script = os.path.join(os.path.dirname(__file__), "..", "remedify.py")
        scanf = _tmp(json.dumps(scan_data), ".json")
        ig = _tmp("CVE-1  # accepted\n", ".remedifyignore")
        try:
            r = subprocess.run(
                [sys.executable, script, scanf, "--ignore", ig,
                 "--fail-on", "CRITICAL"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)     # gate not tripped
            self.assertIn("Suppressed", r.stdout)
            # sanity: without the ignore the same scan DOES trip the gate
            r2 = subprocess.run(
                [sys.executable, script, scanf, "--fail-on", "CRITICAL"],
                capture_output=True, text=True)
            self.assertEqual(r2.returncode, 2)
        finally:
            os.remove(scanf)
            os.remove(ig)


if __name__ == "__main__":
    unittest.main()
