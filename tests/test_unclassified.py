"""Regression: unknown ecosystems must be SURFACED, never silently dropped (#2).

The core promise is "never silently drop a finding". Before this fix every
parser `continue`-skipped a finding whose ecosystem/package-type it did not
recognise (conda, julia, swift, elixir/Hex, ...): it landed in no bucket and
was invisible — the exact opposite of a security tool's job.

Each test feeds one recognised-but-unmappable finding at CRITICAL and asserts
it reaches the `unclassified` bucket, appears in the rendered output (markdown
+ json + shell), is NOT turned into a command, and trips the --fail-on gate.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402


def _assert_surfaced(tc, parsed, pkg, cve, ecosystem):
    plan = remedify.build_plan(parsed)

    # 1. reached the unclassified bucket
    entry = next((u for u in plan["unclassified"] if u["package"] == pkg), None)
    tc.assertIsNotNone(entry, f"{pkg}: unknown ecosystem was dropped, not surfaced")
    tc.assertEqual(entry["ecosystem"], ecosystem)
    tc.assertIn(cve, entry["cves"])
    tc.assertEqual(entry["severity"], "CRITICAL")

    # 2. NOT turned into a command (unknown pkg manager) — absent from steps/app
    for coll in ("steps", "app_steps"):
        for s in plan[coll]:
            tc.assertNotIn(pkg, s.get("packages", []))
            tc.assertNotEqual(s.get("package"), pkg)

    # 3. visible in every human/machine output (nothing vanishes)
    md = remedify.render_markdown(plan)
    js = remedify.render_json(plan)
    sh = remedify.render_shell(plan)
    for out, label in ((md, "markdown"), (js, "json"), (sh, "shell")):
        tc.assertIn(cve, out, f"{cve} missing from {label} output (silently dropped)")
        tc.assertIn(pkg, out, f"{pkg} missing from {label} output")

    return plan


class TestUnclassifiedSurfacing(unittest.TestCase):
    def test_trivy_unknown_lang_type(self):
        data = {
            "ArtifactName": "app:latest",
            "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
            "Results": [{
                "Class": "lang-pkgs", "Type": "conda", "Target": "environment.yml",
                "Vulnerabilities": [{
                    "PkgName": "numpy", "InstalledVersion": "1.0",
                    "FixedVersion": "1.1", "Severity": "CRITICAL",
                    "VulnerabilityID": "CVE-2024-0001",
                }],
            }],
        }
        _assert_surfaced(self, remedify.parse_trivy(data),
                         "numpy", "CVE-2024-0001", "conda")

    def test_grype_unknown_artifact_type(self):
        data = {"matches": [{
            "vulnerability": {"id": "CVE-2024-0002", "severity": "Critical",
                              "fix": {"state": "fixed", "versions": ["2.0"]}},
            "artifact": {"name": "widget", "version": "1.0", "type": "conda",
                         "locations": [{"path": "/opt/env"}]},
        }]}
        _assert_surfaced(self, remedify.parse_grype(data),
                         "widget", "CVE-2024-0002", "conda")

    def test_osv_unknown_ecosystem(self):
        data = {"results": [{
            "source": {"path": "mix.lock"},
            "packages": [{
                "package": {"name": "plug", "version": "1.0", "ecosystem": "Hex"},
                "vulnerabilities": [{
                    "id": "CVE-2024-0003",
                    "affected": [{"ranges": [{"events": [{"fixed": "1.5"}]}]}],
                    "database_specific": {"severity": "CRITICAL"},
                }],
            }],
        }]}
        _assert_surfaced(self, remedify.parse_osv(data),
                         "plug", "CVE-2024-0003", "Hex")

    def test_sysdig_csv_unknown_pkg_type(self):
        csv_text = (
            "Vulnerability ID,Package Name,Package Version,Fix Version,"
            "Severity,Package Type\n"
            "CVE-2024-0004,leftpad,1.0,1.1,Critical,conda\n"
        )
        _assert_surfaced(self, remedify.parse_sysdig_csv(csv_text),
                         "leftpad", "CVE-2024-0004", "conda")

    def test_sysdig_json_unknown_pkg_type(self):
        data = {"result": {
            "metadata": {"pullString": "img:tag"},
            "packages": [{
                "type": "conda", "name": "scipy", "version": "1.0",
                "vulns": [{"name": "CVE-2024-0005",
                           "severity": {"value": "Critical"},
                           "fixedInVersion": "1.2"}],
            }],
        }}
        _assert_surfaced(self, remedify.parse_sysdig_json(data),
                         "scipy", "CVE-2024-0005", "conda")

    def test_known_and_unknown_coexist(self):
        # a mappable python finding AND an unmappable conda finding in one scan:
        # the known one becomes an app step, the unknown one is surfaced apart.
        data = {
            "ArtifactName": "app:latest",
            "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
            "Results": [
                {"Class": "lang-pkgs", "Type": "pip", "Target": "req.txt",
                 "Vulnerabilities": [{"PkgName": "django", "InstalledVersion": "3.0",
                                      "FixedVersion": "3.2", "Severity": "HIGH",
                                      "VulnerabilityID": "CVE-2024-1000"}]},
                {"Class": "lang-pkgs", "Type": "conda", "Target": "env.yml",
                 "Vulnerabilities": [{"PkgName": "numpy", "InstalledVersion": "1.0",
                                      "FixedVersion": "1.1", "Severity": "CRITICAL",
                                      "VulnerabilityID": "CVE-2024-1001"}]},
            ],
        }
        plan = remedify.build_plan(remedify.parse_trivy(data))
        self.assertTrue(any(s["package"] == "django" for s in plan["app_steps"]))
        self.assertTrue(any(u["package"] == "numpy" for u in plan["unclassified"]))
        self.assertFalse(any(u["package"] == "django" for u in plan["unclassified"]))

    def test_fail_on_gate_trips_on_unclassified(self):
        # a CRITICAL that we can't command-ify must still fail a --fail-on gate,
        # otherwise it is a silent pass — the CI-gate variant of the drop bug.
        data = {"result": {
            "metadata": {"pullString": "img:tag"},
            "packages": [{
                "type": "conda", "name": "scipy", "version": "1.0",
                "vulns": [{"name": "CVE-2024-0006",
                           "severity": {"value": "Critical"},
                           "fixedInVersion": "1.2"}],
            }],
        }}
        with open(os.path.join(os.path.dirname(__file__), "_uc_scan.json"), "w") as f:
            json.dump(data, f)
        path = os.path.join(os.path.dirname(__file__), "_uc_scan.json")
        try:
            argv = sys.argv
            sys.argv = ["remedify", path, "--input", "sysdig-json",
                        "--fail-on", "CRITICAL"]
            with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()):
                remedify.main()
            self.assertEqual(cm.exception.code, 2)
        finally:
            sys.argv = argv
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
