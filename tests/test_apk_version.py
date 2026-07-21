"""Regression: apk pre-release ordering must not pin a release candidate (#3).

dpkg treats '_' as an ordinary character sorting AFTER the base version, so the
dpkg comparator ranks `1.5.0_rc1` ABOVE `1.5.0` and highest_version() would pin
the release candidate as the "fix" — which lacks the final patch (and is often
absent from the stable repo, so `apk add pkg=1.5.0_rc1` fails).

Alpine's apk treats _alpha/_beta/_pre/_rc as PRE-release (below the base) and
_p as POST-release. These tests pin the correct apk ordering and assert the
alpine plan picks the release, not the candidate, across all parsers that feed
apk fix versions (trivy/sysdig via build_plan, grype, osv).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402


def sign(n):
    return (n > 0) - (n < 0)


class TestApkComparator(unittest.TestCase):
    ORDER = [  # strictly increasing in apk semantics. Note: the release-phase
        # suffix is ranked before the -rN revision, so a post-release _p1
        # (rev 0) outranks a bare release with -r1.
        "1.5.0_alpha1", "1.5.0_beta1", "1.5.0_pre1", "1.5.0_rc1", "1.5.0_rc2",
        "1.5.0", "1.5.0-r1", "1.5.0_p1",
    ]

    def test_suffix_ordering_is_monotonic(self):
        for i in range(len(self.ORDER)):
            for j in range(len(self.ORDER)):
                want = sign(i - j)
                got = sign(remedify.compare_versions_apk(self.ORDER[i], self.ORDER[j]))
                self.assertEqual(got, want,
                                 f"apk cmp({self.ORDER[i]}, {self.ORDER[j]}) "
                                 f"= {got}, want {want}")

    def test_prerelease_below_release(self):
        # the exact bug-report case
        self.assertEqual(remedify.compare_versions_apk("1.5.0_rc1", "1.5.0"), -1)
        self.assertEqual(remedify.compare_versions_apk("1.5.0", "1.5.0_rc1"), 1)

    def test_post_release_above_release(self):
        self.assertEqual(remedify.compare_versions_apk("1.5.0_p1", "1.5.0"), 1)

    def test_letter_and_revision(self):
        self.assertEqual(remedify.compare_versions_apk("1.1.1n-r0", "1.1.1m-r0"), 1)
        self.assertEqual(remedify.compare_versions_apk("3.1.5-r1", "3.1.5-r0"), 1)
        self.assertEqual(remedify.compare_versions_apk("3.1.5-r0", "3.2.1-r0"), -1)

    def test_highest_version_scheme_dispatch(self):
        vs = ["1.5.0", "1.5.0_rc1"]
        # apk: the release wins; dpkg (the old, wrong path): the rc "wins"
        self.assertEqual(remedify.highest_version(vs, scheme="apk"), "1.5.0")
        self.assertEqual(remedify.highest_version(vs, scheme="dpkg"), "1.5.0_rc1")
        self.assertEqual(remedify.highest_version(vs), "1.5.0_rc1")  # default = dpkg


class TestApkPlanPicksRelease(unittest.TestCase):
    """End-to-end: an alpine plan must never emit `apk add pkg=<rc>`."""

    def test_trivy_alpine(self):
        data = {
            "ArtifactName": "img:alpine",
            "Metadata": {"OS": {"Family": "alpine", "Name": "3.19"}},
            "Results": [{
                "Class": "os-pkgs",
                "Vulnerabilities": [{
                    "PkgName": "libfoo", "InstalledVersion": "1.4.0-r0",
                    "FixedVersion": "1.5.0_rc1, 1.5.0", "Severity": "HIGH",
                    "VulnerabilityID": "CVE-2024-3001",
                }],
            }],
        }
        plan = remedify.build_plan(remedify.parse_trivy(data))
        self.assertEqual(plan["pkg_manager"], "apk")
        step = plan["steps"][0]
        self.assertEqual(step["fix_version"], "1.5.0")
        self.assertIn("libfoo=1.5.0", step["command"])
        self.assertNotIn("_rc1", step["command"])

    def test_grype_alpine(self):
        data = {
            "distro": {"name": "alpine", "version": "3.19"},
            "matches": [{
                "vulnerability": {"id": "CVE-2024-3002", "severity": "High",
                                  "fix": {"state": "fixed",
                                          "versions": ["1.5.0_rc1", "1.5.0"]}},
                "artifact": {"name": "libbar", "version": "1.4.0-r0", "type": "apk"},
            }],
        }
        plan = remedify.build_plan(remedify.parse_grype(data))
        self.assertEqual(plan["pkg_manager"], "apk")
        step = plan["steps"][0]
        self.assertEqual(step["fix_version"], "1.5.0")
        self.assertNotIn("_rc1", step["command"])

    def test_osv_alpine(self):
        data = {"results": [{
            "source": {"path": "img"},
            "packages": [{
                "package": {"name": "libbaz", "version": "1.4.0-r0",
                            "ecosystem": "Alpine:v3.19"},
                "vulnerabilities": [{
                    "id": "CVE-2024-3003",
                    "affected": [{"ranges": [{"events": [
                        {"fixed": "1.5.0_rc1"}, {"fixed": "1.5.0"}]}]}],
                    "database_specific": {"severity": "HIGH"},
                }],
            }],
        }]}
        plan = remedify.build_plan(remedify.parse_osv(data))
        self.assertEqual(plan["pkg_manager"], "apk")
        step = plan["steps"][0]
        self.assertEqual(step["fix_version"], "1.5.0")
        self.assertNotIn("_rc1", step["command"])


class TestApkVerifyPath(unittest.TestCase):
    """Regression (#3, reopened): the verify path must also use apk ordering.
    The first fix covered the plan but left verify on dpkg, so verify pinned the
    _rc as `required` and told an operator at the real fix they were still short.
    """

    @staticmethod
    def _alpine(installed):
        return {"ArtifactName": "img:v1",
                "Metadata": {"OS": {"Family": "alpine", "Name": "3.19"}},
                "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-7777", "PkgName": "libfoo",
                     "InstalledVersion": installed,
                     "FixedVersion": "1.5.0_rc1, 1.5.0", "Severity": "HIGH"}]}]}

    def _verify(self, before_inst, after_inst):
        return remedify.verify(remedify.parse_trivy(self._alpine(before_inst)),
                               remedify.parse_trivy(self._alpine(after_inst)))

    def test_required_is_release_not_rc(self):
        v = self._verify("1.4.0-r0", "1.5.0")
        row = (v["remaining"] + v["anomalies"])[0]
        self.assertEqual(row["required"], "1.5.0")  # not 1.5.0_rc1

    def test_host_at_real_fix_is_not_reported_short(self):
        # installed == real fix, still scanned -> anomaly (at/above fix), and
        # explicitly NOT "upgraded_but_short" (the dpkg-path bug)
        v = self._verify("1.4.0-r0", "1.5.0")
        row = (v["remaining"] + v["anomalies"])[0]
        self.assertEqual(row["reason"], "installed_at_or_above_fix")

    def test_flatten_marks_apk_scheme(self):
        flat = remedify._flatten_findings(remedify.parse_trivy(self._alpine("1.4.0-r0")))
        entry = flat[("libfoo", "CVE-2024-7777")]
        self.assertEqual(entry["scheme"], "apk")
        self.assertEqual(entry["required"], "1.5.0")

    def test_ubuntu_still_dpkg(self):
        # non-apk targets keep dpkg semantics (no regression)
        deb = {"ArtifactName": "img", "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
               "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
                   {"VulnerabilityID": "C1", "PkgName": "bar", "InstalledVersion": "1.0",
                    "FixedVersion": "1.2", "Severity": "HIGH"}]}]}
        flat = remedify._flatten_findings(remedify.parse_trivy(deb))
        self.assertEqual(flat[("bar", "C1")]["scheme"], "dpkg")


if __name__ == "__main__":
    unittest.main()
