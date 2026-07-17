import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def load(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return json.load(f)


class TestParser(unittest.TestCase):
    def test_unfixed_vulns_tracked_separately(self):
        parsed = remedify.parse_trivy(load("trivy-real-ubuntu1804.json"))
        self.assertNotIn("bash", parsed["findings"])  # no FixedVersion
        self.assertIn("bash", parsed["unfixed"])      # ...but not silently dropped
        self.assertEqual(parsed["unfixed"]["bash"]["vulns"][0]["status"], "affected")

    def test_groups_cves_per_package(self):
        parsed = remedify.parse_trivy(load("trivy-ubuntu.json"))
        libssl = parsed["findings"]["libssl3"]
        self.assertEqual(len(libssl["vulns"]), 2)
        self.assertEqual(libssl["max_severity"], "HIGH")


class TestPlan(unittest.TestCase):
    def test_apt_command(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-ubuntu.json")))
        item = next(i for i in plan["items"] if i["package"] == "libssl3")
        self.assertEqual(
            item["command"],
            "apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18")
        self.assertEqual(item["backport"], "Ubuntu")

    def test_dnf_command(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-rhel.json")))
        item = next(i for i in plan["items"] if i["package"] == "glibc")
        self.assertTrue(item["command"].startswith("dnf update -y glibc-"))
        self.assertEqual(item["backport"], "RHEL")

    def test_min_severity_filter(self):
        plan = remedify.build_plan(
            remedify.parse_trivy(load("trivy-rhel.json")), min_severity="HIGH")
        self.assertEqual([i["package"] for i in plan["items"]], ["glibc"])

    def test_highest_fixed_version_wins(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-ubuntu.json")))
        item = next(i for i in plan["items"] if i["package"] == "libssl3")
        self.assertEqual(item["fix_version"], "3.0.2-0ubuntu1.18")

    def test_kernel_reboot_hint(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-ubuntu.json")))
        item = next(i for i in plan["items"] if i["package"] == "linux-image-generic")
        self.assertTrue(any("reboot" in h.lower() for h in item["hints"]))


class TestConsolidation(unittest.TestCase):
    """v0.2: real scans report one CVE across N binary packages from one source."""

    def setUp(self):
        self.plan = remedify.build_plan(
            remedify.parse_trivy(load("trivy-real-ubuntu1804.json")))

    def test_e2fsprogs_family_collapses_to_one_step(self):
        self.assertEqual(len(self.plan["items"]), 4)   # 4 binary packages...
        self.assertEqual(len(self.plan["steps"]), 1)   # ...one remediation step
        step = self.plan["steps"][0]
        self.assertEqual(sorted(step["packages"]),
                         ["e2fsprogs", "libcom-err2", "libext2fs2", "libss2"])

    def test_consolidated_command_lists_all_packages(self):
        cmd = self.plan["steps"][0]["command"]
        for pkg in ("e2fsprogs", "libcom-err2", "libext2fs2", "libss2"):
            self.assertIn(f"{pkg}=1.44.1-1ubuntu1.2", cmd)

    def test_unfixed_section_present(self):
        self.assertEqual(len(self.plan["unfixed"]), 1)
        u = self.plan["unfixed"][0]
        self.assertEqual(u["package"], "bash")
        self.assertIn("CVE-2019-18276", u["cves"])
        self.assertIn("No vendor fix", u["status_label"])

    def test_eol_warning_for_ubuntu_1804(self):
        self.assertIsNotNone(self.plan["eol_warning"])
        self.assertIn("ESM", self.plan["eol_warning"])

    def test_no_eol_warning_for_supported_os(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-rhel.json")))
        self.assertIsNone(plan["eol_warning"])

    def test_advisory_family_dedup(self):
        # USN-4142-1 and USN-4142-2 should collapse to one entry
        advisories = [u for _, u in self.plan["steps"][0]["advisories"]]
        usn = [u for u in advisories if "USN-4142" in u]
        self.assertEqual(len(usn), 1)


class TestDistroCoverage(unittest.TestCase):
    """v0.3: every supported package manager, from realistic fixtures."""

    def test_alpine_apk_command(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-alpine.json")))
        self.assertEqual(plan["pkg_manager"], "apk")
        step = plan["steps"][0]
        # libcrypto3 + libssl3 share installed/fixed versions -> one step
        self.assertEqual(sorted(step["packages"]), ["libcrypto3", "libssl3"])
        self.assertEqual(step["command"], "apk upgrade libcrypto3 libssl3")

    def test_amazon_linux_2_uses_yum(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-amazon2.json")))
        self.assertEqual(plan["pkg_manager"], "yum")
        kernel = next(s for s in plan["steps"] if "kernel" in s["packages"])
        self.assertTrue(kernel["command"].startswith("yum update -y kernel-"))
        self.assertEqual(kernel["backport"], "Amazon Linux")
        self.assertTrue(any("reboot" in h.lower() for h in kernel["hints"]))

    def test_amazon_alas_advisory_surfaced(self):
        plan = remedify.build_plan(remedify.parse_trivy(load("trivy-amazon2.json")))
        kernel = next(s for s in plan["steps"] if "kernel" in s["packages"])
        labels = [label for label, _ in kernel["advisories"]]
        self.assertIn("Amazon ALAS", labels)

    def test_unsupported_os_family_degrades_gracefully(self):
        data = load("trivy-alpine.json")
        data["Metadata"]["OS"]["Family"] = "windows"
        plan = remedify.build_plan(remedify.parse_trivy(data))
        self.assertIsNone(plan["pkg_manager"])
        self.assertIsNone(plan["steps"][0]["command"])
        md = remedify.render_markdown(plan)
        self.assertIn("Unsupported OS family", md)


class TestStatusHandling(unittest.TestCase):
    """v0.3: Trivy Status values map to distinct guidance."""

    def setUp(self):
        self.plan = remedify.build_plan(
            remedify.parse_trivy(load("trivy-centos7-eol.json")))

    def test_centos7_eol_warning(self):
        self.assertIsNotNone(self.plan["eol_warning"])
        self.assertIn("end-of-life", self.plan["eol_warning"])

    def test_will_not_fix_label(self):
        u = next(x for x in self.plan["unfixed"] if x["package"] == "bind-license")
        self.assertIn("will not fix", u["status_label"].lower())

    def test_end_of_life_label(self):
        u = next(x for x in self.plan["unfixed"] if x["package"] == "openssl-libs")
        self.assertIn("EOL", u["status_label"])

    def test_unfixed_survives_min_severity_filter(self):
        # min-severity must never hide unfixed findings (trust!)
        plan = remedify.build_plan(
            remedify.parse_trivy(load("trivy-centos7-eol.json")),
            min_severity="CRITICAL")
        self.assertEqual(len(plan["steps"]), 0)
        self.assertEqual(len(plan["unfixed"]), 2)

    def test_unfixed_sorted_by_severity(self):
        sevs = [u["severity"] for u in self.plan["unfixed"]]
        self.assertEqual(sevs, ["HIGH", "LOW"])


class TestEdgeCases(unittest.TestCase):
    def test_multiple_fixed_version_candidates(self):
        data = load("trivy-alpine.json")
        data["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "3.1.5-r0, 3.2.1-r0"
        parsed = remedify.parse_trivy(data)
        self.assertEqual(
            remedify.highest_version(parsed["findings"]["libcrypto3"]["fixed_versions"]),
            "3.2.1-r0")

    def test_empty_results(self):
        plan = remedify.build_plan(remedify.parse_trivy(
            {"ArtifactName": "x", "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
             "Results": []}))
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["unfixed"], [])
        remedify.render_markdown(plan)  # must not crash

    def test_missing_metadata(self):
        plan = remedify.build_plan(remedify.parse_trivy({"Results": []}))
        self.assertIsNone(plan["pkg_manager"])

    def test_lang_pkgs_skipped(self):
        data = load("trivy-alpine.json")
        data["Results"].append({
            "Target": "app/package-lock.json", "Class": "lang-pkgs", "Type": "npm",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-9999",
                                 "PkgName": "lodash", "InstalledVersion": "4.0.0",
                                 "FixedVersion": "4.17.21", "Severity": "HIGH"}]})
        parsed = remedify.parse_trivy(data)
        self.assertNotIn("lodash", parsed["findings"])


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.plan = remedify.build_plan(
            remedify.parse_trivy(load("trivy-real-ubuntu1804.json")))

    def test_markdown_contains_advisories(self):
        md = remedify.render_markdown(self.plan)
        self.assertIn("ubuntu.com/security/notices/USN-4142-1", md)

    def test_shell_is_commented_and_safe(self):
        sh = remedify.render_shell(self.plan)
        self.assertIn("set -euo pipefail", sh)
        self.assertIn("apt-get update", sh)

    def test_json_roundtrip(self):
        json.loads(remedify.render_json(self.plan))


if __name__ == "__main__":
    unittest.main()
