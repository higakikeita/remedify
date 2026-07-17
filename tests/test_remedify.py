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
    def test_skips_unfixed_vulns(self):
        parsed = remedify.parse_trivy(load("trivy-real-ubuntu1804.json"))
        self.assertNotIn("bash", parsed["findings"])  # no FixedVersion

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
