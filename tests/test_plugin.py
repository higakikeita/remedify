"""Trivy plugin wrapper (remedify-trivy) + plugin.yaml sanity."""

import os
import re
import subprocess
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
WRAPPER = os.path.join(ROOT, "remedify-trivy")
EXAMPLES = os.path.join(ROOT, "examples")


class TestPluginWrapper(unittest.TestCase):
    def test_output_plugin_mode_reads_stdin(self):
        # Trivy output-plugin mode: report piped on stdin, no file arg
        with open(os.path.join(EXAMPLES, "trivy-ubuntu.json"), encoding="utf-8") as f:
            r = subprocess.run(["sh", WRAPPER], stdin=f,
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Remediation plan", r.stdout)

    def test_output_plugin_mode_passes_flags(self):
        with open(os.path.join(EXAMPLES, "trivy-ubuntu.json"), encoding="utf-8") as f:
            r = subprocess.run(["sh", WRAPPER, "--format=shell"], stdin=f,
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#!/usr/bin/env bash", r.stdout)

    def test_file_arg_mode(self):
        # trivy remedify scan.json
        r = subprocess.run(
            ["sh", WRAPPER, os.path.join(EXAMPLES, "trivy-ubuntu.json")],
            stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Remediation plan", r.stdout)

    def test_file_arg_followed_by_flag(self):
        # Regression (#5): a flag AFTER the file must not misroute to stdin.
        # `trivy remedify scan.json --format shell` -> last arg is "shell".
        scan = os.path.join(EXAMPLES, "trivy-ubuntu.json")
        for tail in (["--format", "shell"], ["--format=shell"]):
            r = subprocess.run(["sh", WRAPPER, scan, *tail],
                               stdin=subprocess.DEVNULL,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{tail}: {r.stderr}")
            self.assertIn("#!/usr/bin/env bash", r.stdout, tail)

    def test_flag_before_file(self):
        # the already-working reversed order must keep working
        scan = os.path.join(EXAMPLES, "trivy-ubuntu.json")
        r = subprocess.run(["sh", WRAPPER, "--format", "shell", scan],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("#!/usr/bin/env bash", r.stdout)

    def test_file_arg_followed_by_flag_does_not_double_source(self):
        # explicit guard against the exact failure: "-" AND a file both passed
        scan = os.path.join(EXAMPLES, "trivy-ubuntu.json")
        r = subprocess.run(["sh", WRAPPER, scan, "--min-severity", "HIGH"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("usage:", r.stderr.lower())


class TestPluginManifest(unittest.TestCase):
    def test_manifest_has_required_fields(self):
        with open(os.path.join(ROOT, "plugin.yaml"), encoding="utf-8") as f:
            text = f.read()
        for field in ("name:", "version:", "repository:", "maintainer:",
                      "summary:", "description:", "platforms:", "bin:", "uri:"):
            self.assertIn(field, text, f"plugin.yaml missing {field}")

    def test_manifest_version_matches_package(self):
        import sys
        sys.path.insert(0, ROOT)
        import remedify
        with open(os.path.join(ROOT, "plugin.yaml"), encoding="utf-8") as f:
            m = re.search(r'version:\s*"([^"]+)"', f.read())
        self.assertEqual(m.group(1), remedify.__version__,
                         "plugin.yaml version must match remedify.__version__ "
                         "(bump both on release)")


if __name__ == "__main__":
    unittest.main()
