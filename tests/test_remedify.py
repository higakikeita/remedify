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


class TestSysdigCsv(unittest.TestCase):
    """v0.4: Sysdig vulnerability report CSV exports."""

    def setUp(self):
        with open(os.path.join(EXAMPLES, "sysdig-report.csv"), encoding="utf-8") as f:
            self.raw = f.read()
        self.parsed = remedify.parse_sysdig_csv(self.raw)
        self.plan = remedify.build_plan(self.parsed)

    def test_os_detected_from_csv(self):
        self.assertEqual(self.parsed["family"], "ubuntu")
        self.assertEqual(self.parsed["os_name"], "22.04")
        self.assertEqual(self.plan["pkg_manager"], "apt")

    def test_target_from_image_column(self):
        self.assertEqual(self.parsed["target"], "prod-api:v2.3.1")

    def test_libc_family_consolidated(self):
        step = next(s for s in self.plan["steps"] if "libc6" in s["packages"])
        self.assertEqual(sorted(step["packages"]), ["libc-bin", "libc6"])
        self.assertEqual(step["severity"], "CRITICAL")

    def test_highest_fix_version_per_package(self):
        step = next(s for s in self.plan["steps"] if "libssl3" in s["packages"])
        self.assertEqual(step["fix_version"], "3.0.2-0ubuntu1.18")

    def test_unfixed_from_empty_fix_column(self):
        self.assertEqual([u["package"] for u in self.plan["unfixed"]], ["bash"])

    def test_language_packages_skipped(self):
        self.assertNotIn("lodash", self.parsed["findings"])

    def test_os_override(self):
        parsed = remedify.parse_sysdig_csv(self.raw, os_override="redhat:9.3")
        plan = remedify.build_plan(parsed)
        self.assertEqual(plan["pkg_manager"], "dnf")

    def test_alias_headers(self):
        raw = ("CVE ID,Vulnerability Severity,Package,Version,Fixed In,Host\n"
               "CVE-2024-0001,High,openssl,1.1.1,1.1.1a,web-01\n")
        parsed = remedify.parse_sysdig_csv(raw, os_override="ubuntu 22.04")
        self.assertIn("openssl", parsed["findings"])
        self.assertEqual(parsed["target"], "web-01")

    def test_format_autodetect(self):
        self.assertEqual(remedify.detect_input_format(self.raw), "sysdig-csv")
        self.assertEqual(remedify.detect_input_format('{"Results": []}'), "trivy")

    def test_parse_os_string_variants(self):
        self.assertEqual(remedify.parse_os_string("Ubuntu 22.04"), ("ubuntu", "22.04"))
        self.assertEqual(remedify.parse_os_string("rhel:9.3"), ("redhat", "9.3"))
        self.assertEqual(remedify.parse_os_string("Red Hat 9.3"), ("redhat", "9.3"))
        self.assertEqual(remedify.parse_os_string(""), ("", ""))


class TestSysdigScanJson(unittest.TestCase):
    """v0.4: sysdig-cli-scanner / VM API scan-result JSON."""

    def setUp(self):
        self.plan = remedify.build_plan(
            remedify.parse_sysdig_json(load("sysdig-scan-result.json")))

    def test_target_and_os_from_metadata(self):
        self.assertEqual(self.plan["target"], "sock-shop/orders:latest")
        self.assertEqual(self.plan["pkg_manager"], "apt")  # debian 11.6

    def test_os_packages_get_commands(self):
        step = next(s for s in self.plan["steps"] if "libssl1.1" in s["packages"])
        self.assertIn("apt-get install --only-upgrade libssl1.1=1.1.1n-0+deb11u5",
                      step["command"])
        self.assertEqual(step["backport"], "Debian")

    def test_java_packages_become_app_steps(self):
        spring = next(s for s in self.plan["app_steps"]
                      if s["package"] == "org.springframework:spring-beans")
        self.assertEqual(spring["ecosystem"], "java")
        self.assertEqual(spring["fix_version"], "5.3.18")
        self.assertIn("CVE-2022-22965", spring["cves"])
        self.assertIn("pom.xml", spring["action"])
        self.assertIn("BOOT-INF/lib/spring-beans-5.3.15.jar",
                      spring["locations"][0])

    def test_npm_action(self):
        lodash = next(s for s in self.plan["app_steps"] if s["package"] == "lodash")
        self.assertIn("npm install lodash@4.17.21", lodash["action"])

    def test_unfixed_os_package(self):
        self.assertEqual([u["package"] for u in self.plan["unfixed"]], ["bash"])

    def test_markdown_has_rebuild_section(self):
        md = remedify.render_markdown(self.plan)
        self.assertIn("Application dependencies (rebuild required)", md)
        self.assertIn("neither can copa", md)

    def test_autodetect_sysdig_json(self):
        with open(os.path.join(EXAMPLES, "sysdig-scan-result.json"), encoding="utf-8") as f:
            self.assertEqual(remedify.detect_input_format(f.read()), "sysdig-json")


class TestLangPkgsTrivy(unittest.TestCase):
    """v0.4: Trivy lang-pkgs results become app steps."""

    def _data_with_npm(self):
        data = load("trivy-alpine.json")
        data["Results"].append({
            "Target": "app/package-lock.json", "Class": "lang-pkgs", "Type": "npm",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-23337",
                                 "PkgName": "lodash", "InstalledVersion": "4.17.20",
                                 "FixedVersion": "4.17.21", "Severity": "HIGH"}]})
        return data

    def test_trivy_lang_pkgs_parsed(self):
        plan = remedify.build_plan(remedify.parse_trivy(self._data_with_npm()))
        self.assertEqual(len(plan["app_steps"]), 1)
        step = plan["app_steps"][0]
        self.assertEqual(step["package"], "lodash")
        self.assertEqual(step["locations"], ["app/package-lock.json"])

    def test_min_severity_applies_to_app_steps(self):
        plan = remedify.build_plan(remedify.parse_trivy(self._data_with_npm()),
                                   min_severity="CRITICAL")
        self.assertEqual(plan["app_steps"], [])

    def test_sysdig_csv_lang_pkg_routed(self):
        with open(os.path.join(EXAMPLES, "sysdig-report.csv"), encoding="utf-8") as f:
            plan = remedify.build_plan(remedify.parse_sysdig_csv(f.read()))
        self.assertEqual([s["package"] for s in plan["app_steps"]], ["lodash"])


class TestSysdigApiV1(unittest.TestCase):
    """v0.5: real VM API v1 response shape (fixture extracted from a live
    tenant response for the public nicolaka/netshoot image).
    packages = dict keyed by id, vulnerabilities = separate dict,
    severity = lowercase string, fixVersion may be null."""

    def setUp(self):
        self.plan = remedify.build_plan(
            remedify.parse_sysdig_json(load("sysdig-api-v1.json")))

    def test_metadata(self):
        self.assertEqual(self.plan["target"], "nicolaka/netshoot:latest")
        self.assertEqual(self.plan["pkg_manager"], "apk")  # alpine 3.24.1

    def test_vulnerabilities_refs_resolved(self):
        step = next(s for s in self.plan["steps"] if "c-ares" in s["packages"])
        self.assertTrue(step["command"].startswith("apk upgrade"))
        self.assertTrue(step["cves"])

    def test_in_use_flag_from_isrunning(self):
        step = next(s for s in self.plan["steps"] if "c-ares" in s["packages"])
        self.assertTrue(step["in_use"])

    def test_null_fixversion_goes_to_unfixed(self):
        self.assertIn("perl", [u["package"] for u in self.plan["unfixed"]])

    def test_go_binary_becomes_app_step(self):
        pkgs = [s["package"] for s in self.plan["app_steps"]]
        self.assertIn("github.com/gogo/protobuf", pkgs)

    def test_priority_badges_render(self):
        md = remedify.render_markdown(self.plan)
        self.assertIn("package in use at runtime", md)


class TestVersionSemantics(unittest.TestCase):
    """dpkg/rpm version ordering — wrong picks = wrong remediation commands."""

    CASES = [
        # (a, b, expected_highest)
        ("1.0~rc1", "1.0", "1.0"),               # tilde sorts before release
        ("1.0~beta1", "1.0~rc1", "1.0~rc1"),
        ("2:1.0", "1:9.9", "2:1.0"),             # epoch wins
        ("1.0", "1.0.1", "1.0.1"),               # longer release
        ("1.44.1-1ubuntu1.2", "1.44.1-1ubuntu1.10", "1.44.1-1ubuntu1.10"),  # numeric not lexical
        ("10.4", "10.3_p1-r0", "10.4"),          # alpine style
        ("3.0.2-0ubuntu1.9", "3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.18"),
        ("2.34-83.el9_3.7", "2.34-83.el9_3.12", "2.34-83.el9_3.12"),
        ("1.2.3", "1.2.3", "1.2.3"),             # equal
    ]

    def test_highest_version_semantics(self):
        for a, b, want in self.CASES:
            got = remedify.highest_version([a, b])
            self.assertEqual(got, want, f"highest({a}, {b}) = {got}, want {want}")
            got = remedify.highest_version([b, a])  # order-independent
            self.assertEqual(got, want, f"highest({b}, {a}) = {got}, want {want}")

    def test_compare_symmetry(self):
        self.assertEqual(remedify.compare_versions("1.0", "1.0"), 0)
        self.assertEqual(remedify.compare_versions("1.0~rc1", "1.0"), -1)
        self.assertEqual(remedify.compare_versions("1.0", "1.0~rc1"), 1)


class TestCliRobustness(unittest.TestCase):
    """The CLI must never traceback on bad input: clean error + exit code 1."""

    def _run(self, *args, stdin=None):
        import subprocess
        script = os.path.join(os.path.dirname(__file__), "..", "remedify.py")
        return subprocess.run([sys.executable, script, *args],
                              capture_output=True, text=True, input=stdin)

    def assertCleanError(self, result, fragment=""):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("error:", result.stderr)
        if fragment:
            self.assertIn(fragment, result.stderr)

    def test_missing_file(self):
        self.assertCleanError(self._run("/nonexistent/scan.json"), "cannot read")

    def test_broken_json(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"Results": [broken')
        self.assertCleanError(self._run(f.name), "not valid JSON")

    def test_empty_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("")
        self.assertCleanError(self._run(f.name), "empty")

    def test_csv_missing_columns(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write("Foo,Bar\n1,2\n")
        self.assertCleanError(self._run(f.name), "required column")

    def test_no_args_without_from_sysdig(self):
        self.assertCleanError(self._run())

    def test_from_sysdig_without_credentials(self):
        import subprocess, os as _os
        env = dict(_os.environ)
        env.pop("SYSDIG_API_TOKEN", None)
        script = os.path.join(os.path.dirname(__file__), "..", "remedify.py")
        r = subprocess.run([sys.executable, script, "--from-sysdig"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)

    def test_stdin_input(self):
        with open(os.path.join(EXAMPLES, "trivy-ubuntu.json"), encoding="utf-8") as f:
            r = self._run("-", stdin=f.read())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Remediation plan", r.stdout)

    def test_bom_and_crlf_csv(self):
        import tempfile
        content = ("﻿CVE ID,Severity,Package,Version,Fix Version,Host\r\n"
                   "CVE-2024-1,High,openssl,1.0,1.1,web-01\r\n")
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False,
                                         encoding="utf-8") as f:
            f.write(content)
        r = self._run(f.name, "--os", "ubuntu:22.04")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("openssl", r.stdout)

    def test_exit_zero_on_success(self):
        r = self._run(os.path.join(EXAMPLES, "sysdig-scan-result.json"))
        self.assertEqual(r.returncode, 0)


class TestParserNullSafety(unittest.TestCase):
    """Real-world data has nulls everywhere. No field may be assumed present."""

    def test_trivy_all_nulls(self):
        data = {"ArtifactName": None, "Metadata": None,
                "Results": [{"Class": "os-pkgs", "Vulnerabilities": [
                    {"VulnerabilityID": None, "PkgName": None,
                     "InstalledVersion": None, "FixedVersion": None,
                     "Severity": None}]}]}
        plan = remedify.build_plan(remedify.parse_trivy(data))
        remedify.render_markdown(plan)
        remedify.render_shell(plan)

    def test_sysdig_json_minimal(self):
        plan = remedify.build_plan(remedify.parse_sysdig_json({"packages": {}}))
        remedify.render_markdown(plan)

    def test_sysdig_json_null_fields(self):
        data = {"metadata": None,
                "packages": {"p": {"type": "os", "name": "x", "version": None,
                                   "vulnerabilitiesRefs": ["v", "missing-ref"]}},
                "vulnerabilities": {"v": {"name": "CVE-1", "severity": None,
                                          "fixVersion": None}}}
        plan = remedify.build_plan(remedify.parse_sysdig_json(data))
        self.assertEqual([u["package"] for u in plan["unfixed"]], ["x"])

    def test_severity_variants(self):
        self.assertEqual(remedify._sysdig_severity("high"), "HIGH")
        self.assertEqual(remedify._sysdig_severity({"value": "Critical"}), "CRITICAL")
        self.assertEqual(remedify._sysdig_severity(0), "CRITICAL")
        self.assertEqual(remedify._sysdig_severity(None), "UNKNOWN")
        self.assertEqual(remedify._sysdig_severity(True), "UNKNOWN")
        self.assertEqual(remedify._sysdig_severity([]), "UNKNOWN")


class TestGrype(unittest.TestCase):
    """v0.6: Grype JSON (`grype <target> -o json`)."""

    def setUp(self):
        self.plan = remedify.build_plan(remedify.parse_grype(load("grype-ubuntu.json")))

    def test_distro_and_target(self):
        self.assertEqual(self.plan["target"], "myapp:1.0")
        self.assertEqual(self.plan["pkg_manager"], "apt")

    def test_deb_package_command(self):
        step = next(s for s in self.plan["steps"] if "libssl3" in s["packages"])
        self.assertEqual(step["command"],
                         "apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18")
        self.assertEqual(step["backport"], "Ubuntu")

    def test_wont_fix_goes_to_unfixed_with_status(self):
        u = next(x for x in self.plan["unfixed"] if x["package"] == "bash")
        self.assertEqual(u["status"], "wont_fix")

    def test_npm_becomes_app_step(self):
        step = next(s for s in self.plan["app_steps"] if s["package"] == "lodash")
        self.assertEqual(step["ecosystem"], "npm")
        self.assertIn("npm install lodash@4.17.21", step["action"])

    def test_autodetect(self):
        with open(os.path.join(EXAMPLES, "grype-ubuntu.json"), encoding="utf-8") as f:
            self.assertEqual(remedify.detect_input_format(f.read()), "grype")

    def test_advisory_surfaced(self):
        md = remedify.render_markdown(self.plan)
        self.assertIn("USN-6986-1", md)


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
