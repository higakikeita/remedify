"""Schema canary — the "don't be silently wrong" guard.

Fuzzing proves we don't crash; this proves we don't quietly drop findings.
For each committed real-world scan fixture we pin the EXACT shape of the plan
(how many OS steps, app steps, unfixed, rejected) plus a couple of anchor
findings. If a parser refactor — or a scanner schema change we adapt to —
starts losing findings, these go red instead of shipping a plan that silently
omits vulnerabilities.

The paired scheduled-CI job fetches *live* scanner golden files and only
asserts "still parses" (counts there legitimately drift with new CVEs)."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def plan_for(name, parser):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return remedify.build_plan(parser(json.load(f)))


def counts(plan):
    return (len(plan["steps"]), len(plan["app_steps"]),
            len(plan["unfixed"]), len(plan["rejected"]))


class TestSchemaCanary(unittest.TestCase):
    # (fixture, parser, pkg_manager, (steps, app, unfixed, rejected))
    BASELINES = [
        ("trivy-real-ubuntu1804.json", remedify.parse_trivy, "apt", (1, 0, 1, 0)),
        ("sysdig-api-v1.json", remedify.parse_sysdig_json, "apk", (2, 1, 1, 0)),
        ("grype-ubuntu.json", remedify.parse_grype, "apt", (2, 1, 1, 0)),
        ("osv-scanner.json", remedify.parse_osv, "apt", (2, 1, 1, 0)),
    ]

    def test_exact_plan_shape(self):
        for name, parser, pkgmgr, expected in self.BASELINES:
            plan = plan_for(name, parser)
            self.assertEqual(plan["pkg_manager"], pkgmgr, name)
            self.assertEqual(counts(plan), expected,
                             f"{name}: finding counts changed — a parser/schema "
                             f"change may be silently dropping findings")

    def test_total_findings_conserved(self):
        # every input finding must land in exactly one bucket, never vanish
        for name, parser, _pkgmgr, _exp in self.BASELINES:
            with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
                raw = f.read()
            plan = plan_for(name, parser)
            # each committed fixture references CVE-/GHSA- ids; every unique id
            # must appear somewhere in the rendered plan (nothing dropped)
            import re as _re
            ids = set(_re.findall(r"(?:CVE|GHSA)[-A-Za-z0-9]+", raw))
            rendered = remedify.render_markdown(plan) + remedify.render_json(plan)
            missing = [i for i in ids if i not in rendered]
            self.assertEqual(missing, [],
                             f"{name}: these findings vanished from output: {missing}")

    def test_anchor_findings_present(self):
        # spot-check specific known remediations survive
        trivy = plan_for("trivy-real-ubuntu1804.json", remedify.parse_trivy)
        step = trivy["steps"][0]
        self.assertIn("e2fsprogs", step["packages"])
        self.assertEqual(step["fix_version"], "1.44.1-1ubuntu1.2")

        osv = plan_for("osv-scanner.json", remedify.parse_osv)
        libssl = next(s for s in osv["steps"] if "libssl3" in s["packages"])
        self.assertEqual(libssl["fix_version"], "3.0.2-0ubuntu1.18")


if __name__ == "__main__":
    unittest.main()
