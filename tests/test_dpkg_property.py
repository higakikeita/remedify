"""Property test: compare_versions must agree with the real dpkg.

Fuzzing only proves we don't crash; this proves we're *correct* — against
`dpkg --compare-versions`, the reference implementation. Skipped where dpkg
is unavailable (runs in CI on ubuntu-latest)."""

import os
import random
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

SEGMENTS = ["0", "1", "2", "10", "9", "1.0", "2.35", "3.0.2", "5.15.0"]
SUFFIXES = ["", "-1", "-0ubuntu1.18", "+deb12u14", "~rc1", "~beta2", "-r0",
            "_p1-r0", ".el9_3.12", "+esm1", "-1ubuntu1.10"]
EPOCHS = ["", "1:", "2:", "10:"]


def random_version(rng):
    return (rng.choice(EPOCHS) + rng.choice(SEGMENTS) + rng.choice(SUFFIXES))


def dpkg_compare(a, b):
    for op, val in (("lt", -1), ("eq", 0)):
        if subprocess.run(["dpkg", "--compare-versions", a, op, b],
                          capture_output=True).returncode == 0:
            return val
    return 1


@unittest.skipUnless(shutil.which("dpkg"), "dpkg not available")
class TestDpkgAgreement(unittest.TestCase):
    def test_agrees_with_dpkg(self):
        rng = random.Random(7)
        n = int(os.environ.get("DPKG_PROP_N", "300"))
        disagreements = []
        for _ in range(n):
            a, b = random_version(rng), random_version(rng)
            ours, theirs = remedify.compare_versions(a, b), dpkg_compare(a, b)
            if ours != theirs:
                disagreements.append((a, b, ours, theirs))
        self.assertEqual(disagreements[:10], [],
                         f"{len(disagreements)}/{n} disagreements with dpkg")

    def test_known_epoch_cases(self):
        # the bug report case
        self.assertEqual(remedify.compare_versions("1:1.2.3", "2.0"), 1)
        self.assertEqual(remedify.highest_version(["1:1.2.3", "2.0"]), "1:1.2.3")
        self.assertEqual(remedify.highest_version(["1:9.6p1-3", "2:1.0"]), "2:1.0")


if __name__ == "__main__":
    unittest.main()
