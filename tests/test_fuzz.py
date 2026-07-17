"""Seeded structural fuzz — parsers and renderers must never raise anything
except SystemExit, no matter how the input is mangled. 600 mutated documents
per run (kept small for CI; run with FUZZ_N=10000 for a deep pass)."""

import copy
import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import remedify  # noqa: E402

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")
FIXTURES = ["trivy-real-ubuntu1804.json", "sysdig-scan-result.json",
            "sysdig-api-v1.json", "trivy-ubuntu.json"]

MUTATIONS = ["delete", "null", "int", "str", "list", "dict",
             "empty_str", "unicode", "huge_int", "bool"]
VALUES = {"null": None, "int": 42, "str": "x", "list": [], "dict": {},
          "empty_str": "", "unicode": "\U0001f389　\x00ü",
          "huge_int": 10 ** 30, "bool": True}


def mutate(node, rng, depth=0):
    if depth > 6 or not isinstance(node, (dict, list)) or not node:
        return
    if isinstance(node, dict):
        key = rng.choice(list(node.keys()))
        action = rng.choice(MUTATIONS)
        if action == "delete":
            del node[key]
        elif rng.random() < 0.5:
            node[key] = VALUES[action]
        else:
            mutate(node[key], rng, depth + 1)
    else:
        i = rng.randrange(len(node))
        if rng.random() < 0.3:
            node[i] = rng.choice(list(VALUES.values()))
        else:
            mutate(node[i], rng, depth + 1)


class TestStructuralFuzz(unittest.TestCase):
    def test_mutated_documents_never_crash(self):
        rng = random.Random(42)
        bases = [json.load(open(os.path.join(EXAMPLES, f), encoding="utf-8"))
                 for f in FIXTURES]
        n = int(os.environ.get("FUZZ_N", "600"))
        for _ in range(n):
            data = copy.deepcopy(rng.choice(bases))
            for _ in range(rng.randint(1, 8)):
                mutate(data, rng)
            for parser in (remedify.parse_trivy, remedify.parse_sysdig_json):
                try:
                    plan = remedify.build_plan(parser(copy.deepcopy(data)))
                    remedify.render_markdown(plan)
                    remedify.render_shell(plan)
                    remedify.render_json(plan)
                except SystemExit:
                    pass  # clean exit is allowed; tracebacks are not


if __name__ == "__main__":
    unittest.main()
