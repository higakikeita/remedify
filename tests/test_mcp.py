"""MCP server protocol tests — full JSON-RPC round-trips over stdio."""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
EXAMPLES = os.path.join(ROOT, "examples")


def rpc(*msgs):
    stdin = "\n".join(json.dumps(m) for m in msgs) + "\n"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "remedify_mcp.py")],
                       input=stdin, capture_output=True, text=True, timeout=60)
    return [json.loads(line) for line in r.stdout.strip().splitlines()]


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}}


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        out = rpc(INIT)
        result = out[0]["result"]
        self.assertEqual(result["serverInfo"]["name"], "remedify")
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertIn("tools", result["capabilities"])

    def test_tools_list(self):
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in out[1]["result"]["tools"]]
        self.assertEqual(names, ["generate_remediation_plan", "fetch_sysdig_plan"])
        for t in out[1]["result"]["tools"]:
            self.assertIn("inputSchema", t)

    def test_generate_plan_from_content(self):
        with open(os.path.join(EXAMPLES, "sysdig-scan-result.json"),
                  encoding="utf-8") as f:
            scan = f.read()
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "generate_remediation_plan",
                                    "arguments": {"scan_content": scan}}})
        result = out[1]["result"]
        self.assertFalse(result["isError"])
        text = result["content"][0]["text"]
        self.assertIn("spring-beans", text)
        self.assertIn("Remediation plan", text)

    def test_generate_plan_json_format(self):
        with open(os.path.join(EXAMPLES, "grype-ubuntu.json"), encoding="utf-8") as f:
            scan = f.read()
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "generate_remediation_plan",
                                    "arguments": {"scan_content": scan,
                                                  "format": "json"}}})
        plan = json.loads(out[1]["result"]["content"][0]["text"])
        self.assertEqual(plan["target"], "myapp:1.0")

    def test_missing_args_is_clean_error(self):
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "generate_remediation_plan",
                                    "arguments": {}}})
        self.assertTrue(out[1]["result"]["isError"])

    def test_unknown_tool(self):
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "nope", "arguments": {}}})
        self.assertIn("error", out[1])

    def test_fetch_sysdig_without_token_is_clean_error(self):
        out = rpc(INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "fetch_sysdig_plan",
                                    "arguments": {"api_url": "https://x"}}})
        result = out[1]["result"]
        self.assertTrue(result["isError"])
        self.assertIn("SYSDIG_API_TOKEN", result["content"][0]["text"])

    def test_notifications_get_no_response(self):
        out = rpc(INIT, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"jsonrpc": "2.0", "id": 9, "method": "ping"})
        self.assertEqual(len(out), 2)  # init + ping only
        self.assertEqual(out[1]["id"], 9)


if __name__ == "__main__":
    unittest.main()
