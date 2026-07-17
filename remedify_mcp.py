#!/usr/bin/env python3
"""
remedify_mcp - Model Context Protocol server for remedify.

Exposes remedify as MCP tools so AI agents (Claude Desktop, Claude Code, etc.)
can request deterministic remediation plans. Zero dependencies: the MCP stdio
transport is newline-delimited JSON-RPC 2.0, implemented here with stdlib only.

Claude Desktop config (claude_desktop_config.json):

    "mcpServers": {
      "remedify": {
        "command": "python3",
        "args": ["/path/to/remedify/remedify_mcp.py"],
        "env": { "SYSDIG_API_TOKEN": "..." }   // only needed for fetch_sysdig_plan
      }
    }
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remedify  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "generate_remediation_plan",
        "description": (
            "Turn vulnerability scan results into a deterministic, actionable "
            "remediation plan: per-distro fix commands (apt/yum/dnf/apk/zypper), "
            "vendor-backport explanations, reboot/service-restart hints, "
            "language-package (Java/npm/Go/...) rebuild instructions, and a "
            "'no fix available' section. Accepts Trivy JSON, Grype JSON, Sysdig "
            "scan-result JSON, or Sysdig report CSV (auto-detected)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_content": {
                    "type": "string",
                    "description": "Raw scan file content (JSON or CSV).",
                },
                "scan_path": {
                    "type": "string",
                    "description": "Path to a scan file (alternative to "
                                   "scan_content). Disabled unless the server "
                                   "sets REMEDIFY_MCP_ALLOWED_DIR; only files "
                                   "inside that directory can be read. Prefer "
                                   "scan_content.",
                },
                "format": {
                    "type": "string", "enum": ["markdown", "json"],
                    "description": "Output format (default markdown).",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "Only include fixes at or above this severity.",
                },
                "os": {
                    "type": "string",
                    "description": "OS override like 'ubuntu:22.04' (for CSVs "
                                   "without an OS column).",
                },
            },
        },
    },
    {
        "name": "fetch_sysdig_plan",
        "description": (
            "Fetch recent runtime scan results from the Sysdig Vulnerability "
            "Management API and generate remediation plans, with a fleet "
            "summary ('one fix -> N workloads') when multiple workloads are "
            "requested. Requires the SYSDIG_API_TOKEN environment variable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_url": {
                    "type": "string",
                    "description": "Sysdig API base URL, e.g. https://us2.app.sysdig.com",
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of most recent workloads (default 1).",
                },
                "filter": {
                    "type": "string",
                    "description": "Sysdig runtime-results filter expression.",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
            },
            "required": ["api_url"],
        },
    },
]


def _resolve_scan_path(path):
    """MCP tool arguments are assembled by an AI agent, which can be influenced
    by untrusted content (prompt injection). Never open an arbitrary path.
    scan_path is only honored when REMEDIFY_MCP_ALLOWED_DIR is set, and only
    for files that resolve inside it (defeats ../ traversal and symlinks)."""
    allowed = os.environ.get("REMEDIFY_MCP_ALLOWED_DIR")
    if not allowed:
        raise ValueError(
            "scan_path is disabled. Pass scan_content instead, or set "
            "REMEDIFY_MCP_ALLOWED_DIR to permit reading files from one directory.")
    allowed_real = os.path.realpath(allowed)
    target = os.path.realpath(path)
    if os.path.commonpath([allowed_real, target]) != allowed_real:
        raise ValueError(f"scan_path must resolve inside {allowed_real}")
    return target


def tool_generate(args):
    raw = args.get("scan_content") or ""
    if not raw and args.get("scan_path"):
        with open(_resolve_scan_path(args["scan_path"]), encoding="utf-8-sig") as f:
            raw = f.read()
    if not raw.strip():
        raise ValueError("provide scan_content or scan_path")

    fmt = remedify.detect_input_format(raw)
    if fmt == "trivy":
        parsed = remedify.parse_trivy(json.loads(raw))
    elif fmt == "grype":
        parsed = remedify.parse_grype(json.loads(raw))
    elif fmt == "sysdig-json":
        parsed = remedify.parse_sysdig_json(json.loads(raw))
    else:
        parsed = remedify.parse_sysdig_csv(raw, os_override=args.get("os"))
    if args.get("os"):
        parsed["family"], parsed["os_name"] = remedify.parse_os_string(args["os"])

    plan = remedify.build_plan(parsed, args.get("min_severity", "UNKNOWN"))
    if args.get("format") == "json":
        return remedify.render_json(plan)
    return remedify.render_markdown(plan)


def tool_fetch_sysdig(args):
    token = os.environ.get("SYSDIG_API_TOKEN")
    if not token:
        raise ValueError("SYSDIG_API_TOKEN environment variable is not set")
    results = remedify.fetch_sysdig(
        args["api_url"], token,
        filter_expr=args.get("filter"),
        limit=int(args.get("limit", 1)))
    plans = [remedify.build_plan(remedify.parse_sysdig_json(r),
                                 args.get("min_severity", "UNKNOWN"))
             for r in results]
    parts = []
    if len(plans) > 1:
        parts.append(remedify.render_fleet_markdown(
            remedify.build_fleet_summary(plans)))
    parts.extend(remedify.render_markdown(p) for p in plans)
    return "\n\n---\n\n".join(parts)


HANDLERS = {
    "generate_remediation_plan": tool_generate,
    "fetch_sysdig_plan": tool_fetch_sysdig,
}


def handle(req):
    method = req.get("method")
    if method == "initialize":
        client_version = (req.get("params") or {}).get("protocolVersion",
                                                       PROTOCOL_VERSION)
        return {
            "protocolVersion": client_version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "remedify", "version": remedify.__version__},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        handler = HANDLERS.get(name)
        if not handler:
            raise ValueError(f"unknown tool: {name}")
        try:
            text = handler(params.get("arguments") or {})
            return {"content": [{"type": "text", "text": text}],
                    "isError": False}
        except SystemExit as e:  # remedify uses sys.exit for clean errors
            return {"content": [{"type": "text", "text": str(e)}],
                    "isError": True}
        except Exception as e:
            return {"content": [{"type": "text",
                                 "text": f"{type(e).__name__}: {e}"}],
                    "isError": True}
    if method == "ping":
        return {}
    return None  # notifications etc.


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if "id" not in req:      # notification: no response
            continue
        try:
            result = handle(req)
            resp = {"jsonrpc": "2.0", "id": req["id"]}
            if result is None:
                resp["error"] = {"code": -32601,
                                 "message": f"method not found: {req.get('method')}"}
            else:
                resp["result"] = result
        except Exception as e:
            resp = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32603, "message": str(e)}}
        sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
