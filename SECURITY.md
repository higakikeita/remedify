# Security Policy

remedify generates and runs privileged remediation commands, so we take its
own security seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/higakikeita/remedify/security/advisories/new)
(Security → Report a vulnerability). Include a minimal reproducer — ideally
the scan input (sanitized) and the command you ran.

We aim to acknowledge within a few days and to ship a fix or mitigation
before any public disclosure.

## Threat model

remedify has three trust boundaries where external data enters:

1. **Scan input** — package names/versions come from a scanned image's own
   package DB, which a malicious base image controls. All OS package
   identifiers are whitelist-validated against distro naming rules and
   *rejected* (not escaped) if they contain shell metacharacters.
2. **MCP tool arguments** — assembled by an AI agent and reachable by prompt
   injection. `scan_path` is disabled unless `REMEDIFY_MCP_ALLOWED_DIR` is set
   and only reads files resolving inside it; prefer `scan_content`.
3. **Sysdig API responses** — scan-result IDs are validated before use in a
   URL, and the bearer token is stripped on cross-origin redirects.

See `tests/test_security.py` for the regression suite (injection payloads,
path traversal, identifier validation).

## Supported versions

remedify is pre-1.0; only the latest release on PyPI receives fixes.
