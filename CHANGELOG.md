# Changelog

## 0.9.0

- **`--format ansible`**: multi-distro remediation playbook with pinned
  versions and an `allow_reboot`-guarded reboot task
- **Correct dpkg version comparison** (external review finding): faithful
  verrevcmp port — epoch, upstream/revision split at last '-', dpkg
  character ordering. Verified against real `dpkg --compare-versions`
  with a 10,000-case property test (new in CI)
- **Non-interactive scripts** (review): shell output uses
  `DEBIAN_FRONTEND=noninteractive` + `-y`; markdown stays confirmable
- **Pinned versions everywhere** (review): apk/zypper now pin the fix
  version — deterministic execution, not just deterministic text
- **`--fail-on SEVERITY`** (review): exit code 2 for CI gates
- EOL table: Amazon Linux 2 (EOL 2026-06-30); Wolfi/Chainguard -> apk

## 0.8.0

- **MCP server** (`remedify_mcp.py`): expose remedify to AI agents via the
  Model Context Protocol — stdio JSON-RPC implemented with stdlib only
  (zero dependencies preserved). Tools: `generate_remediation_plan`,
  `fetch_sysdig_plan` (with fleet summary). Protocol-level test suite.

## 0.7.0

- **Fleet summary**: multi-workload runs now lead with "one fix → N
  workloads" aggregation, sorted by coverage, severity, and priority
  signals; included in markdown, shell (comment header), and JSON
  (`fleet_summary` key)
- **Third-party image detection**: vendor-built images (registry.k8s.io,
  GKE system images, Docker official, quay.io, MCR, ECR public, etc.) get
  "upgrade to the newest vendor tag" as the primary recommendation
- ROADMAP.md added (v0.8: MCP server + PyPI)

## 0.6.0

- **Grype JSON parser** (`grype <target> -o json`, auto-detected) — remedify
  now speaks Trivy, Grype, and Sysdig (API/JSON/CSV)
- **Multi-workload mode**: `--from-sysdig --limit N` fetches the N most
  recent runtime results and emits one combined report (markdown sections,
  merged shell script, JSON array)

## 0.5.2

- **Real-OS validation**: generated apt commands verified against a live
  Ubuntu 22.04 system (`apt-get --dry-run` accepts all output, including
  consolidated multi-package commands)
- **Structural fuzzing**: 20,000 mutated-document runs with zero uncaught
  exceptions; type-coercion guards on every external field; a seeded
  600-iteration fuzz test now runs in CI (`FUZZ_N=10000` for deep passes)
- **Scale**: 30,000 vulnerabilities / 10,000 packages processed in <0.2s
- CSV delimiter sniffing (semicolon/tab Excel-locale exports)
- Honest consolidation label (identical version pairs, not "same source")

## 0.5.1

- Correct dpkg/rpm version semantics: `~` sorts before release (`1.0~rc1 < 1.0`),
  epoch handling, numeric-over-lexical ordering
- CLI never tracebacks: clean errors + exit code 1 for missing files, broken
  JSON, empty input, CSVs with unrecognized headers
- BOM / CRLF tolerance for CSV exports
- Null-safety across all parsers (real-world data has nulls everywhere)
- Test suite: 70 tests including subprocess-level CLI checks

## 0.5.0

- `--from-sysdig` **validated against a live Sysdig tenant** (us2)
- VM API v1 response shape supported (packages dict + vulnerabilities table + refs)
- Priority signals from Sysdig runtime context: In-Use (`isRunning`),
  exploit available (`exploitable`), CISA KEV — 🚨 badges + priority-aware sort
- `--insecure` / `--ca-bundle` for corporate TLS-inspecting proxies, `--dump`
  for raw response debugging
- API endpoint prefix probing (v1 → v1beta1) with actionable error messages

## 0.4.0

- Language packages (lang-pkgs): Java/npm/pip/Go/Ruby/PHP/Rust/.NET findings
  become "Application dependencies (rebuild required)" steps with
  per-ecosystem fix instructions
- Sysdig scan-result JSON parser (sysdig-cli-scanner shape, auto-detected)
- `--from-sysdig` API fetch mode (beta)

## 0.3.0

- Sysdig vulnerability report CSV parser with alias-based header matching
- `--os` override, `--input` format selection, input auto-detection

## 0.2.0

- Consolidated remediation steps (source-package grouping)
- "No fix available" section using Trivy's `Status` field
- EOL / ESM awareness, advisory family dedup

## 0.1.0

- Initial PoC: Trivy JSON → per-distro remediation commands
  (apt/dnf/yum/apk/zypper), backport detection, reboot/restart hints,
  vendor advisory surfacing, Markdown/shell/JSON output
