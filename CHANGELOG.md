# Changelog

## 0.11.1

- **endoflife.date integration** (`--check-eol`, opt-in): live EOL data
  instead of the static table. Network is off by default (zero-dep/offline
  promise holds); cached ~24h; any failure falls back to the static table
  and never raises.
- **SECURITY.md**: private vulnerability reporting + documented threat model.
- **Weekly scheduled CI**: deep dpkg-property (20k) and fuzz (20k) passes,
  live-EOL drift check, and a Trivy-schema smoke test against the current
  upstream golden file — catches drift without anyone remembering to look.

## 0.11.0 — closed loop (verify)

- **`remedify --baseline before.json after.json`**: diff two scans and prove
  whether the fixes landed. Built entirely on the existing dpkg-correct
  `compare_versions` — no new version logic.
  - Classifies each (package, CVE): resolved / new / remaining, where
    "remaining" is sub-typed via version comparison: untouched ·
    upgraded-but-short · regressed · no-fix · now-fixable
  - **Anomaly detection**: installed >= fix version yet still flagged →
    surfaces scanner-cache / version-string / backport mismatches other
    tools miss (leverages remedify's backport awareness)
  - `--fail-on <sev>`: exit 2 if any fixable finding at/above severity
    remains or a new one appears (no-fix remainings never trip the gate)
  - `--format json` with a stable `reason` enum for MCP agents
  - Cross-format (e.g. Grype baseline × Trivy after) supported

## 0.10.0

- **`--context host|image`** (auto-detected): for container images, lead with
  "update the Dockerfile and rebuild" (immutable infra) rather than patching a
  running container in place. Third-party images keep their vendor-tag advice.
- **OSV-Scanner input** (`osv-scanner --format json`, auto-detected): OS
  ecosystems (Debian/Ubuntu/Alpine/RHEL/…) → commands; language ecosystems
  (npm/PyPI/Go/Maven/…) → rebuild steps. CVSS-vector severity fallback.
- remedify now ingests Trivy, Grype, OSV-Scanner, and Sysdig (API/JSON/CSV).

## 0.9.2 — security (trust boundary hardening)

Second-pass security review found two more attacker-reachable paths (distinct
from the 0.9.1 shell-injection fix):

- **MCP: no arbitrary local file reads.** `generate_remediation_plan`'s
  `scan_path` is agent-controlled and prompt-injection reachable. It is now
  disabled unless `REMEDIFY_MCP_ALLOWED_DIR` is set, and only reads files that
  resolve (realpath) inside that directory — defeats `../` traversal and
  symlinks. Prefer `scan_content`.
- **`--from-sysdig`: don't trust API responses in URLs, or leak the token on
  redirect.** Server-provided scan-result IDs are validated (`[A-Za-z0-9._-]+`)
  before going into a URL path; a custom redirect handler strips the
  `Authorization: Bearer` header on any cross-origin redirect (urllib, unlike
  requests, would otherwise resend it). `--api-url` scheme/host validated.
- New MCP file-access tests; identifier-validation tests.

remedify's three trust boundaries — scan input, MCP tool args, Sysdig API
responses — now all validate external strings against a character-set
whitelist before use.

## 0.9.1 — security

- **Fix command injection via crafted package names/versions** (external
  security review). Scan results are attacker-influenced (a malicious base
  image controls its own package DB); an unvalidated name like
  `libfoo$(cmd)` became a live shell command in `--format shell`. OS package
  names and versions are now whitelisted against distro naming rules and
  **rejected** (surfaced, never silently dropped, never escaped-and-run) if
  they contain anything outside `[A-Za-z0-9.+~:_-]`. Lang-package names are
  validated against output-framing-breaking characters. New `test_security.py`
  with 12 injection payloads as a regression guard.
- Shell script header now states commands are derived from scan input and
  validated against distro naming rules.

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
