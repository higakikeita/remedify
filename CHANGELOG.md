# Changelog

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
