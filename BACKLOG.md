# Backlog

## Done in v0.2

- ✅ Source-package grouping (1 consolidated step instead of N commands)
- ✅ "No fix available" section using Trivy's `Status` field
- ✅ EOL / ESM awareness (static table; see v0.3 below)
- ✅ Advisory family dedup (USN-4142-1/-2 → one entry)

## Done in v0.3

- ✅ Test expansion: Alpine (apk), Amazon Linux 2 (yum + ALAS), CentOS 7 EOL,
  `will_not_fix` / `end_of_life` statuses, edge cases (39 tests)
- ✅ Sysdig vulnerability report CSV parser (alias-based header matching,
  `--os` override, auto-detection)

**Note on the Sysdig parser**: column aliases are based on common report
template headers. Validate against a real (anonymized) customer export and
extend `SYSDIG_COLUMN_ALIASES` if headers differ — that is the only place
that needs changing.

## Done in v0.4

- ✅ lang-pkgs support: Java/npm/pip/Go/Ruby/PHP/Rust/.NET findings become
  "Application dependencies (rebuild required)" steps with per-ecosystem
  fix instructions (Trivy lang-pkgs, Sysdig CSV lang types, Sysdig JSON)
- ✅ Sysdig scan-result JSON parser (sysdig-cli-scanner / VM API shape)
- ✅ `--from-sysdig` API fetch mode (beta — endpoint paths follow the public
  VM API v1; **needs validation against a real tenant**)

## Done in v0.5

- ✅ **`--from-sysdig` validated against a live tenant** (us2). Fixes found:
  correct host is `us2.app.sysdig.com`; API prefix probing (v1 → v1beta1);
  VM API v1 shape = packages dict + vulnerabilities table + refs;
  severity as lowercase string; `fixVersion` nullable
- ✅ Priority signals from Sysdig runtime context: `isRunning` (In-Use),
  `exploitable`, `cisaKev` → 🚨 badges + priority-aware sorting
- ✅ Real-response regression fixture (`examples/sysdig-api-v1.json`)
- ✅ Ops hardening: `--insecure` / `--ca-bundle` (corporate TLS interception),
  `--dump` (raw response debugging), full-width-space-tolerant token handling

## From external code review (open)

- `--context host|image`: for first-party container images, recommend
  "bump base image + rebuild" as primary (immutable infra) instead of
  in-place commands
- distroless images: third branch — no package manager, base-image update only

## v0.6 candidates

- Use `endOfLifeDate` from the API for per-package EOL warnings
- Validate Sysdig CSV parser against real customer exports
- EOL data from [endoflife.date](https://endoflife.date) API instead of static table
- Grype JSON parser
- Source-package grouping via PURL metadata (current heuristic: identical
  installed+fixed version pair)
- Windows (KB / winget)
- MCP server so AI agents can call remedify directly

---

# Original v0.2 notes (from first real-data run)

Findings from running the PoC against real Trivy output
(`aquasecurity/trivy` integration-test golden file, ubuntu-1804 image).
The parser survived; the *report quality* is where real data exposed gaps.

## 1. Source-package grouping (high priority)

Real scans report one CVE across every binary package built from the same
source. CVE-2019-5094 appeared as **4 separate findings** (e2fsprogs,
libcom-err2, libext2fs2, libss2) with 4 separate commands — when the real
remediation is **one action**:

```bash
apt-get install --only-upgrade e2fsprogs libcom-err2 libext2fs2 libss2
```

Fix: group by source package (derivable from PURL / identical
source-version pairs) and emit one consolidated step.

## 2. "No fix available" section (high priority)

`bash` (CVE-2019-18276, `Status: affected`, no `FixedVersion`) was silently
dropped. Users need to see it with guidance: no vendor fix yet — options are
mitigation, acceptance, or workaround. Silent omission erodes trust in the
report.

## 3. Use Trivy's `Status` field (medium)

Real output carries `Status`: `fixed`, `affected`, `will_not_fix`,
`end_of_life`. Map these to distinct report sections:
- `will_not_fix` → "vendor declined; assess exposure"
- `end_of_life` → see item 4

## 4. EOL / ESM awareness (medium)

The test target was Ubuntu 18.04 — standard repos no longer receive patches;
fixes require Ubuntu Pro (ESM). remedify should detect EOL distro versions
and say so: "this fix requires ESM enrollment" instead of emitting a command
that will not find the package.

## 5. Dedup identical advisory links (low)

USN-4142-1 and USN-4142-2 both surfaced (correct, but near-duplicates).
Consider collapsing to the newest per advisory family.

## Test-environment note

The sandbox blocks GitHub binary downloads, so verification used Trivy's
committed golden files (real output format, version-controlled by the Trivy
project). Next step: run `trivy image --format json` locally against a
production-like image and feed the raw output in.
