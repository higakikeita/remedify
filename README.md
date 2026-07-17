# remedify

[![CI](https://github.com/higakikeita/remedify/actions/workflows/ci.yml/badge.svg)](https://github.com/higakikeita/remedify/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](remedify.py)

> **copa patches container images. remedify tells you how to patch everything else.**

Vulnerability scanners are great at telling you *what* is vulnerable and *which version* fixes it. They are terrible at telling you *what command to run*. After triage, every team asks the same question: "So how exactly do I fix this on my OS?" — and the answer today is "go read the Ubuntu/RHEL/Amazon Linux docs."

**remedify** closes that last-mile gap. It takes vulnerability scan results (Trivy today; Grype and Sysdig on the roadmap) and generates concrete, distro-aware remediation:

```
$ trivy rootfs --format json -o scan.json /
$ remedify scan.json
```

```markdown
## libssl3  `HIGH`
- Installed: `3.0.2-0ubuntu1.15` -> Fix: `3.0.2-0ubuntu1.18`
- CVEs: CVE-2024-5535, CVE-2024-6119
- **Vendor backport (Ubuntu)**: the fixed version is a distro backport — it will
  not match the upstream version number. Trust the vendor advisory below.

    apt-get install --only-upgrade libssl3=3.0.2-0ubuntu1.18

- ⚠️ Restart services that link against OpenSSL (nginx, sshd, etc.).
- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-6986-1)
```

## Why not just use copa?

[Copacetic](https://project-copacetic.github.io/copacetic/website/) is excellent — for **container images**. It patches an image directly by adding a patch layer, no rebuild needed. But it does not help with:

| Gap | copa | remedify |
|---|---|---|
| Container images | ✅ patches directly | 🔜 emits copa-compatible workflows |
| **Hosts / VMs / bare metal** | ❌ | ✅ per-distro commands |
| Backport explanation (Ubuntu/RHEL fixed version ≠ upstream) | ❌ | ✅ |
| Reboot / service-restart guidance | ❌ | ✅ |
| Vendor advisory links next to the fix | ❌ | ✅ |

They are complementary: containers → copa, everything else → remedify.

## Features (v0.2)

- **Inputs** (auto-detected): Trivy JSON (`trivy image|fs|rootfs --format json`), **Sysdig scan-result JSON** (sysdig-cli-scanner / VM API), **Sysdig vulnerability report CSV exports** (header names matched flexibly — pass `--os ubuntu:22.04` if your export lacks an OS column), or **live from the Sysdig VM API** (`--from-sysdig --api-url https://us2.app.sysdig.com` with `SYSDIG_API_TOKEN`; validated against a live tenant)
- **Priority signals**: findings carry Sysdig runtime context — 🚨 CISA KEV (known exploited), public exploit available, and **package in use at runtime** — and steps are sorted by severity + these signals, so you fix what attackers can actually reach first
- **Application dependencies (lang-pkgs)**: Java/npm/pip/Go/Ruby/PHP/Rust/.NET findings get ecosystem-specific fix instructions (update pom.xml / `npm install pkg@ver` / etc. + rebuild) — the class of finding neither OS package managers nor copa can fix
- **Distro-aware commands**: apt (Ubuntu/Debian), dnf/yum (RHEL/Rocky/Alma/Amazon/Fedora), apk (Alpine), zypper (SUSE)
- **Consolidated steps**: binary packages from one source package (e.g. e2fsprogs + libcom-err2 + libext2fs2 + libss2) become **one** command, not four
- **"No fix available" section**: findings without a fixed version are reported with their vendor status (`affected`, `will_not_fix`, `end_of_life`) — never silently dropped
- **EOL awareness**: detects end-of-life distro versions and warns when fixes require ESM enrollment or an OS migration
- **Backport detection**: flags vendor backports (`~ubuntu`, `.el9`, `.amzn2`, `+esm`, `+deb`) and explains why the version won't match upstream
- **Operational hints**: kernel → reboot required; glibc → reboot recommended; OpenSSL → restart linked services
- **Advisory surfacing**: vendor sources first (USN, RHSA, ALAS, DSA), NVD as fallback, near-duplicates collapsed
- **Three output formats**: Markdown report, executable shell script, JSON
- **Zero dependencies**: single-file Python, stdlib only

## What you get

**1. A prioritized Markdown report** — consolidated steps instead of per-package noise:

```markdown
# Remediation plan: `prod-web-host (ubuntu 18.04)`

- **Remediation steps**: 1 (covering 4 packages)
- **No fix available**: 1 packages

> ⚠️ **EOL**: Ubuntu 18.04 standard repositories no longer receive security
> updates. Fixes for many CVEs require Ubuntu Pro (ESM).

## e2fsprogs (+3 related packages)  `MEDIUM`

- Packages: `e2fsprogs`, `libcom-err2`, `libext2fs2`, `libss2` (same source, one update)
- Installed: `1.44.1-1ubuntu1.1` -> Fix: `1.44.1-1ubuntu1.2`
- **Vendor backport (Ubuntu)**: fixed version won't match upstream — trust the advisory.

    apt-get install --only-upgrade e2fsprogs=1.44.1-1ubuntu1.2 libcom-err2=1.44.1-1ubuntu1.2 ...

- Advisories: [Ubuntu USN](https://ubuntu.com/security/notices/USN-4142-1)

## No fix available

- **bash** `LOW` (CVE-2019-18276) — No vendor fix released yet
```

**2. A reviewable shell script** (`--format shell`) — commented, `set -euo pipefail`, reboot reminder at the end:

```bash
#!/usr/bin/env bash
# Review before running. Run as root or with sudo.
apt-get update

# e2fsprogs, libcom-err2, ... 1.44.1-1ubuntu1.1 -> 1.44.1-1ubuntu1.2 [MEDIUM] CVE-2019-5094
#   NOTE: Ubuntu vendor backport — version differs from upstream
apt-get install --only-upgrade e2fsprogs=1.44.1-1ubuntu1.2 ...
```

**3. Machine-readable JSON** (`--format json`) — feed it to your ticketing system, chatbot, or AI agent.

## CLI reference

| Option | Values | Default | Purpose |
|---|---|---|---|
| `--format` | `markdown` `shell` `json` | `markdown` | Output format |
| `--min-severity` | `LOW` `MEDIUM` `HIGH` `CRITICAL` | show all | Filter remediation steps (unfixed findings are **never** hidden) |
| `--input` | `auto` `trivy` `sysdig-csv` `sysdig-json` | `auto` | Input format |
| `--os` | e.g. `ubuntu:22.04` | from input | OS override for inputs lacking OS metadata |
| `--from-sysdig` | | | Fetch latest runtime result from Sysdig VM API (beta) |
| `--api-url` / `--result-id` / `--filter` | | | Sysdig API endpoint / specific result / filter |
| `--version` | | | Print version |

Input via file path or stdin (`-`).

## Supported distros

| Family | Package manager | Backport detection | EOL detection |
|---|---|---|---|
| Ubuntu / Debian | `apt` | ✅ (`~ubuntu`, `+deb`, `+esm`) | ✅ (ESM guidance) |
| RHEL / Rocky / Alma / Oracle / Fedora | `dnf` | ✅ (`.el9`) | — |
| CentOS | `dnf` | ✅ | ✅ (migration guidance) |
| Amazon Linux | `yum` (AL2) / `dnf` | ✅ (`.amzn2`) | ✅ (AL1) |
| Alpine | `apk` | — | — |
| SUSE / openSUSE | `zypper` | — | — |
| Anything else | — | degrades gracefully: findings listed without commands | |

Try it with the bundled examples:

```
python3 remedify.py examples/trivy-real-ubuntu1804.json   # real Trivy output: grouping + EOL + no-fix
python3 remedify.py examples/trivy-rhel.json --min-severity HIGH
python3 remedify.py examples/trivy-amazon2.json           # yum + ALAS advisories
python3 remedify.py examples/trivy-alpine.json            # apk
python3 remedify.py examples/trivy-centos7-eol.json       # EOL + will_not_fix / end_of_life
python3 remedify.py examples/sysdig-report.csv           # Sysdig CSV export
python3 remedify.py examples/sysdig-scan-result.json     # Sysdig scan JSON: OS + Java/npm (Spring4Shell)
python3 remedify.py examples/trivy-ubuntu.json --format shell > fix.sh
```

## Architecture

```
 scan results        parser          normalized        generators          renderers
┌────────────┐   ┌───────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐
│ Trivy JSON │──▶│  trivy.py │──▶│ Finding      │──▶│ apt / dnf /  │──▶│ markdown   │
│ Grype JSON │   │ (grype 🔜)│   │  pkg,        │   │ apk / zypper │   │ shell      │
│ Sysdig 🔜  │   │           │   │  fix ver,    │   │ + backport   │   │ json       │
└────────────┘   └───────────┘   │  CVEs, refs  │   │ + hints      │   │ sarif 🔜   │
                                 └──────────────┘   └──────────────┘   └────────────┘
```

Each stage is pluggable: new scanners are parsers, new distros are generators, new outputs are renderers.

## Roadmap

- **v0.2 — inputs**: Grype JSON, Sysdig vulnerability report CSV/JSON
- **v0.3 — enrichment**: query vendor security data (Ubuntu OVAL/USN API, Red Hat CSAF/errata API, ALAS) to add "not affected / needs-restart" precision beyond what the scanner reports
- **v0.4 — containers**: emit copa-compatible patch workflows for image findings; language packages (pip/npm) remediation
- **v0.5 — integration**: GitHub Action, `--format sarif`, Windows (KB articles / `winget`), MCP server so AI agents can call it
- **Rewrite in Go** once the interface stabilizes (single static binary, same ecosystem as copa/trivy)

## Non-goals

- remedify does **not** apply patches. It generates the plan; a human (or your automation) executes it. Auto-apply is deliberately out of scope for v0.x.
- Not a scanner. Bring your own (Trivy/Grype/Sysdig).

## Status

PoC / pre-alpha. Name provisional. Feedback and contributions welcome.

## License

Apache-2.0 (proposed).
