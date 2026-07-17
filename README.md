# remedify

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

## Features (PoC, v0.1)

- **Input**: Trivy JSON (`trivy image|fs|rootfs --format json`)
- **Distro-aware commands**: apt (Ubuntu/Debian), dnf/yum (RHEL/Rocky/Alma/Amazon/Fedora), apk (Alpine), zypper (SUSE)
- **Backport detection**: flags vendor backports (`~ubuntu`, `.el9`, `.amzn2`, `+esm`, `+deb`) and explains why the version won't match upstream
- **Operational hints**: kernel → reboot required; glibc → reboot recommended; OpenSSL → restart linked services
- **Advisory surfacing**: vendor sources first (USN, RHSA, ALAS, DSA), NVD as fallback
- **Three output formats**: Markdown report, executable shell script, JSON
- **Zero dependencies**: single-file Python, stdlib only

```
usage: remedify scan.json [--format {markdown,shell,json}] [--min-severity {LOW,MEDIUM,HIGH,CRITICAL}]
```

Try it with the bundled examples:

```
python3 remedify.py examples/trivy-ubuntu.json
python3 remedify.py examples/trivy-rhel.json --min-severity HIGH
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
