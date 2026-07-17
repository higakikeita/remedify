# Roadmap

remedify is developed on two tracks: growing as a standalone OSS tool, and
serving as a field-validated prototype for scanner vendors (see README's
copa comparison). Milestones gate on working, tested code — not dates.

**North star:** move from *translator* (scan → action) to *closed loop*
(how much will this hurt → do it → prove it's gone). remedify is the only
deterministic tool positioned to answer "did the fix actually land?" —
because it already owns dpkg-accurate version comparison.

## Shipped

- **v0.1–0.5** — Trivy input; per-distro commands (apt/dnf/yum/apk/zypper);
  source-package consolidation; "no fix available"; EOL/ESM awareness;
  backport detection; Sysdig CSV + scan JSON + live VM API (validated on a
  real us2 tenant); runtime priority signals (In-Use / exploitable / KEV).
- **v0.6** — Grype input; multi-workload `--limit`.
- **v0.7** — Fleet summary ("one fix → N workloads"); third-party image
  detection.
- **v0.8** — MCP server (zero-dep); PyPI release.
- **v0.9** — `--format ansible`; correct dpkg verrevcmp (10k-case property
  test vs. real dpkg); non-interactive scripts; pinned apk/zypper;
  `--fail-on` CI gate. **Security:** command-injection fix (input
  whitelisting), MCP path allowlist, API-response ID validation,
  cross-origin token stripping.
- **v0.10** — `--context host|image` (immutable-infra rebuild advice);
  **OSV-Scanner input**. remedify now ingests Trivy, Grype, OSV-Scanner,
  and Sysdig.

## v0.10.x — Planning ergonomics (in progress)

Low-cost reshaping of information remedify already has; big UX payoff.

- **Downtime-budget view (`--group-by disruption`)**: sort by *pain*, not
  just severity — (1) do-now / no-restart, (2) service-restart, (3)
  maintenance-window (kernel/libc → reboot). Lets an operator plan a window
  directly. The blast-radius hints already exist; promote them to a sort axis.
- **Rollback steps**: for every forward command (`apt-get install pkg=NEW`),
  emit the undo (`pkg=OLD` + `apt-mark hold`), and an Ansible `rescue` block.
  A documented undo lowers the bar to production.

## v0.11 — `remedify verify` (north star)

- Feed a **before** and an **after** scan; emit a diff:
  ✅ resolved / ⚠️ still vulnerable (upgraded but below the fix version —
  uses dpkg verrevcmp) / 🆕 newly introduced (e.g. base-image swap).
  Machine-readable answer to "I upgraded but the scanner is still red."
- **`--strategy minimal|latest`**: minimal (security backport only; matches
  our backport philosophy) as default, latest opt-in — pairs naturally with
  verify ("minimal was enough" vs "latest was needed").

## v0.12 — Fleet / enterprise reach

- **Owner-sliced reports**: resolve owner from K8s label/annotation (or
  Sysdig Resource Ownership) and split the plan per team — "platform gets
  these 3, payments gets these 5." Assigns the *hands*, not just the fix.
- **Air-gap bundle (`remedify bundle`)**: tarball of exact .deb/.rpm URLs +
  checksum manifest + install script, to pre-stage in closed networks.
  Natural extension of the zero-dependency philosophy.

## v1.0 — Data correctness & trust

- endoflife.date API for live EOL data (opt-in; caching; keep the static
  table as offline fallback — zero-dep default must hold)
- Vendor advisory cross-check (Ubuntu USN API, RHEL CSAF) so advisory links
  don't depend on scanner input
- `--format sarif` (GitHub Code Scanning); GitHub Action; cron + ticket
  auto-filing recipes (Jira/DevRev)
- copa-compatible output for container findings (complete the copa story)
- Validation against real customer report exports and multi-region tenants
- Decide: Go rewrite (single static binary) once interfaces are stable

## Backlog (from external review)

- distroless images: no package manager → base-image-update-only branch

## Continuous (every release)

- Real-tenant / real-OS validation for anything touching parsers or commands
- Fuzz + dpkg property suites stay green (deep pass before release)
- Trust-boundary review before releases that touch parsing or I/O
- Honest docs: capability comparisons updated as competitors evolve
