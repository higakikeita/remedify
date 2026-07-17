# Roadmap

remedify is developed on two tracks: growing as a standalone OSS tool, and
serving as a field-validated prototype for scanner vendors (see README's
copa/Sage comparison). Milestones below gate on working, tested code — not
dates.

## v0.7 — Fleet intelligence (in progress)

- **Fleet summary**: when processing multiple workloads, lead with
  "one fix → N workloads" — the aggregated view an operator acts on first
- **Third-party image detection**: vendor-built images (registry.k8s.io,
  GKE system images, Docker official, etc.) get "upgrade to the newest
  vendor tag" as the primary recommendation instead of in-place commands
- Live-tenant validation of both

## v0.8 — AI ecosystem

- **MCP server**: expose remedify as a Model Context Protocol tool so AI
  agents (Claude, etc.) can request deterministic remediation plans —
  "the reliable hands for AI-driven security workflows"
- **PyPI release** (`pip install remedify`), GitHub Releases with changelog
- JSON schema for the plan output (stable contract for agents/integrations)

## v0.9 — Automation & integrations

- **`--format ansible`**: emit a multi-distro remediation playbook — closes
  the "emits commands but doesn't execute" gap via the tool ops teams
  already trust (what Red Hat Insights does, but not RHEL-only)
- **OSV-Scanner input** (OSV JSON is becoming the lingua franca)
- `--format sarif` (GitHub Code Scanning)
- GitHub Action: scan → remediation plan as PR comment / artifact
- Recipes: cron + ticket auto-filing (Jira/DevRev examples)
- copa-compatible output for container findings (complete the copa story)

## v1.0 — Data correctness & trust

- endoflife.date API for live EOL data (replacing the static table)
- Vendor advisory cross-check (Ubuntu USN API, RHEL CSAF) so advisory links
  don't depend on scanner input
- Validation against real customer report exports and multi-region tenants
- Decide: Go rewrite (single static binary) once interfaces are stable

## Continuous (every release)

- Real-tenant / real-OS validation for anything touching parsers or commands
- Fuzz suite stays green (`FUZZ_N=10000` deep pass before release)
- Honest docs: capability comparisons updated as competitors evolve
