#!/usr/bin/env python3
"""
remedify - Turn vulnerability scan results into concrete, OS-specific remediation commands.

"copa patches container images. remedify tells you how to patch everything else."

v0.2:
  * Consolidated remediation steps (source-package grouping)
  * "No fix available" section (uses Trivy's Status field)
  * EOL / ESM awareness
  * Input : Trivy JSON (`trivy image|fs|rootfs ... --format json`)
  * Output: Markdown report / shell script / JSON

Usage:
  python3 remedify.py scan.json                    # markdown report (default)
  python3 remedify.py scan.json --format shell     # executable remediation script
  python3 remedify.py scan.json --format json      # machine-readable
  python3 remedify.py scan.json --min-severity HIGH

Stdlib only. No dependencies.
"""

import argparse
import json
import re
import sys
from collections import defaultdict

__version__ = "0.2.0"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# ---------------------------------------------------------------------------
# Distro handling
# ---------------------------------------------------------------------------

APT_FAMILIES = {"debian", "ubuntu"}
DNF_FAMILIES = {"redhat", "rhel", "centos", "rocky", "almalinux", "alma",
                "oracle", "fedora", "amazon"}
APK_FAMILIES = {"alpine"}
ZYPPER_FAMILIES = {"suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed"}

# Vendor backport markers embedded in package versions
BACKPORT_PATTERNS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu"),
    (re.compile(r"\+esm", re.I), "Ubuntu ESM"),
    (re.compile(r"\+deb\d+|~deb\d+", re.I), "Debian"),
    (re.compile(r"\.el\d+", re.I), "RHEL"),
    (re.compile(r"\.amzn\d+", re.I), "Amazon Linux"),
]

# Advisory URL patterns worth surfacing (vendor sources first)
ADVISORY_PATTERNS = [
    ("Ubuntu USN", re.compile(r"ubuntu\.com/security/notices|ubuntu\.com/usn")),
    ("Debian DSA", re.compile(r"security-tracker\.debian\.org|debian\.org/security")),
    ("RHEL Errata", re.compile(r"access\.redhat\.com/errata")),
    ("Red Hat CVE", re.compile(r"access\.redhat\.com/security/cve")),
    ("Amazon ALAS", re.compile(r"alas\.aws\.amazon\.com")),
    ("SUSE", re.compile(r"suse\.com/security")),
    ("Alpine", re.compile(r"security\.alpinelinux\.org")),
    ("NVD", re.compile(r"nvd\.nist\.gov")),
]

# Packages whose update implies reboot / service restarts
REBOOT_PACKAGES = re.compile(r"^(linux-image|linux-headers|linux-generic|linux|kernel)(-|$)")
LIBC_PACKAGES = {"libc6", "glibc", "libc-bin", "musl"}
RESTART_HINT_PACKAGES = {
    "openssl": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "libssl3": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "libssl1.1": "Restart services that link against OpenSSL (nginx, sshd, etc.).",
    "systemd": "Run `systemctl daemon-reexec` or reboot.",
    "dbus": "A reboot is recommended after updating dbus.",
}

# End-of-life distro versions (standard repos no longer receive security fixes).
# Deliberately conservative; roadmap: pull from endoflife.date API.
EOL_VERSIONS = {
    "ubuntu": {
        "versions": {"14.04", "16.04", "18.04", "20.04"},
        "note": ("Ubuntu {v} standard repositories no longer receive security "
                 "updates. Fixes for many CVEs require Ubuntu Pro (ESM). "
                 "Commands below may fail to find the fixed version without "
                 "ESM enrollment."),
    },
    "debian": {
        "versions": {"8", "9", "10"},
        "note": ("Debian {v} is end-of-life. Security fixes may only exist in "
                 "Debian LTS/ELTS. Consider upgrading the base OS."),
    },
    "centos": {
        "versions": {"6", "7", "8"},
        "note": ("CentOS {v} is end-of-life. No further security updates are "
                 "published. Migrate to a supported distribution "
                 "(Rocky/Alma/RHEL/CentOS Stream)."),
    },
    "amazon": {
        "versions": {"1", "2018.03"},
        "note": "Amazon Linux {v} is end-of-life. Migrate to AL2023.",
    },
}

# Trivy Status values that mean "no command to give you"
UNFIXED_STATUS_LABELS = {
    "affected": "No vendor fix released yet",
    "fix_deferred": "Fix deferred by vendor",
    "will_not_fix": "Vendor will not fix — assess exposure and mitigate",
    "end_of_life": "Distro version is EOL — no fix will be published",
    "": "No fixed version reported",
}


def detect_pkg_manager(family: str, os_name: str):
    f = (family or "").lower()
    if f in APT_FAMILIES:
        return "apt"
    if f in DNF_FAMILIES:
        if f == "amazon" and str(os_name).strip().startswith("2"):
            return "yum"
        return "dnf"
    if f in APK_FAMILIES:
        return "apk"
    if f in ZYPPER_FAMILIES:
        return "zypper"
    return None


def fix_command(pkg_manager: str, packages, version: str):
    """Consolidated command for one or more packages sharing a fixed version."""
    if isinstance(packages, str):
        packages = [packages]
    if pkg_manager == "apt":
        specs = " ".join(f"{p}={version}" for p in packages)
        return f"apt-get install --only-upgrade {specs}"
    if pkg_manager in ("dnf", "yum"):
        specs = " ".join(f"{p}-{version}" for p in packages)
        return f"{pkg_manager} update -y {specs}"
    if pkg_manager == "apk":
        return "apk upgrade " + " ".join(packages)
    if pkg_manager == "zypper":
        return "zypper update -y " + " ".join(packages)
    return None


def preamble(pkg_manager: str):
    return {
        "apt": "apt-get update",
        "dnf": "dnf makecache",
        "yum": "yum makecache",
        "apk": "apk update",
        "zypper": "zypper refresh",
    }.get(pkg_manager)


def detect_backport(version: str):
    for pattern, vendor in BACKPORT_PATTERNS:
        if pattern.search(version or ""):
            return vendor
    return None


def detect_eol(family: str, os_name: str):
    entry = EOL_VERSIONS.get((family or "").lower())
    if entry and str(os_name).strip() in entry["versions"]:
        return entry["note"].format(v=os_name)
    return None


def classify_references(refs):
    """Return list of (label, url), vendor advisories first, deduped, max 3.

    Near-duplicate advisories from the same family (USN-4142-1 / USN-4142-2)
    are collapsed to the first seen.
    """
    scored = []
    for url in refs or []:
        for i, (label, pattern) in enumerate(ADVISORY_PATTERNS):
            if pattern.search(url):
                scored.append((i, label, url))
                break
    scored.sort(key=lambda t: t[0])
    seen_urls, seen_families, out = set(), set(), []
    for _, label, url in scored:
        if url in seen_urls:
            continue
        family = re.sub(r"-\d+/?$", "", url.rstrip("/"))
        if family in seen_families:
            continue
        seen_urls.add(url)
        seen_families.add(family)
        out.append((label, url))
        if len(out) >= 3:
            break
    return out


def post_update_hints(package: str):
    hints = []
    if REBOOT_PACKAGES.match(package):
        hints.append("Kernel update: reboot required.")
    if package in LIBC_PACKAGES:
        hints.append("libc update: reboot strongly recommended (all processes link against it).")
    if package in RESTART_HINT_PACKAGES:
        hints.append(RESTART_HINT_PACKAGES[package])
    return hints


# ---------------------------------------------------------------------------
# Version comparison (loose; PoC-grade)
# ---------------------------------------------------------------------------

def _version_key(v: str):
    parts = re.split(r"[^0-9a-zA-Z]+", v or "")
    key = []
    for p in parts:
        if p.isdigit():
            key.append((1, int(p), ""))
        else:
            key.append((0, 0, p))
    return key


def highest_version(versions):
    return max(versions, key=_version_key)


# ---------------------------------------------------------------------------
# Trivy parser
# ---------------------------------------------------------------------------

def parse_trivy(data: dict):
    meta = data.get("Metadata", {}) or {}
    os_info = meta.get("OS", {}) or {}
    family = os_info.get("Family", "")
    os_name = os_info.get("Name", "")
    target = data.get("ArtifactName", "unknown")

    findings = defaultdict(lambda: {
        "vulns": [], "fixed_versions": set(), "installed": None,
        "max_severity": "UNKNOWN", "references": [],
    })
    unfixed = defaultdict(lambda: {
        "vulns": [], "installed": None, "max_severity": "UNKNOWN",
    })

    for result in data.get("Results", []) or []:
        if result.get("Class") not in (None, "os-pkgs"):
            continue  # PoC: OS packages only; lang-pkgs on the roadmap
        for v in result.get("Vulnerabilities", []) or []:
            pkg = v.get("PkgName")
            sev = (v.get("Severity") or "UNKNOWN").upper()
            status = (v.get("Status") or "").lower()
            fixed = (v.get("FixedVersion") or "").strip()
            vuln = {"id": v.get("VulnerabilityID"), "severity": sev,
                    "title": v.get("Title", ""), "status": status}

            if not fixed:
                u = unfixed[pkg]
                u["installed"] = v.get("InstalledVersion")
                u["vulns"].append(vuln)
                if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(u["max_severity"], 0):
                    u["max_severity"] = sev
                continue

            f = findings[pkg]
            f["installed"] = v.get("InstalledVersion")
            for candidate in re.split(r"[,\s]+", fixed):
                if candidate:
                    f["fixed_versions"].add(candidate)
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(f["max_severity"], 0):
                f["max_severity"] = sev
            f["vulns"].append(vuln)
            refs = v.get("References") or []
            if v.get("PrimaryURL"):
                refs = [v["PrimaryURL"]] + refs
            f["references"].extend(refs)

    return {"target": target, "family": family, "os_name": os_name,
            "findings": findings, "unfixed": unfixed}


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def build_plan(parsed, min_severity="UNKNOWN"):
    pkg_manager = detect_pkg_manager(parsed["family"], parsed["os_name"])
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)

    # Per-package items (kept for JSON consumers / tests)
    items = []
    for pkg, f in sorted(parsed["findings"].items()):
        if SEVERITY_ORDER.get(f["max_severity"], 0) < threshold:
            continue
        target_version = highest_version(f["fixed_versions"])
        items.append({
            "package": pkg,
            "installed": f["installed"],
            "fix_version": target_version,
            "severity": f["max_severity"],
            "cves": sorted({v["id"] for v in f["vulns"] if v["id"]}),
            "command": fix_command(pkg_manager, pkg, target_version) if pkg_manager else None,
            "backport": detect_backport(target_version),
            "advisories": classify_references(f["references"]),
            "hints": post_update_hints(pkg),
        })
    items.sort(key=lambda i: -SEVERITY_ORDER.get(i["severity"], 0))

    # Consolidated steps: same installed+fixed version pair => almost always
    # binary packages built from one source package => one remediation action.
    groups = defaultdict(list)
    for item in items:
        groups[(item["installed"], item["fix_version"])].append(item)

    steps = []
    for (installed, fix_version), members in groups.items():
        packages = [m["package"] for m in members]
        cves = sorted({c for m in members for c in m["cves"]})
        severity = max((m["severity"] for m in members),
                       key=lambda s: SEVERITY_ORDER.get(s, 0))
        advisories, seen = [], set()
        for m in members:
            for a in m["advisories"]:
                if a[1] not in seen:
                    seen.add(a[1])
                    advisories.append(a)
        hints = sorted({h for m in members for h in m["hints"]})
        steps.append({
            "packages": packages,
            "installed": installed,
            "fix_version": fix_version,
            "severity": severity,
            "cves": cves,
            "command": fix_command(pkg_manager, packages, fix_version) if pkg_manager else None,
            "backport": detect_backport(fix_version),
            "advisories": advisories[:3],
            "hints": hints,
        })
    steps.sort(key=lambda s: -SEVERITY_ORDER.get(s["severity"], 0))

    # Unfixed findings (never filtered by min-severity: silent omission erodes trust)
    unfixed = []
    for pkg, u in sorted(parsed["unfixed"].items()):
        statuses = {v["status"] for v in u["vulns"]}
        status = next(iter(statuses)) if len(statuses) == 1 else "mixed"
        unfixed.append({
            "package": pkg,
            "installed": u["installed"],
            "severity": u["max_severity"],
            "cves": sorted({v["id"] for v in u["vulns"] if v["id"]}),
            "status": status,
            "status_label": UNFIXED_STATUS_LABELS.get(status, f"Status: {status}"),
        })
    unfixed.sort(key=lambda i: -SEVERITY_ORDER.get(i["severity"], 0))

    return {
        "target": parsed["target"],
        "os": f'{parsed["family"]} {parsed["os_name"]}'.strip(),
        "pkg_manager": pkg_manager,
        "preamble": preamble(pkg_manager) if pkg_manager else None,
        "eol_warning": detect_eol(parsed["family"], parsed["os_name"]),
        "items": items,
        "steps": steps,
        "unfixed": unfixed,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _step_title(step):
    pkgs = step["packages"]
    if len(pkgs) == 1:
        return pkgs[0]
    return f"{pkgs[0]} (+{len(pkgs) - 1} related packages)"


def render_markdown(plan):
    lines = []
    lines.append(f"# Remediation plan: `{plan['target']}`")
    lines.append("")
    lines.append(f"- **OS**: {plan['os']}")
    lines.append(f"- **Package manager**: {plan['pkg_manager'] or 'unsupported (see notes)'}")
    lines.append(f"- **Remediation steps**: {len(plan['steps'])} "
                 f"(covering {len(plan['items'])} packages)")
    if plan["unfixed"]:
        lines.append(f"- **No fix available**: {len(plan['unfixed'])} packages")
    lines.append("")
    if plan["eol_warning"]:
        lines.append(f"> ⚠️ **EOL**: {plan['eol_warning']}")
        lines.append("")
    if not plan["pkg_manager"]:
        lines.append("> Unsupported OS family for command generation. "
                     "Findings are listed without commands.")
        lines.append("")

    for step in plan["steps"]:
        lines.append(f"## {_step_title(step)}  `{step['severity']}`")
        lines.append("")
        if len(step["packages"]) > 1:
            lines.append(f"- Packages: {', '.join(f'`{p}`' for p in step['packages'])} "
                         f"(same source, one update)")
        lines.append(f"- Installed: `{step['installed']}` -> Fix: `{step['fix_version']}`")
        lines.append(f"- CVEs: {', '.join(step['cves'])}")
        if step["backport"]:
            lines.append(f"- **Vendor backport ({step['backport']})**: the fixed version is a "
                         f"distro backport — it will not match the upstream version number. "
                         f"Scanners comparing against upstream may still flag it; trust the "
                         f"vendor advisory below.")
        if step["command"]:
            lines.append("")
            lines.append("```bash")
            lines.append(step["command"])
            lines.append("```")
        for hint in step["hints"]:
            lines.append(f"- ⚠️ {hint}")
        if step["advisories"]:
            lines.append("- Advisories: " + " / ".join(
                f"[{label}]({url})" for label, url in step["advisories"]))
        lines.append("")

    if plan["unfixed"]:
        lines.append("## No fix available")
        lines.append("")
        lines.append("These findings have no fixed version yet. Options: mitigate, "
                     "accept the risk with justification, or track the vendor advisory.")
        lines.append("")
        for u in plan["unfixed"]:
            lines.append(f"- **{u['package']}** `{u['severity']}` "
                         f"({', '.join(u['cves'])}) — {u['status_label']}")
        lines.append("")

    return "\n".join(lines)


def render_shell(plan):
    lines = [
        "#!/usr/bin/env bash",
        f"# Remediation script generated by remedify v{__version__} "
        f"for {plan['target']} ({plan['os']})",
        "# Review before running. Run as root or with sudo.",
        "set -euo pipefail",
        "",
    ]
    if plan["eol_warning"]:
        lines.append(f"# EOL WARNING: {plan['eol_warning']}")
        lines.append("")
    if plan["preamble"]:
        lines.append(plan["preamble"])
        lines.append("")
    needs_reboot = False
    for step in plan["steps"]:
        if not step["command"]:
            continue
        lines.append(f"# {', '.join(step['packages'])} {step['installed']} -> "
                     f"{step['fix_version']} [{step['severity']}] {', '.join(step['cves'])}")
        if step["backport"]:
            lines.append(f"#   NOTE: {step['backport']} vendor backport — version differs from upstream")
        for hint in step["hints"]:
            lines.append(f"#   WARNING: {hint}")
            if "reboot" in hint.lower():
                needs_reboot = True
        lines.append(step["command"])
        lines.append("")
    if plan["unfixed"]:
        lines.append("# --- No fix available (informational) ---")
        for u in plan["unfixed"]:
            lines.append(f"# {u['package']} [{u['severity']}] "
                         f"{', '.join(u['cves'])}: {u['status_label']}")
        lines.append("")
    if needs_reboot:
        lines.append('echo "One or more updates require a reboot. Schedule one."')
    return "\n".join(lines)


def render_json(plan):
    return json.dumps(plan, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        prog="remedify",
        description="Turn vulnerability scan results into OS-specific remediation commands.")
    ap.add_argument("scan", help="Path to Trivy JSON output (or '-' for stdin)")
    ap.add_argument("--format", choices=["markdown", "shell", "json"], default="markdown")
    ap.add_argument("--min-severity", default="UNKNOWN",
                    choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("--version", action="version", version=f"remedify {__version__}")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.scan == "-" else open(args.scan, encoding="utf-8").read()
    data = json.loads(raw)

    if "Results" not in data:
        sys.exit("error: input does not look like Trivy JSON (missing 'Results'). "
                 "Grype/Sysdig parsers are on the roadmap.")

    plan = build_plan(parse_trivy(data), args.min_severity)

    renderer = {"markdown": render_markdown, "shell": render_shell, "json": render_json}
    print(renderer[args.format](plan))


if __name__ == "__main__":
    main()
