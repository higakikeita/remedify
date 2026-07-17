#!/usr/bin/env python3
"""
remedify - Turn vulnerability scan results into concrete, OS-specific remediation commands.

"copa patches container images. remedify tells you how to patch everything else."

PoC scope:
  * Input : Trivy JSON (`trivy image|fs|rootfs ... --format json`)
  * Output: Markdown report / shell script / JSON with per-distro fix commands,
            vendor-backport notes, advisory links, and reboot/restart hints.

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


def detect_pkg_manager(family: str, os_name: str):
    f = (family or "").lower()
    if f in APT_FAMILIES:
        return "apt"
    if f in DNF_FAMILIES:
        # Amazon Linux 2 still ships yum as primary
        if f == "amazon" and str(os_name).strip().startswith("2"):
            return "yum"
        return "dnf"
    if f in APK_FAMILIES:
        return "apk"
    if f in ZYPPER_FAMILIES:
        return "zypper"
    return None


def fix_command(pkg_manager: str, package: str, version: str):
    if pkg_manager == "apt":
        return f"apt-get install --only-upgrade {package}={version}"
    if pkg_manager == "dnf":
        return f"dnf update -y {package}-{version}"
    if pkg_manager == "yum":
        return f"yum update -y {package}-{version}"
    if pkg_manager == "apk":
        return f"apk upgrade {package}"
    if pkg_manager == "zypper":
        return f"zypper update -y {package}"
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


def classify_references(refs):
    """Return list of (label, url), vendor advisories first, deduped, max 3."""
    scored = []
    for url in refs or []:
        for i, (label, pattern) in enumerate(ADVISORY_PATTERNS):
            if pattern.search(url):
                scored.append((i, label, url))
                break
    scored.sort(key=lambda t: t[0])
    seen, out = set(), []
    for _, label, url in scored:
        if url not in seen:
            seen.add(url)
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
        "vulns": [], "fixed_versions": set(), "installed": None, "max_severity": "UNKNOWN",
        "references": [],
    })

    for result in data.get("Results", []) or []:
        if result.get("Class") not in (None, "os-pkgs"):
            continue  # PoC: OS packages only; lang-pkgs on the roadmap
        for v in result.get("Vulnerabilities", []) or []:
            fixed = (v.get("FixedVersion") or "").strip()
            if not fixed:
                continue  # no fix available -> out of scope for command generation
            pkg = v.get("PkgName")
            f = findings[pkg]
            f["installed"] = v.get("InstalledVersion")
            # FixedVersion may contain multiple candidates ("1.2.3, 2.0.1")
            for candidate in re.split(r"[,\s]+", fixed):
                if candidate:
                    f["fixed_versions"].add(candidate)
            sev = (v.get("Severity") or "UNKNOWN").upper()
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(f["max_severity"], 0):
                f["max_severity"] = sev
            f["vulns"].append({
                "id": v.get("VulnerabilityID"),
                "severity": sev,
                "title": v.get("Title", ""),
            })
            refs = v.get("References") or []
            if v.get("PrimaryURL"):
                refs = [v["PrimaryURL"]] + refs
            f["references"].extend(refs)

    return {"target": target, "family": family, "os_name": os_name, "findings": findings}


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def build_plan(parsed, min_severity="UNKNOWN"):
    pkg_manager = detect_pkg_manager(parsed["family"], parsed["os_name"])
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)

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
    return {
        "target": parsed["target"],
        "os": f'{parsed["family"]} {parsed["os_name"]}'.strip(),
        "pkg_manager": pkg_manager,
        "preamble": preamble(pkg_manager) if pkg_manager else None,
        "items": items,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_markdown(plan):
    lines = []
    lines.append(f"# Remediation plan: `{plan['target']}`")
    lines.append("")
    lines.append(f"- **OS**: {plan['os']}")
    lines.append(f"- **Package manager**: {plan['pkg_manager'] or 'unsupported (see notes)'}")
    lines.append(f"- **Fixable packages**: {len(plan['items'])}")
    lines.append("")
    if not plan["pkg_manager"]:
        lines.append("> Unsupported OS family for command generation. "
                     "Findings are listed without commands.")
        lines.append("")

    for item in plan["items"]:
        lines.append(f"## {item['package']}  `{item['severity']}`")
        lines.append("")
        lines.append(f"- Installed: `{item['installed']}` -> Fix: `{item['fix_version']}`")
        lines.append(f"- CVEs: {', '.join(item['cves'])}")
        if item["backport"]:
            lines.append(f"- **Vendor backport ({item['backport']})**: the fixed version is a "
                         f"distro backport — it will not match the upstream version number. "
                         f"Scanners comparing against upstream may still flag it; trust the "
                         f"vendor advisory below.")
        if item["command"]:
            lines.append("")
            lines.append("```bash")
            lines.append(item["command"])
            lines.append("```")
        for hint in item["hints"]:
            lines.append(f"- ⚠️ {hint}")
        if item["advisories"]:
            lines.append("- Advisories: " + " / ".join(
                f"[{label}]({url})" for label, url in item["advisories"]))
        lines.append("")

    return "\n".join(lines)


def render_shell(plan):
    lines = [
        "#!/usr/bin/env bash",
        f"# Remediation script generated by remedify for {plan['target']} ({plan['os']})",
        "# Review before running. Run as root or with sudo.",
        "set -euo pipefail",
        "",
    ]
    if plan["preamble"]:
        lines.append(plan["preamble"])
        lines.append("")
    needs_reboot = False
    for item in plan["items"]:
        if not item["command"]:
            continue
        lines.append(f"# {item['package']} {item['installed']} -> {item['fix_version']} "
                     f"[{item['severity']}] {', '.join(item['cves'])}")
        if item["backport"]:
            lines.append(f"#   NOTE: {item['backport']} vendor backport — version differs from upstream")
        for hint in item["hints"]:
            lines.append(f"#   WARNING: {hint}")
            if "reboot" in hint.lower():
                needs_reboot = True
        lines.append(item["command"])
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
