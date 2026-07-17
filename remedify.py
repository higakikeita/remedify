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
import csv
import io
import json
import re
import sys
from collections import defaultdict

__version__ = "0.4.0"

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

# Language-package ecosystems: Trivy Result.Type / Sysdig package type -> ecosystem
LANG_ECOSYSTEMS = {
    # Trivy types
    "jar": "java", "pom": "java", "gradle-lockfile": "java", "sbt-lockfile": "java",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm",
    "pip": "python", "poetry": "python", "pipenv": "python", "python-pkg": "python",
    "gomod": "go", "gobinary": "go",
    "gemspec": "ruby", "bundler": "ruby",
    "composer": "php",
    "cargo": "rust",
    "nuget": "dotnet", "dotnet-core": "dotnet",
    # Sysdig package types
    "java": "java", "javascript": "npm", "python": "python", "golang": "go",
    "ruby": "ruby", "php": "php", "rust": "rust", "c#": "dotnet",
}


def app_fix_action(ecosystem: str, package: str, version: str):
    """Human-actionable fix for an application dependency. Always implies rebuild."""
    if ecosystem == "java":
        return (f"Update `{package}` to `{version}` in pom.xml / build.gradle "
                f"(check the dependency tree: it may be transitive — pin via "
                f"dependencyManagement / constraints).")
    if ecosystem == "npm":
        return f"`npm install {package}@{version}` (update package.json / lockfile)."
    if ecosystem == "python":
        return f"`pip install --upgrade {package}=={version}` and update requirements.txt / lockfile."
    if ecosystem == "go":
        return f"`go get {package}@v{version.lstrip('v')} && go mod tidy`."
    if ecosystem == "ruby":
        return f"Update `{package}` to `{version}` in Gemfile, then `bundle update {package}`."
    if ecosystem == "php":
        return f"`composer require {package}:{version}`."
    if ecosystem == "rust":
        return f"Update `{package}` to `{version}` in Cargo.toml, then `cargo update -p {package}`."
    if ecosystem == "dotnet":
        return f"`dotnet add package {package} --version {version}`."
    return f"Update `{package}` to `{version}` in your dependency manifest."


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

    parsed = _empty_parsed(target, family, os_name)

    for result in data.get("Results", []) or []:
        klass = result.get("Class")
        is_os = klass in (None, "os-pkgs")
        ecosystem = LANG_ECOSYSTEMS.get((result.get("Type") or "").lower())
        if not is_os and (klass != "lang-pkgs" or not ecosystem):
            continue
        for v in result.get("Vulnerabilities", []) or []:
            refs = v.get("References") or []
            if v.get("PrimaryURL"):
                refs = [v["PrimaryURL"]] + refs
            _add_finding(
                parsed,
                pkg=v.get("PkgName"),
                installed=v.get("InstalledVersion"),
                fixed=(v.get("FixedVersion") or "").strip(),
                severity=(v.get("Severity") or "UNKNOWN").upper(),
                vuln_id=v.get("VulnerabilityID"),
                status=(v.get("Status") or "").lower(),
                title=v.get("Title", ""),
                references=refs,
                ecosystem=None if is_os else ecosystem,
                location=result.get("Target") if not is_os else None,
            )
    return parsed


def _empty_parsed(target="unknown", family="", os_name=""):
    return {
        "target": target, "family": family, "os_name": os_name,
        "findings": defaultdict(lambda: {
            "vulns": [], "fixed_versions": set(), "installed": None,
            "max_severity": "UNKNOWN", "references": [],
        }),
        "unfixed": defaultdict(lambda: {
            "vulns": [], "installed": None, "max_severity": "UNKNOWN",
            "ecosystem": None,
        }),
        "app": defaultdict(lambda: {
            "vulns": [], "fixed_versions": set(), "installed": None,
            "max_severity": "UNKNOWN", "locations": set(),
        }),
    }


def _add_finding(parsed, pkg, installed, fixed, severity, vuln_id,
                 status="", title="", references=None, ecosystem=None,
                 location=None):
    """Route one vulnerability record into findings / app / unfixed."""
    if not pkg:
        return
    sev = severity if severity in SEVERITY_ORDER else \
        {"NEGLIGIBLE": "LOW"}.get(severity, "UNKNOWN")
    vuln = {"id": vuln_id, "severity": sev, "title": title, "status": status}

    if not fixed or fixed.lower() in ("none", "n/a", "-"):
        u = parsed["unfixed"][pkg]
        u["installed"] = installed or u["installed"]
        u["ecosystem"] = ecosystem
        u["vulns"].append(vuln)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(u["max_severity"], 0):
            u["max_severity"] = sev
        return

    if ecosystem:
        a = parsed["app"][(ecosystem, pkg)]
        a["installed"] = installed or a["installed"]
        if location:
            a["locations"].add(location)
        for candidate in re.split(r"[,\s]+", fixed):
            if candidate:
                a["fixed_versions"].add(candidate)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(a["max_severity"], 0):
            a["max_severity"] = sev
        a["vulns"].append(vuln)
        return

    f = parsed["findings"][pkg]
    f["installed"] = installed or f["installed"]
    for candidate in re.split(r"[,\s]+", fixed):
        if candidate:
            f["fixed_versions"].add(candidate)
    if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(f["max_severity"], 0):
        f["max_severity"] = sev
    f["vulns"].append(vuln)
    f["references"].extend(references or [])


# ---------------------------------------------------------------------------
# Sysdig CSV parser (vulnerability report exports)
# ---------------------------------------------------------------------------
# Column names vary across Sysdig report templates and versions, so we match
# headers against aliases, case-insensitively. To adapt to a new export
# variant, extend these alias lists — nothing else should need to change.

SYSDIG_COLUMN_ALIASES = {
    "vuln_id": ["vulnerability id", "cve id", "vuln id", "cve", "vulnerability"],
    "severity": ["severity", "vulnerability severity"],
    "package": ["package name", "package", "package path", "resource name"],
    "installed": ["package version", "installed version", "version",
                  "current version"],
    "fixed": ["fix version", "fixed in", "fixed version", "fix",
              "solved in version"],
    "pkg_type": ["package type", "type"],
    "os": ["image os", "os", "operating system", "os name", "distro"],
    "target": ["image", "image name", "hostname", "host", "asset",
               "workload", "image tag"],
}

# Only OS packages get commands; language packages are on the roadmap
SYSDIG_OS_PKG_TYPES = {"os", "deb", "rpm", "apk", "dpkg", ""}


def _sysdig_header_map(fieldnames):
    mapping = {}
    lowered = {(f or "").strip().lower(): f for f in fieldnames or []}
    for key, aliases in SYSDIG_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                mapping[key] = lowered[alias]
                break
    return mapping


def parse_os_string(os_string: str):
    """'Ubuntu 22.04' / 'ubuntu:22.04' / 'rhel 9.3' -> (family, name)."""
    s = (os_string or "").strip().replace(":", " ")
    if not s:
        return "", ""
    parts = s.split()
    family = parts[0].lower()
    if family in ("red", "redhat") and len(parts) > 1 and parts[1].lower() == "hat":
        family, parts = "redhat", [p for p in parts if p.lower() != "hat"]
    name = " ".join(parts[1:])
    # normalize common vendor spellings
    family = {"rhel": "redhat", "amazonlinux": "amazon", "amzn": "amazon"}.get(family, family)
    return family, name


def parse_sysdig_csv(text: str, os_override: str = None):
    reader = csv.DictReader(io.StringIO(text))
    cols = _sysdig_header_map(reader.fieldnames)
    required = {"vuln_id", "package", "fixed"}
    missing = required - set(cols)
    if missing:
        expected = {k: SYSDIG_COLUMN_ALIASES[k] for k in sorted(missing)}
        sys.exit("error: could not find required column(s) in Sysdig CSV: "
                 f"{sorted(missing)}. Accepted header names: {expected}. "
                 "If your export uses different headers, please open an issue "
                 "with the header row.")

    parsed = _empty_parsed("sysdig-report")
    os_string = ""
    for row in reader:
        def col(key, default=""):
            return (row.get(cols[key], default) or default).strip() if key in cols else default

        pkg = col("package")
        if not pkg:
            continue
        if col("target"):
            parsed["target"] = col("target")
        if col("os"):
            os_string = col("os")

        pkg_type = col("pkg_type").lower()
        ecosystem = None
        if pkg_type not in SYSDIG_OS_PKG_TYPES:
            ecosystem = LANG_ECOSYSTEMS.get(pkg_type)
            if not ecosystem:
                continue  # unknown package type
        _add_finding(parsed, pkg=pkg, installed=col("installed"),
                     fixed=col("fixed"), severity=(col("severity") or "UNKNOWN").upper(),
                     vuln_id=col("vuln_id"), ecosystem=ecosystem)

    parsed["family"], parsed["os_name"] = parse_os_string(os_override or os_string)
    return parsed


# ---------------------------------------------------------------------------
# Sysdig scan-result JSON parser (sysdig-cli-scanner / Vulnerability Management API)
# ---------------------------------------------------------------------------
# Shape: {"result": {"metadata": {...}, "packages": [
#   {"type": "os"|"java"|..., "name", "version", "path", "suggestedFix",
#    "vulns": [{"name": "CVE-...", "severity": {"value": "Critical"},
#               "fixedInVersion": "..."}]}]}}
# NOTE: field names validated against sysdig-cli-scanner output; treat as beta
# until confirmed against your tenant's API version.

def parse_sysdig_json(data: dict, os_override: str = None):
    result = data.get("result", data)
    meta = result.get("metadata", {}) or {}
    target = meta.get("pullString") or meta.get("imageId") or "sysdig-scan"
    os_string = meta.get("baseOs", "")

    parsed = _empty_parsed(target)
    for pkg in result.get("packages", []) or []:
        pkg_type = (pkg.get("type") or "").lower()
        ecosystem = None
        if pkg_type not in SYSDIG_OS_PKG_TYPES:
            ecosystem = LANG_ECOSYSTEMS.get(pkg_type)
            if not ecosystem:
                continue
        for v in pkg.get("vulns", []) or []:
            sev = v.get("severity")
            if isinstance(sev, dict):
                sev = sev.get("value", "UNKNOWN")
            fixed = v.get("fixedInVersion") or pkg.get("suggestedFix") or ""
            _add_finding(parsed, pkg=pkg.get("name"),
                         installed=pkg.get("version"), fixed=fixed,
                         severity=(sev or "UNKNOWN").upper(),
                         vuln_id=v.get("name"), ecosystem=ecosystem,
                         location=pkg.get("path"))

    if os_override or os_string:
        parsed["family"], parsed["os_name"] = parse_os_string(os_override or os_string)
    return parsed


def fetch_sysdig(api_url: str, token: str, result_id: str = None, filter_expr: str = None):
    """Fetch a scan result from the Sysdig Vulnerability Management API.

    Without --result-id, lists runtime results and picks the first match.
    Beta: endpoint paths follow the public VM API (v1); report issues with
    your region/API version if they differ.
    """
    import urllib.request

    def get(path):
        req = urllib.request.Request(
            api_url.rstrip("/") + path,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())

    if not result_id:
        query = "/secure/vulnerability/v1/runtime-results?limit=1"
        if filter_expr:
            import urllib.parse
            query += "&filter=" + urllib.parse.quote(filter_expr)
        listing = get(query)
        rows = listing.get("data") or []
        if not rows:
            sys.exit("error: no runtime scan results matched. "
                     "Try --result-id or adjust --filter.")
        result_id = rows[0].get("resultId") or rows[0].get("id")
    return get(f"/secure/vulnerability/v1/results/{result_id}")


def detect_input_format(raw: str):
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            return "trivy"
        if "Results" in data:
            return "trivy"
        if "packages" in data.get("result", data):
            return "sysdig-json"
        return "trivy"
    return "sysdig-csv"


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

    # Application dependencies (lang-pkgs): fix = upgrade + rebuild
    app_steps = []
    for (ecosystem, pkg), a in sorted(parsed.get("app", {}).items()):
        if SEVERITY_ORDER.get(a["max_severity"], 0) < threshold:
            continue
        fix_version = highest_version(a["fixed_versions"])
        app_steps.append({
            "ecosystem": ecosystem,
            "package": pkg,
            "installed": a["installed"],
            "fix_version": fix_version,
            "severity": a["max_severity"],
            "cves": sorted({v["id"] for v in a["vulns"] if v["id"]}),
            "locations": sorted(a["locations"]),
            "action": app_fix_action(ecosystem, pkg, fix_version),
        })
    app_steps.sort(key=lambda s: -SEVERITY_ORDER.get(s["severity"], 0))

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
        "app_steps": app_steps,
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
    if plan["app_steps"]:
        lines.append(f"- **Application dependencies (rebuild required)**: "
                     f"{len(plan['app_steps'])}")
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

    if plan["app_steps"]:
        lines.append("## Application dependencies (rebuild required)")
        lines.append("")
        lines.append("These are language packages inside your application or image. "
                     "OS package managers cannot fix them — and neither can copa. "
                     "Update the dependency, rebuild, and redeploy.")
        lines.append("")
        for step in plan["app_steps"]:
            lines.append(f"### {step['package']}  `{step['severity']}` ({step['ecosystem']})")
            lines.append("")
            lines.append(f"- Installed: `{step['installed']}` -> Fix: `{step['fix_version']}`")
            lines.append(f"- CVEs: {', '.join(step['cves'])}")
            if step["locations"]:
                lines.append(f"- Found in: {', '.join(f'`{l}`' for l in step['locations'])}")
            lines.append(f"- Fix: {step['action']}")
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
    if plan["app_steps"]:
        lines.append("# --- Application dependencies: fix in source + rebuild image ---")
        for step in plan["app_steps"]:
            lines.append(f"# {step['package']} ({step['ecosystem']}) "
                         f"{step['installed']} -> {step['fix_version']} "
                         f"[{step['severity']}] {', '.join(step['cves'])}")
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
    ap.add_argument("scan", nargs="?", default=None,
                    help="Path to Trivy JSON, Sysdig scan-result JSON, or Sysdig CSV "
                         "export ('-' for stdin). Omit when using --from-sysdig.")
    ap.add_argument("--format", choices=["markdown", "shell", "json"], default="markdown")
    ap.add_argument("--min-severity", default="UNKNOWN",
                    choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ap.add_argument("--input", choices=["auto", "trivy", "sysdig-csv", "sysdig-json"],
                    default="auto", help="Input format (default: auto-detect)")
    ap.add_argument("--os", dest="os_override", default=None, metavar="FAMILY:VERSION",
                    help="OS override for inputs lacking OS metadata, "
                         "e.g. 'ubuntu:22.04' or 'redhat:9.3'")
    ap.add_argument("--from-sysdig", action="store_true",
                    help="Fetch scan results from the Sysdig VM API "
                         "(requires --api-url and SYSDIG_API_TOKEN env var). Beta.")
    ap.add_argument("--api-url", default=None,
                    help="Sysdig API base URL, e.g. https://app.us2.sysdig.com")
    ap.add_argument("--result-id", default=None,
                    help="Specific scan result ID (default: latest runtime result)")
    ap.add_argument("--filter", dest="filter_expr", default=None,
                    help="Sysdig runtime-results filter expression")
    ap.add_argument("--version", action="version", version=f"remedify {__version__}")
    args = ap.parse_args()

    if args.from_sysdig:
        import os as _os
        token = _os.environ.get("SYSDIG_API_TOKEN")
        if not args.api_url or not token:
            sys.exit("error: --from-sysdig requires --api-url and the "
                     "SYSDIG_API_TOKEN environment variable.")
        data = fetch_sysdig(args.api_url, token, args.result_id, args.filter_expr)
        parsed = parse_sysdig_json(data, os_override=args.os_override)
    else:
        if not args.scan:
            sys.exit("error: provide a scan file (or '-' for stdin), "
                     "or use --from-sysdig.")
        raw = sys.stdin.read() if args.scan == "-" else open(args.scan, encoding="utf-8").read()
        input_format = args.input if args.input != "auto" else detect_input_format(raw)

        if input_format == "trivy":
            data = json.loads(raw)
            if "Results" not in data:
                sys.exit("error: input does not look like Trivy JSON (missing 'Results').")
            parsed = parse_trivy(data)
            if args.os_override:
                parsed["family"], parsed["os_name"] = parse_os_string(args.os_override)
        elif input_format == "sysdig-json":
            parsed = parse_sysdig_json(json.loads(raw), os_override=args.os_override)
        else:
            parsed = parse_sysdig_csv(raw, os_override=args.os_override)

    if not parsed["family"] and (parsed["findings"] or parsed["unfixed"]):
        print("warning: no OS information found in input; pass --os "
              "(e.g. --os ubuntu:22.04) to generate OS package commands.",
              file=sys.stderr)

    plan = build_plan(parsed, args.min_severity)

    renderer = {"markdown": render_markdown, "shell": render_shell, "json": render_json}
    print(renderer[args.format](plan))


if __name__ == "__main__":
    main()
